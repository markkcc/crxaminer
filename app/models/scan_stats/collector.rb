module ScanStats
  # Works out every statistic in one pass over the stored scans.
  #
  # The pass reads the scans in primary-key batches and asks the database
  # for each manifest without its list of embedded URLs, which is most of a
  # stored row and which no statistic uses. Nothing else is queried.
  #
  # Each statistic is a Metric that is shown every row. Stored scans can
  # hold anything, so the metrics read defensively; should one raise all the
  # same, that row is skipped for that metric only, and a metric that keeps
  # raising is switched off and reports nil (see ScanStats.cache_attributes).
  class Collector
    BATCH_SIZE = 500
    # A metric that raised on more rows than this is switched off.
    MAX_ERRORS = 25

    COLUMNS = <<~SQL.squish.freeze
      id, extension_id, extension_name, extension_image, created_at, extension_details, security_findings,
      CASE WHEN jsonb_typeof(manifest) = 'object' THEN manifest - 'embedded_urls' ELSE '{}'::jsonb END AS slim_manifest
    SQL

    # values: metric key => what to save, or nil for a metric that failed.
    Result = Struct.new(:scans, :values, :failed, keyword_init: true)

    def self.run(scope = ScanResult.all, now: Time.current)
      new(scope, now: now).run
    end

    def initialize(scope, now: Time.current)
      @scope = scope
      @now = now
    end

    def run
      metrics = build_metrics
      scans = 0
      @scope.select(COLUMNS).find_each(batch_size: BATCH_SIZE) do |record|
        scans += 1
        row = Row.new(record)
        metrics.each { |metric| metric.add(row) }
      end
      values = metrics.to_h { |metric| [metric.key, metric.value] }
      Result.new(scans: scans, values: values, failed: values.select { |_, value| value.nil? }.keys)
    end

    private

    def build_metrics
      [LevelCounts.new, Spiciest.new, RecentCount.new(@now), AllUrls.new, AllSites.new, ManifestVersions.new,
       Permissions.new, Users.new, PopularFullControl.new]
    end

    # One stored scan, with what the metrics need worked out once and shared.
    class Row
      def initialize(record)
        @record = record
        @memo = {}
      end

      def id = @record.id
      def extension_id = @record.extension_id
      def created_at = @record.created_at

      def name
        value = @record.extension_name
        value.is_a?(String) ? value[0, 200] : nil
      end

      def image
        value = @record.extension_image
        value.is_a?(String) && value.match?(%r{\Ahttps://}i) && value.length <= 2_000 ? value : nil
      end

      def findings = @record.read_attribute(:security_findings)

      # The level the scan shows everywhere (ScanDisplayLevel), or nil.
      def level = memo(:level) { ScanDisplayLevel.for(findings) }

      # The access tier the scan's page shows.
      def access_tier = memo(:access_tier) { ScanRating.access_tier(ScanRating.stored_access_level(findings)) }

      # Rule findings, not counting the overall rating, the AI check or
      # routine permissions.
      def finding_count
        memo(:finding_count) { ScanPage::FindingGroups.new(findings).areas.sum { |area| area.findings.size } }
      end

      # The stored manifest without its embedded URLs.
      def manifest = @record[:slim_manifest]

      def summary = memo(:summary) { ExtensionSecurityAnalyzer.manifest_summary(manifest) }

      # The listing's user count as a number, or nil when it has none.
      def users
        memo(:users) { ScanRating.count(ScanPage.value(@record.read_attribute(:extension_details), :users)) }
      end

      def listing
        { "extension_id" => extension_id, "extension_name" => name, "extension_image" => image }
      end

      private

      def memo(key)
        @memo.fetch(key) { @memo[key] = yield }
      end
    end

    class Metric
      def initialize
        @errors = 0
        @rows = 0
      end

      def key = self.class::KEY

      def add(row)
        return if switched_off?

        count(row)
        @rows += 1
      rescue StandardError => e
        @errors += 1
        Rails.logger.warn("Statistic #{key} skipped scan #{row.id}: #{e.class}: #{e.message}") if @errors == 1
        Rails.logger.error("Statistic #{key} switched off after #{@errors} errors") if switched_off?
      end

      # What to save, or nil when the metric failed: it was switched off, or
      # it raised on every row it saw.
      def value
        return nil if switched_off? || (@errors.positive? && @rows.zero?)

        result
      rescue StandardError => e
        Rails.logger.error("Statistic #{key} could not be finished: #{e.class}: #{e.message}")
        nil
      end

      private

      def switched_off? = @errors > MAX_ERRORS
    end

    # The largest `size` entries by a number, largest first; ties go to the
    # scan stored first.
    class TopList
      def initialize(size)
        @size = size
        @entries = []
      end

      def offer(number, id, entry)
        return if @entries.size == @size && number <= @entries.last[0]

        @entries << [number, id, entry]
        @entries.sort_by! { |n, i, _| [-n, i] }
        @entries.pop if @entries.size > @size
      end

      def entries = @entries.map(&:last)
    end

    # How many scans show each overall level.
    class LevelCounts < Metric
      KEY = :levels

      def initialize
        super
        @counts = ExtensionAnalyzerData::OVERALL_LEVELS.index_with(0)
      end

      def count(row)
        level = row.level
        @counts[level] += 1 if level && @counts.key?(level)
      end

      def result = @counts
    end

    # The scans with the most rule findings.
    class Spiciest < Metric
      KEY = :spiciest

      def initialize
        super
        @top = TopList.new(TOP_EXTENSIONS)
      end

      def count(row)
        @top.offer(row.finding_count, row.id, row.listing.merge("finding_count" => row.finding_count))
      end

      def result = @top.entries
    end

    # Extensions first scanned in the last 30 days.
    class RecentCount < Metric
      KEY = :recent

      def initialize(now)
        super()
        @since = now - 30.days
        @count = 0
      end

      def count(row)
        @count += 1 if row.created_at && row.created_at >= @since
      end

      def result = @count
    end

    # Extensions with the literal "<all_urls>" in the stored permissions or
    # host_permissions. This is what the all_urls_count column has always
    # held; it misses "*://*/*" and content scripts, which AllSites counts.
    class AllUrls < Metric
      KEY = :all_urls

      def initialize
        super
        @count = 0
      end

      def count(row)
        manifest = row.manifest
        lists = [ScanPage.value(manifest, :permissions), ScanPage.value(manifest, :host_permissions)]
        @count += 1 if lists.any? { |list| list.is_a?(Array) && list.include?(MatchPattern::ALL_URLS) }
      end

      def result = @count
    end

    # Extensions that can run on every website: a required host permission
    # or a content script covers all sites (MatchPattern#all_sites?), as the
    # rules "host.all_sites" and "content_script.all_sites" see it.
    class AllSites < Metric
      KEY = :all_sites

      def initialize
        super
        @any = @host_access = @content_scripts = 0
      end

      def count(row)
        summary = row.summary
        @host_access += 1 if summary.all_sites_host_access
        @content_scripts += 1 if summary.all_sites_content_scripts
        @any += 1 if summary.all_sites_host_access || summary.all_sites_content_scripts
      end

      def result
        { "scans" => @rows, "any" => @any, "host_access" => @host_access, "content_scripts" => @content_scripts }
      end
    end

    # Manifest V2, Manifest V3, and anything else (no usable version).
    class ManifestVersions < Metric
      KEY = :manifest_versions

      def initialize
        super
        @counts = { "2" => 0, "3" => 0, "other" => 0 }
      end

      def count(row)
        version = row.summary.manifest_version.to_s
        @counts[@counts.key?(version) ? version : "other"] += 1
      end

      def result = @counts
    end

    # The API permissions most extensions ask for at install.
    class Permissions < Metric
      KEY = :permissions
      NAME = /\A[A-Za-z][A-Za-z0-9_.]{0,59}\z/
      # Bounds on junk: names read per scan, and different names remembered.
      PER_SCAN = 200
      MAX_NAMES = 2_000

      def initialize
        super
        @counts = Hash.new(0)
      end

      def count(row)
        row.summary.permissions.first(PER_SCAN).uniq.each do |name|
          next unless name.match?(NAME)
          next if @counts.size >= MAX_NAMES && !@counts.key?(name)

          @counts[name] += 1
        end
      end

      def result
        top = @counts.sort_by { |name, count| [-count, name] }.first(TOP_PERMISSIONS)
        { "scans" => @rows, "top" => top.map { |name, count| { "name" => name, "count" => count } } }
      end
    end

    # Extensions by the number of users their listing shows.
    class Users < Metric
      KEY = :users

      def initialize
        super
        @buckets = USER_BUCKETS.to_h { |bucket| [bucket[:key], 0] }
        @unknown = 0
      end

      def count(row)
        users = row.users
        users ? @buckets[ScanStats.user_bucket(users)[:key]] += 1 : @unknown += 1
      end

      def result
        { "buckets" => @buckets, "unknown" => @unknown }
      end
    end

    # The most-installed extensions whose access tier is Full control.
    class PopularFullControl < Metric
      KEY = :popular_full_control
      TIER = "full_control".freeze

      def initialize
        super
        @top = TopList.new(TOP_EXTENSIONS)
      end

      def count(row)
        users = row.users
        return unless users&.positive? && row.access_tier.key == TIER

        @top.offer(users, row.id, row.listing.merge("users" => users))
      end

      def result = @top.entries
    end
  end
end
