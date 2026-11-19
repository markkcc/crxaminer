module ScanStats
  # What the statistics page shows, read from the saved StatCache row.
  #
  # Every reader checks what was saved before handing it to the page. A
  # statistic that is missing (never worked out, or the migration for the
  # newer ones has not run) or that does not look right comes back as nil or
  # empty, and the page leaves its card out. No reader raises.
  class Dashboard
    EXTENSION_ID = /\A[a-zA-Z0-9]{32}\z/

    # number: the figure the list is ranked by (findings, or users).
    Extension = Struct.new(:extension_id, :name, :image, :number, keyword_init: true)
    # One bar: `count` out of `total`. level: a finding level for its colour, or nil.
    Share = Struct.new(:key, :label, :count, :total, :level, keyword_init: true)
    AllSites = Struct.new(:count, :scans, :host_access, :content_scripts, keyword_init: true)
    ManifestVersions = Struct.new(:v2, :v3, :other, keyword_init: true) do
      def total = v2 + v3 + other
    end
    Users = Struct.new(:buckets, :known, :unknown, keyword_init: true)

    def self.load
      new(StatCache.current)
    rescue StandardError => e
      Rails.logger.error("Statistics could not be loaded: #{e.class}: #{e.message}")
      new(nil)
    end

    def initialize(cache)
      @cache = cache
      @metrics = safely({}) { cache ? cache.stored_metrics : {} }
    end

    # Nothing has been saved yet.
    def empty?
      @cache.nil?
    end

    # The newer statistics can be saved but this row predates them.
    def awaiting_metrics?
      safely(false) { @cache ? @cache.awaiting_metrics? : false }
    end

    def refreshed_at
      safely(nil) { @cache&.updated_at }
    end

    # Every overall level, most severe first, with its count (0 when unknown).
    def level_counts
      stored = safely(nil) { @cache&.severity_counts }
      stored = {} unless stored.is_a?(Hash)
      ExtensionAnalyzerData::OVERALL_LEVELS.index_with { |level| whole(stored[level]) || 0 }
    end

    def spiciest
      safely([]) { extensions(@cache&.spiciest_extensions, "finding_count") }
    end

    def scans_last_30_days
      safely(nil) { whole(@cache&.scans_last_30_days) }
    end

    # Extensions with the literal "<all_urls>" permission: the older, narrower
    # count, shown only while #all_sites is not available.
    def all_urls_count
      safely(nil) { whole(@cache&.all_urls_count) }
    end

    # Extensions that can run on every website, or nil.
    def all_sites
      safely(nil) do
        saved = hash("all_sites")
        count = whole(saved["any"])
        scans = whole(saved["scans"])
        next nil unless count && scans && count <= scans

        AllSites.new(count: count, scans: scans, host_access: whole(saved["host_access"]),
                     content_scripts: whole(saved["content_scripts"]))
      end
    end

    def manifest_versions
      safely(nil) do
        saved = hash("manifest_versions")
        counts = %w[2 3 other].map { |key| whole(saved[key]) }
        next nil if counts.any?(&:nil?) || counts.sum.zero?

        ManifestVersions.new(v2: counts[0], v3: counts[1], other: counts[2])
      end
    end

    # The most requested permissions as Shares (level: the permission's
    # level in the rule data, nil for one the rules do not rate), or nil.
    def permissions
      safely(nil) do
        saved = hash("permissions")
        scans = whole(saved["scans"])
        next nil unless scans&.positive?

        rows = ScanPage.list(saved["top"]).first(TOP_PERMISSIONS).filter_map do |entry|
          name = ScanPage.value(entry, :name)
          count = whole(ScanPage.value(entry, :count))
          next unless name.is_a?(String) && name.match?(Collector::Permissions::NAME) && count && count <= scans

          Share.new(key: name, label: name, count: count, total: scans, level: ExtensionAnalyzerData.permission_level(name))
        end
        rows.presence
      end
    end

    # Extensions by number of users, or nil.
    def users
      safely(nil) do
        saved = hash("users")
        buckets = saved["buckets"]
        next nil unless buckets.is_a?(Hash)

        counts = USER_BUCKETS.map { |bucket| whole(buckets[bucket[:key]]) }
        next nil if counts.any?(&:nil?) || counts.sum.zero?

        known = counts.sum
        shares = USER_BUCKETS.zip(counts).map do |bucket, count|
          Share.new(key: bucket[:key], label: bucket[:label], count: count, total: known)
        end
        Users.new(buckets: shares, known: known, unknown: whole(saved["unknown"]) || 0)
      end
    end

    # The most-installed extensions with full-control access, or nil.
    def popular_full_control
      safely(nil) { extensions(@metrics["popular_full_control"], "users").presence }
    end

    private

    def hash(key)
      value = @metrics[key]
      value.is_a?(Hash) ? value : {}
    end

    # A count: a whole number that is not negative, or nil.
    def whole(value)
      value.is_a?(Integer) && value >= 0 ? value : nil
    end

    def extensions(list, number_key)
      usable = ScanPage.list(list).first(50).filter_map do |entry|
        id = ScanPage.value(entry, :extension_id)
        number = whole(ScanPage.value(entry, number_key))
        next unless id.is_a?(String) && id.match?(EXTENSION_ID) && number

        name = ScanPage.value(entry, :extension_name)
        image = ScanPage.value(entry, :extension_image)
        Extension.new(extension_id: id, number: number,
                      name: name.is_a?(String) && name.present? ? name[0, 200] : nil,
                      image: image.is_a?(String) && image.match?(%r{\Ahttps?://}i) ? image : nil)
      end
      usable.first(TOP_EXTENSIONS)
    end

    def safely(default)
      yield
    rescue StandardError => e
      Rails.logger.error("A statistic could not be read: #{e.class}: #{e.message}")
      default
    end
  end
end
