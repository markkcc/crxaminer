require "test_helper"

# Reading the saved statistics for the page: anything missing or malformed
# becomes nil or empty, never an error.
class ScanStatsDashboardTest < ActiveSupport::TestCase
  ID = "a" * 32
  METRICS = {
    "all_sites" => { "scans" => 200, "any" => 90, "host_access" => 80, "content_scripts" => 40 },
    "manifest_versions" => { "2" => 30, "3" => 165, "other" => 5 },
    "permissions" => { "scans" => 200, "top" => [{ "name" => "storage", "count" => 150 }, { "name" => "debugger", "count" => 3 },
                                                 { "name" => "madeUp", "count" => 1 }] },
    "users" => { "buckets" => { "under_1k" => 10, "1k_10k" => 20, "10k_100k" => 30, "100k_1m" => 25, "1m_plus" => 15 }, "unknown" => 100 },
    "popular_full_control" => [{ "extension_id" => ID, "extension_name" => "Big", "extension_image" => "https://img.example/a.png",
                                 "users" => 5_000_000 }]
  }.freeze

  def dashboard(**attributes)
    ScanStats::Dashboard.new(StatCache.new({ severity_counts: {}, spiciest_extensions: [] }.merge(attributes)))
  end

  NEW_READERS = %i[all_sites manifest_versions permissions users popular_full_control].freeze

  test "reads every saved statistic" do
    stats = dashboard(metrics: METRICS, severity_counts: { "High" => 4, "Low" => 1 }, scans_last_30_days: 7, all_urls_count: 9,
                      spiciest_extensions: [{ "extension_id" => ID, "extension_name" => "Spicy", "finding_count" => 12 }])

    assert_equal({ "Critical" => 0, "High" => 4, "Medium" => 0, "Low" => 1, "Minimal" => 0 }, stats.level_counts)
    assert_equal 7, stats.scans_last_30_days
    assert_equal 9, stats.all_urls_count
    assert_equal [[ID, "Spicy", nil, 12]], stats.spiciest.map(&:to_a)
    assert_equal [90, 200, 80, 40], stats.all_sites.to_a
    assert_equal [30, 165, 5, 200], stats.manifest_versions.to_a + [stats.manifest_versions.total]
    assert_equal [["storage", 150, 200, "Low"], ["debugger", 3, 200, "Critical"], ["madeUp", 1, 200, nil]],
                 stats.permissions.map { |s| [s.label, s.count, s.total, s.level] }
    assert_equal ScanStats::USER_BUCKETS.map { |b| b[:label] }, stats.users.buckets.map(&:label)
    assert_equal [10, 20, 30, 25, 15], stats.users.buckets.map(&:count)
    assert_equal [100, 100], [stats.users.known, stats.users.unknown]
    assert stats.users.buckets.all? { |share| share.total == 100 }
    assert_equal [[ID, "Big", "https://img.example/a.png", 5_000_000]], stats.popular_full_control.map(&:to_a)
    assert_not stats.empty?
    assert_not stats.awaiting_metrics?
  end

  JUNK = [nil, [], "x", 5, true, {}, [nil], [[]], { "x" => 1 }].freeze

  test "a statistic saved in the wrong shape is nil and leaves the others alone" do
    ScanStats::METRIC_KEYS.each do |key|
      (JUNK + [{ "scans" => "200", "any" => 3 }, { "scans" => 3, "any" => 5 }, { "scans" => 3, "any" => -1 },
               { "scans" => 5, "top" => "x" }, { "scans" => 5, "top" => [{ "name" => "<script>", "count" => 1 }, 7] },
               { "scans" => 5, "top" => [{ "name" => "tabs", "count" => 9 }] }, { "buckets" => [] },
               { "buckets" => { "under_1k" => 1 } }, { "2" => 1, "3" => "x", "other" => 0 }, { "2" => 0, "3" => 0, "other" => 0 },
               [{ "extension_id" => "<b>", "users" => 5 }], [{ "extension_id" => ID, "users" => "5" }]]).each do |junk|
        stats = dashboard(metrics: METRICS.merge(key => junk))
        assert_nil stats.public_send(key), "#{key} saved as #{junk.inspect}"
        (NEW_READERS - [key.to_sym]).each { |other| assert stats.public_send(other), "#{other} when #{key} is #{junk.inspect}" }
      end
    end
  end

  test "junk in place of all the statistics reads as nothing saved" do
    (JUNK - [{}]).each do |junk|
      stats = dashboard(metrics: junk, severity_counts: junk, spiciest_extensions: junk)
      NEW_READERS.each { |reader| assert_nil stats.public_send(reader), "#{reader} for #{junk.inspect}" }
      assert_equal ExtensionAnalyzerData::OVERALL_LEVELS.index_with(0), stats.level_counts
      assert_equal [], stats.spiciest
    end
  end

  test "extension lists keep only entries that can be linked and shown safely" do
    entries = [
      { "extension_id" => ID, "extension_name" => "<script>x</script>", "extension_image" => "javascript:alert(1)", "finding_count" => 3 },
      { "extension_id" => "../../etc", "finding_count" => 9 },
      { "extension_id" => "b" * 32, "finding_count" => -1 },
      { "extension_id" => "c" * 32, "extension_name" => 7, "extension_image" => ["x"], "finding_count" => 2 },
      "x", nil
    ] + 9.times.map { |i| { "extension_id" => format("%032d", i), "finding_count" => 1 } }

    spiciest = dashboard(spiciest_extensions: entries).spiciest
    assert_equal [[ID, "<script>x</script>", nil, 3], ["c" * 32, nil, nil, 2]], spiciest.first(2).map(&:to_a),
                 "the name is kept as text (the page escapes it); the image must be a web address"
    assert_equal [ID, "c" * 32] + 3.times.map { |i| format("%032d", i) }, spiciest.map(&:extension_id), "five at most"
  end

  test "a row saved before the migration has only the older statistics" do
    StatCache.delete_all
    StatCache.create!(severity_counts: { "High" => 2 }, spiciest_extensions: [], scans_last_30_days: 3, all_urls_count: 4, metrics: METRICS)
    # What a server sees while the table has no metrics column.
    row = StatCache.select(:id, :severity_counts, :spiciest_extensions, :scans_last_30_days, :all_urls_count, :created_at, :updated_at).first
    assert_not row.has_attribute?(:metrics)

    stats = ScanStats::Dashboard.new(row)
    NEW_READERS.each { |reader| assert_nil stats.public_send(reader) }
    assert_equal 2, stats.level_counts["High"]
    assert_equal [3, 4], [stats.scans_last_30_days, stats.all_urls_count]
    assert_not stats.awaiting_metrics?, "nothing to wait for until the column exists"
    assert_equal({}, row.stored_metrics)
  end

  test "a row saved before the column was added is waiting for the newer statistics" do
    stats = dashboard(metrics: nil, all_urls_count: 4)

    assert stats.awaiting_metrics?
    assert_nil stats.all_sites
    assert_equal 4, stats.all_urls_count
  end

  test "statistics read as JSON text by a server that started before the migration are parsed" do
    row = StatCache.new(severity_counts: {}, spiciest_extensions: [])
    row.define_singleton_method(:[]) { |name| name.to_s == "metrics" ? METRICS.to_json : super(name) }
    assert_equal 90, ScanStats::Dashboard.new(row).all_sites.count

    row.define_singleton_method(:[]) { |name| name.to_s == "metrics" ? "{not json" : super(name) }
    assert_nil ScanStats::Dashboard.new(row).all_sites
  end

  test "no saved row, or one that cannot be loaded, is an empty dashboard" do
    StatCache.delete_all
    assert ScanStats::Dashboard.load.empty?

    stats = nil
    log = capture_rails_log { StatCache.stub(:current, -> { raise "database gone" }) { stats = ScanStats::Dashboard.load } }
    assert stats.empty?
    assert_match(/Statistics could not be loaded: RuntimeError: database gone/, log)
    assert_equal ExtensionAnalyzerData::OVERALL_LEVELS.index_with(0), stats.level_counts
    assert_equal [], stats.spiciest
    assert_nil stats.scans_last_30_days
    assert_nil stats.refreshed_at
    NEW_READERS.each { |reader| assert_nil stats.public_send(reader) }
  end
end
