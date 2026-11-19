require "test_helper"

# Saving the statistics: one row, the newer ones in `metrics`, and a
# statistic that failed keeping its last saved value.
class RefreshStatsJobMetricsTest < ActiveJob::TestCase
  setup do
    ScanResult.delete_all
    StatCache.delete_all
  end

  def scan(number, users: "5,000", permissions: ["tabs"], findings: [{ title: "Overall Risk: High", severity: "High" }])
    ScanResult.create!(extension_id: format("%032d", number), extension_name: "Ext #{number}",
                       manifest: { manifest_version: 3, permissions: permissions, host_permissions: ["<all_urls>"] },
                       extension_details: { users: users }, security_findings: findings)
  end

  test "saves every statistic in one row and removes the rows before it" do
    2.times { StatCache.create!(severity_counts: {}, spiciest_extensions: []) }
    scan(1)
    scan(2, users: "9,000,000", findings: [{ title: "Overall Risk: Critical", severity: "Critical" }])

    freeze_time do
      RefreshStatsJob.perform_now

      assert_equal 1, StatCache.count
      cache = StatCache.current
      assert_equal({ "Critical" => 1, "High" => 1, "Medium" => 0, "Low" => 0, "Minimal" => 0 }, cache.severity_counts)
      assert_equal 2, cache.scans_last_30_days
      assert_equal 2, cache.all_urls_count
      assert_equal 2, cache.spiciest_extensions.size
      assert_equal (ScanStats::METRIC_KEYS + %w[computed_at failed scans]).sort, cache.metrics.keys.sort
      assert_equal({ "scans" => 2, "any" => 2, "host_access" => 2, "content_scripts" => 0 }, cache.metrics["all_sites"])
      assert_equal({ "2" => 0, "3" => 2, "other" => 0 }, cache.metrics["manifest_versions"])
      assert_equal [{ "name" => "tabs", "count" => 2 }], cache.metrics["permissions"]["top"]
      assert_equal 1, cache.metrics["users"]["buckets"]["1m_plus"]
      assert_equal [format("%032d", 2)], cache.metrics["popular_full_control"].map { |e| e["extension_id"] }
      assert_equal [2, [], Time.current.utc.iso8601], cache.metrics.values_at("scans", "failed", "computed_at")
    end
  end

  test "a statistic that fails keeps its last saved value while the others are refreshed" do
    scan(1)
    RefreshStatsJob.perform_now
    before = StatCache.current

    scan(2, permissions: %w[tabs cookies])
    log = capture_rails_log do
      ScanStats.stub(:user_bucket, ->(_) { raise "boom" }) do
        ScanDisplayLevel.stub(:for, ->(_) { raise "boom" }) { RefreshStatsJob.perform_now }
      end
    end

    after = StatCache.current
    assert_not_equal before.id, after.id
    assert_equal before.metrics["users"], after.metrics["users"], "kept from the run before"
    assert_equal before.severity_counts, after.severity_counts, "kept from the run before"
    assert_equal %w[levels users], after.metrics["failed"].sort
    assert_equal 2, after.metrics["scans"]
    assert_equal 2, after.metrics["permissions"]["scans"]
    assert_equal 2, after.all_urls_count
    assert_match(/Statistics kept from the last run: levels, users/, log)
  end

  test "a statistic that fails on the first run is simply absent" do
    scan(1)
    ScanStats.stub(:user_bucket, ->(_) { raise "boom" }) { RefreshStatsJob.perform_now }

    cache = StatCache.current
    assert_not cache.metrics.key?("users")
    assert_equal ["users"], cache.metrics["failed"]
    assert_nil ScanStats::Dashboard.new(cache).users
    assert ScanStats::Dashboard.new(cache).permissions
  end

  test "before the migration has run it saves the older statistics only" do
    scan(1)
    StatCache.stub(:metrics_column?, false) { RefreshStatsJob.perform_now }

    cache = StatCache.current
    assert_nil cache.metrics
    assert_equal 1, cache.severity_counts["High"]
    assert_equal [1, 1, 1], [cache.scans_last_30_days, cache.all_urls_count, cache.spiciest_extensions.size]

    result = ScanStats::Collector.run
    assert_equal %i[all_urls_count scans_last_30_days severity_counts spiciest_extensions],
                 ScanStats.cache_attributes(result, metrics_column: false).keys.sort
  end

  test "runs on an empty table" do
    RefreshStatsJob.perform_now

    cache = StatCache.current
    assert_equal ExtensionAnalyzerData::OVERALL_LEVELS.index_with(0), cache.severity_counts
    assert_equal [[], 0, 0, 0], [cache.spiciest_extensions, cache.scans_last_30_days, cache.all_urls_count, cache.metrics["scans"]]
    stats = ScanStats::Dashboard.new(cache)
    assert_nil stats.users
    assert_nil stats.manifest_versions
    assert_nil stats.permissions
    assert_nil stats.popular_full_control
  end

  test "replacing the row is all or nothing" do
    StatCache.create!(severity_counts: { "High" => 1 }, spiciest_extensions: [])

    assert_raises(ActiveRecord::RecordInvalid, ActiveRecord::StatementInvalid, ActiveModel::UnknownAttributeError) do
      StatCache.replace!(severity_counts: {}, spiciest_extensions: [], no_such_column: 1)
    end
    assert_equal [{ "High" => 1 }], StatCache.pluck(:severity_counts)
  end
end
