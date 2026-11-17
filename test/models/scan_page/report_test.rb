require "test_helper"

class ScanPage::ReportTest < ActiveSupport::TestCase
  def with_memory_cache
    original = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    yield Rails.cache
  ensure
    Rails.cache = original
  end

  def urls(count)
    (1..count).map { |i| "https://host#{i}.test/" }
  end

  test "long URL lists are cached per scan; short ones and keyless reports are not" do
    with_memory_cache do |cache|
      over = ScanPage::Report::NETWORK_CACHE_OVER + 1
      ScanPage::Report.new(manifest: { embedded_urls: urls(over) }, security_findings: [], cache_key: [1, 2.0]).network
      key = ["scan-page-network", ScanPage::NetworkDomains::VERSION, 1, 2.0]
      assert_equal over, cache.read(key).url_count

      # A cached summary is used as is.
      cache.write(key, ScanPage::NetworkDomains::Summary.new(url_count: 7, domain_count: 7, category_counts: {}, encoded: ""))
      assert_equal 7, ScanPage::Report.new(manifest: { embedded_urls: urls(over) }, security_findings: [], cache_key: [1, 2.0]).network.url_count

      ScanPage::Report.new(manifest: { embedded_urls: urls(5) }, security_findings: [], cache_key: [3, 4.0]).network
      ScanPage::Report.new(manifest: { embedded_urls: urls(over) }, security_findings: []).network
      assert_nil cache.read(["scan-page-network", ScanPage::NetworkDomains::VERSION, 3, 4.0])
    end
  end

  test "counts and finding lines come from the stored data" do
    report = ScanPage::Report.new(
      manifest: { manifest_version: 3, permissions: %w[tabs storage], host_permissions: ["https://a.test/*", "https://a.test/*"],
                  content_scripts: [{ matches: ["https://a.test/*"] }], raw: { permissions: %w[tabs storage] } },
      security_findings: [{ severity: "High", title: "High-Risk Permission: tabs", description: "x" }]
    )
    assert_equal 3, report.permission_count # two API permissions and one distinct site pattern
    assert_equal({ "High-Risk Permission: tabs" => [3] }, report.finding_lines)
    assert_equal({ 3 => ["High-Risk Permission: tabs"] }, report.flagged_lines)
  end

  test "a missing or junk manifest gives an empty report" do
    [nil, "x", {}].each do |manifest|
      report = ScanPage::Report.new(manifest: manifest, security_findings: nil)
      assert_equal 0, report.permission_count
      assert_equal 0, report.network.url_count
      assert report.manifest_document.empty?
      assert_equal [], report.content_security_policy
    end
  end
end
