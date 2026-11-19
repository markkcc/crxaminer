require "test_helper"

class RefreshStatsJobAllUrlsTest < ActiveSupport::TestCase
  def scan(id, manifest)
    ScanResult.create!(extension_id: id * 32, extension_name: id, manifest: manifest, extension_details: {}, security_findings: [])
  end

  test "counts <all_urls> in either list and is not stopped by manifests whose lists are not lists" do
    scan("c", { permissions: ["tabs", "<all_urls>"], host_permissions: [] })
    scan("d", { permissions: [], host_permissions: ["<all_urls>"] })
    scan("e", { permissions: ["tabs"], host_permissions: ["https://example.com/*"] })
    scan("f", { permissions: "<all_urls>", host_permissions: nil })
    scan("g", { permissions: { "a" => 1 }, host_permissions: 7 })
    scan("h", {})

    assert_nothing_raised { RefreshStatsJob.perform_now }
    assert_equal 2, StatCache.first.all_urls_count
  end
end
