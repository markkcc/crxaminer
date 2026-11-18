require "test_helper"

class ScanPage::SiteAccessTest < ActiveSupport::TestCase
  def access(manifest)
    ScanPage::SiteAccess.new(manifest)
  end

  test "broad host permissions mean all websites" do
    %w[<all_urls> *://*/* https://*/* http://*/ wss://*/*].each do |pattern|
      site = access(manifest_version: 3, host_permissions: [pattern])
      assert_equal :all, site.kind, pattern
      assert_equal "All websites", site.summary
    end
  end

  test "content script matches count as site access" do
    site = access(manifest_version: 3, content_scripts: [{ matches: ["<all_urls>"] }, { "matches" => ["https://a.test/*"] }])
    assert_equal :all, site.kind
    assert_equal %i[content_scripts content_scripts], site.patterns.map(&:source)
  end

  test "named sites are listed once each" do
    site = access(manifest_version: 3, host_permissions: ["https://start.me/", "https://*.Example.com/*", "http://*.example.com/*"],
                  content_scripts: [{ matches: ["https://start.me/*"] }])
    assert_equal :named, site.kind
    assert_equal ["*.example.com", "start.me"], site.sites
    assert_equal "2 named sites", site.summary
  end

  test "activeTab alone means only when you click" do
    site = access(manifest_version: 3, permissions: %w[activeTab storage])
    assert_equal :active_tab, site.kind
    assert_equal "Only when you click the extension", site.summary
  end

  test "nothing means no website access" do
    assert_equal "No website access", access(manifest_version: 3, permissions: ["storage"]).summary
    assert_equal :none, access({}).kind
  end

  test "Manifest V2 patterns inside permissions count, V3 ones do not" do
    v2 = access(manifest_version: 2, permissions: ["tabs", "http://*/", "chrome://favicon/"])
    assert_equal :all, v2.kind
    assert_equal ["http://*/", "chrome://favicon/"], v2.patterns.map(&:pattern)
    assert_equal :permissions, v2.patterns.first.source

    v3 = access(manifest_version: 3, permissions: ["http://*/"])
    assert_equal :none, v3.kind
  end

  test "file access and activeTab are noted alongside the headline" do
    site = access(manifest_version: 3, host_permissions: ["file:///*", "https://a.test/*"], permissions: ["activeTab"])
    assert_equal :named, site.kind
    assert_equal ["a.test"], site.sites
    assert_equal 2, site.notes.size
  end

  test "optional patterns come from optional_host_permissions and, in V2, optional_permissions" do
    site = access(manifest_version: 2, optional_permissions: ["tabs", "https://*/*"],
                  raw: { optional_host_permissions: ["https://b.test/*", 7] })
    assert_equal ["https://b.test/*", "https://*/*"], site.optional_patterns.map(&:pattern)
    assert_equal :none, site.kind
  end

  test "junk never raises" do
    [nil, "string", [], { host_permissions: "x", content_scripts: "y", permissions: 5 },
     { content_scripts: [nil, 5, { matches: [nil, 3, "<script>"] }], host_permissions: [nil, {}, "::", "http://"] }].each do |manifest|
      site = access(manifest)
      assert_includes %i[all named active_tab none], site.kind
      site.summary
      site.notes
      site.optional_patterns
    end
  end
end
