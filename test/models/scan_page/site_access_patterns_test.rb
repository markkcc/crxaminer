require "test_helper"

# SiteAccess reads patterns with MatchPattern, like the rule engine.
class ScanPage::SiteAccessPatternsTest < ActiveSupport::TestCase
  def access(manifest)
    ScanPage::SiteAccess.new(manifest)
  end

  test "a bare * and other invalid patterns are ignored, as Chrome does" do
    site = access(manifest_version: 3, host_permissions: ["*", "*://*", "https://*.example.com"])
    assert_equal :none, site.kind
    assert_equal 3, site.patterns.size # still listed as written
    assert site.patterns.all? { |p| p.rating.nil? }
  end

  test "a wildcard subdomain is a named site; a whole public suffix is all sites, with a note" do
    named = access(manifest_version: 3, host_permissions: ["https://*.example.com/*"])
    assert_equal :named, named.kind
    assert_equal ["*.example.com"], named.sites

    wide = access(manifest_version: 3, host_permissions: ["*://*.com/*"])
    assert_equal :all, wide.kind
    assert_includes wide.notes, "*://*.com/* covers every site ending in .com, so it counts as all websites."
  end

  test "ftp with a * host is neither all sites nor a named site" do
    site = access(manifest_version: 3, host_permissions: ["ftp://*/*"])
    assert_equal :none, site.kind
  end

  test "each pattern carries the level the rule engine gives it" do
    site = access(manifest_version: 3, host_permissions: ["<all_urls>", "file:///*", "https://www.paypal.com/*", "https://a.test/*"],
                  raw: { optional_host_permissions: ["https://*/*", "https://github.com/*"] })
    assert_equal ["High", "Low", "Medium", nil], site.patterns.map(&:rating)
    assert_equal %w[Medium Low], site.optional_patterns.map(&:rating)
  end

  test "optional host permissions come from the extracted key, with raw as the fallback" do
    extracted = access(manifest_version: 3, optional_host_permissions: ["https://a.test/*"],
                       raw: { optional_host_permissions: ["https://a.test/*"] })
    assert_equal ["https://a.test/*"], extracted.optional_patterns.map(&:pattern)

    older = access(manifest_version: 3, raw: { "optional_host_permissions" => ["https://b.test/*"] })
    assert_equal ["https://b.test/*"], older.optional_patterns.map(&:pattern)
  end

  test "pattern? no longer treats a bare * as a pattern" do
    assert ScanPage::SiteAccess.pattern?("<all_urls>")
    assert ScanPage::SiteAccess.pattern?("https://a.test/*")
    assert_not ScanPage::SiteAccess.pattern?("*")
    assert_not ScanPage::SiteAccess.pattern?("tabs")
    assert_not ScanPage::SiteAccess.pattern?(5)
  end
end
