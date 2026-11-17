require "test_helper"

class ScanPage::PermissionCatalogTest < ActiveSupport::TestCase
  Catalog = ScanPage::PermissionCatalog

  test "ratings match the rule engine's lists exactly" do
    ExtensionAnalyzerData::HIGH_RISK_PERMISSIONS.each_key { |name| assert_equal "High", Catalog.rating(name) }
    ExtensionAnalyzerData::MEDIUM_RISK_PERMISSIONS.each_key { |name| assert_equal "Medium", Catalog.rating(name) }
    assert_nil Catalog.rating("alarms")
    assert_nil Catalog.rating("Tabs")
  end

  test "every permission the rule engine knows has a description, except non-extension ones" do
    known = ExtensionAnalyzerData::HIGH_RISK_PERMISSIONS.keys + ExtensionAnalyzerData::MEDIUM_RISK_PERMISSIONS.keys
    missing = known.reject { |name| Catalog.description(name) }
    # <all_urls> is a site pattern, webview is for Chrome apps.
    assert_equal ["<all_urls>", "webview"], missing.sort
  end

  test "doc links use API pages, variants map to their API, the rest use the list page" do
    assert_equal "https://developer.chrome.com/docs/extensions/reference/api/tabs", Catalog.doc_url("tabs")
    assert_equal "https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest", Catalog.doc_url("declarativeNetRequest")
    assert_equal "https://developer.chrome.com/docs/extensions/reference/api/system/cpu", Catalog.doc_url("system.cpu")
    assert_equal "https://developer.chrome.com/docs/extensions/reference/api/webRequest", Catalog.doc_url("webRequestBlocking")
    assert_equal "https://developer.chrome.com/docs/extensions/reference/api/downloads", Catalog.doc_url("downloads.open")
    %w[activeTab unlimitedStorage clipboardRead background geolocation].each do |name|
      assert_equal Catalog::PERMISSIONS_LIST_URL, Catalog.doc_url(name), name
    end
    assert_nil Catalog.doc_url("action")
  end

  test "every doc link is on developer.chrome.com" do
    Catalog::ENTRIES.each_key do |name|
      assert Catalog.doc_url(name).start_with?("https://developer.chrome.com/docs/extensions/reference/"), name
    end
  end

  test "rows keep unknown and non-string entries with a neutral state" do
    catalog = Catalog.new(manifest_version: 3, permissions: ["tabs", "action", 5, nil, { "fileSystem" => ["write"] }, "tabs"])
    rows = catalog.required

    assert_equal ["tabs", "action", "5", '{"fileSystem":["write"]}'], rows.map(&:name)
    assert_equal "High", rows.first.rating
    assert_nil rows[1].description
    assert_nil rows[1].doc_url
    assert_nil rows[2].rating
  end

  test "Manifest V2 site patterns leave the table; Manifest V3 keeps them visible" do
    v2 = Catalog.new(manifest_version: 2, permissions: ["tabs", "<all_urls>", "http://*/"])
    assert_equal ["tabs"], v2.required.map(&:name)

    v3 = Catalog.new(manifest_version: 3, permissions: ["tabs", "<all_urls>"])
    assert_equal ["tabs", "<all_urls>"], v3.required.map(&:name)
  end

  test "optional permissions are separate" do
    catalog = Catalog.new(manifest_version: 3, permissions: ["storage"], optional_permissions: ["tabs", "bookmarks"])
    assert_equal %w[tabs bookmarks], catalog.optional.map(&:name)
  end

  test "junk manifests give empty tables" do
    [nil, "x", { permissions: "tabs" }, { permissions: nil, optional_permissions: 4 }].each do |manifest|
      assert_equal [], Catalog.new(manifest).required
      assert_equal [], Catalog.new(manifest).optional
    end
  end
end
