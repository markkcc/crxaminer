require "test_helper"

# Payload fields for manifest keys the model could not see before
# (overrides, main-world scripts, externally_connectable, oauth2, update_url).
class AiContextAnalysisManifestKeysTest < ActiveSupport::TestCase
  RAW = {
    "manifest_version" => 3, "name" => "Web Shield", "version" => "1.0",
    "chrome_settings_overrides" => {
      "search_provider" => { "name" => "Safe  Search", "keyword" => "s", "is_default" => true,
                             "search_url" => "https://search.websafe-example.com/results?q={searchTerms}" },
      "homepage" => "https://start.websafe-example.com/",
      "startup_pages" => ["https://start.websafe-example.com/a", 5, nil]
    },
    "chrome_url_overrides" => { "newtab" => "tab.html", "other" => "x.html" },
    "content_scripts" => [{ "matches" => ["<all_urls>"], "world" => "MAIN" }, { "matches" => ["https://a.test/*"] }],
    "externally_connectable" => { "matches" => ["https://*.websafe-example.com/*"], "ids" => ["*"] },
    "oauth2" => { "client_id" => "abc", "scopes" => ["openid", "https://www.googleapis.com/auth/drive"] },
    "update_url" => "https://updates.websafe-example.com/crx.xml"
  }.freeze

  def payload(raw)
    AiContextAnalysis.build_payload(manifest: { manifest_version: 3, permissions: [], host_permissions: [], raw: raw },
                                    extension_details: {}, extension_name: "Web Shield", findings: [])
  end

  test "the new manifest fields are sent, compact and capped" do
    sent = payload(RAW)

    assert_equal({ name: "Safe Search", search_url: "https://search.websafe-example.com/results?q={searchTerms}", is_default: true },
                 sent[:search_provider])
    assert_equal "https://start.websafe-example.com/", sent[:homepage]
    assert_equal ["https://start.websafe-example.com/a"], sent[:startup_pages]
    assert_equal ["newtab"], sent[:replaced_pages]
    assert_equal ["<all_urls>"], sent[:main_world_script_matches]
    assert_equal ["https://*.websafe-example.com/*"], sent[:externally_connectable_matches]
    assert_equal ["openid", "https://www.googleapis.com/auth/drive"], sent[:oauth2_scopes]
    assert_equal "https://updates.websafe-example.com/crx.xml", sent[:update_url]
  end

  test "the fields are identical for a stored manifest" do
    stored = ScanResult.new(manifest: { manifest_version: 3, permissions: [], host_permissions: [], raw: RAW }).manifest
    restored = AiContextAnalysis.build_payload(manifest: stored, extension_details: {}, extension_name: "Web Shield", findings: [])
    assert_equal payload(RAW), restored
  end

  test "absent, empty or junk values are left out, and Google's update URL is not sent" do
    keys = %i[search_provider homepage startup_pages replaced_pages main_world_script_matches
              externally_connectable_matches oauth2_scopes update_url]
    junk = {
      "chrome_settings_overrides" => { "search_provider" => [1], "homepage" => 5, "startup_pages" => "x" },
      "chrome_url_overrides" => ["newtab"], "content_scripts" => [{ "matches" => "<all_urls>", "world" => "MAIN" }, 5],
      "externally_connectable" => { "ids" => ["*"] }, "oauth2" => { "scopes" => [nil, 3] },
      "update_url" => "https://clients2.google.com/service/update2/crx"
    }
    [{}, junk, junk.deep_symbolize_keys, { "chrome_settings_overrides" => "x", "oauth2" => [1], "externally_connectable" => 5 }].each do |raw|
      sent = nil
      assert_nothing_raised { sent = payload(raw) }
      keys.each { |key| assert_not sent.key?(key), "#{key} for #{raw.inspect}" }
    end
  end

  test "long values are capped" do
    raw = {
      "chrome_settings_overrides" => { "startup_pages" => (1..9).map { |i| "https://p#{i}.test/" },
                                       "search_provider" => { "search_url" => "https://s.test/#{'a' * 300}" } },
      "oauth2" => { "scopes" => (1..30).map { |i| "scope#{i}" } }
    }
    sent = payload(raw)
    assert_equal 6, sent[:startup_pages].size
    assert_equal "(+4 more)", sent[:startup_pages].last
    assert_equal AiContextAnalysis::LIST_ITEM_LIMIT, sent[:search_provider][:search_url].length
    assert_equal 21, sent[:oauth2_scopes].size
  end

  test "the system prompt says what the new fields are, and the version is bumped" do
    assert_includes AiContextAnalysis::SYSTEM_PROMPT,
                    "search_provider, homepage, startup_pages and replaced_pages, when present, are Chrome settings and pages " \
                    "the extension takes over;"
    assert_equal "2026-11-18.1", AiContextAnalysis::PROMPT_VERSION
  end
end
