require "test_helper"

# Rules for manifest keys added in rules version 3 (review item R1):
# settings overrides, replaced Chrome pages, main-world content scripts,
# externally_connectable, web_accessible_resources, update_url and oauth2.
class ExtensionSecurityAnalyzerManifestKeysTest < ActiveSupport::TestCase
  def extracted(raw)
    {
      manifest_version: raw["manifest_version"], name: raw["name"], version: raw["version"],
      permissions: raw["permissions"] || [], optional_permissions: raw["optional_permissions"] || [],
      host_permissions: raw["host_permissions"] || [], optional_host_permissions: raw["optional_host_permissions"] || [],
      content_scripts: raw["content_scripts"], embedded_urls: [], content_security_policy: [], raw: raw
    }
  end

  # Runs on a fresh and a stored (deep-symbolized) manifest; both must agree.
  def findings_for(raw)
    raw = { "manifest_version" => 3, "name" => "X", "version" => "1" }.merge(raw)
    fresh = ExtensionSecurityAnalyzer.rule_findings(extracted(raw))
    stored = ExtensionSecurityAnalyzer.rule_findings(ScanResult.new(manifest: extracted(raw)).manifest)
    assert_equal fresh, stored, "fresh and stored manifests must agree"
    @raw = raw
    fresh
  end

  def by_rule(findings, rule)
    findings.select { |f| f[:rule] == rule }
  end

  def resolve(path)
    path.reduce(@raw) { |node, step| node.fetch(step) }
  end

  def assert_resolves(finding)
    assert finding[:evidence].present?
    finding[:evidence].each { |path| assert_nothing_raised { resolve(path) } }
  end

  # --- search engine -----------------------------------------------------------

  test "a realistic search hijack with no permissions is rated High, with evidence on the search URL and is_default" do
    findings = findings_for(
      "name" => "Web Shield", "permissions" => [],
      "chrome_settings_overrides" => {
        "search_provider" => {
          "name" => "Safe Search", "keyword" => "safe", "encoding" => "UTF-8", "is_default" => true,
          "search_url" => "https://search.websafe-example.com/results?q={searchTerms}&src=ext",
          "favicon_url" => "https://search.websafe-example.com/favicon.ico"
        }
      }
    )
    hijack = by_rule(findings, "settings.search_provider").sole

    assert_equal "Overall Risk: High", findings.first[:title]
    assert_equal "High", hijack[:severity]
    assert_equal "Changes Your Search Engine", hijack[:title]
    assert_equal [%w[chrome_settings_overrides search_provider search_url], %w[chrome_settings_overrides search_provider is_default]],
                 hijack[:evidence]
    assert_includes hijack[:description], "makes search.websafe-example.com your default search engine"
    assert_includes hijack[:description], "sees every search"
    assert_resolves(hijack)
  end

  test "a search provider without a usable URL still counts and says what it can" do
    named = by_rule(findings_for("chrome_settings_overrides" => { "search_provider" => { "name" => "Finder", "search_url" => 5 } }),
                    "settings.search_provider").sole
    assert_includes named[:description], "It adds Finder as a search engine"
    assert_equal [%w[chrome_settings_overrides search_provider]], named[:evidence]

    bare = by_rule(findings_for("chrome_settings_overrides" => { "search_provider" => { "search_url" => "javascript:alert(1)" } }),
                   "settings.search_provider").sole
    assert_includes bare[:description], "a site it names"
  end

  # --- homepage and startup pages ----------------------------------------------

  test "homepage and startup pages are one Medium finding naming the hosts" do
    findings = findings_for("chrome_settings_overrides" => {
                              "homepage" => "https://start.example.net/?ref=ext",
                              "startup_pages" => ["https://news.example.org/", 7, "http://start.example.net/b"]
                            })
    page = by_rule(findings, "settings.homepage").sole

    assert_equal "Medium", page[:severity]
    assert_equal "Changes Your Homepage and Startup Pages", page[:title]
    assert_equal [%w[chrome_settings_overrides homepage], ["chrome_settings_overrides", "startup_pages", 0],
                  ["chrome_settings_overrides", "startup_pages", 2]], page[:evidence]
    assert_includes page[:description], "start.example.net, news.example.org"
    assert_equal "Changes Your Homepage", by_rule(findings_for("chrome_settings_overrides" => { "homepage" => "https://a.test/" }),
                                                  "settings.homepage").sole[:title]
  end

  # --- replaced Chrome pages -----------------------------------------------------

  test "replaced Chrome pages are one Medium finding naming each page" do
    findings = findings_for("chrome_url_overrides" => { "newtab" => "tab.html", "history" => "h.html", "other" => "x.html" })
    pages = by_rule(findings, "url_overrides").sole

    assert_equal "Medium", pages[:severity]
    assert_equal [%w[chrome_url_overrides newtab], %w[chrome_url_overrides history]], pages[:evidence]
    assert_includes pages[:description], "Chrome's new tab page and history page"
  end

  # --- content scripts ---------------------------------------------------------

  test "main-world scripts are High on all sites and Medium on named sites" do
    findings = findings_for("content_scripts" => [
                              { "matches" => ["<all_urls>"], "js" => ["a.js"], "world" => "MAIN" },
                              { "matches" => ["https://*.shop.example/*"], "js" => ["b.js"], "world" => "MAIN" },
                              { "matches" => ["<all_urls>"], "js" => ["c.js"], "world" => "ISOLATED" }
                            ])
    everywhere = by_rule(findings, "content_script.main_world_all_sites").sole
    named = by_rule(findings, "content_script.main_world").sole

    assert_equal "High", everywhere[:severity]
    assert_equal [["content_scripts", 0, "world"]], everywhere[:evidence]
    assert_includes everywhere[:description], "page's own JavaScript"
    assert_equal "Medium", named[:severity]
    assert_equal [["content_scripts", 1, "world"]], named[:evidence]
    assert_includes named[:description], "On shop.example"
  end

  test "frame and timing keys of all-site scripts join the existing finding instead of adding new ones" do
    # A live example: a proxy manager that injects into every frame of every
    # site, in the page's world, at document start.
    findings = findings_for("content_scripts" => [
                              { "matches" => ["<all_urls>"], "js" => ["inject.js"], "world" => "MAIN", "run_at" => "document_start",
                                "all_frames" => true, "match_about_blank" => true, "match_origin_as_fallback" => true },
                              { "matches" => ["https://a.test/*"], "all_frames" => true, "run_at" => "document_start" }
                            ])
    scripts = by_rule(findings, "content_script.all_sites").sole

    assert_equal [["content_scripts", 0, "matches", 0], ["content_scripts", 0, "all_frames"],
                  ["content_scripts", 0, "match_about_blank"], ["content_scripts", 0, "match_origin_as_fallback"],
                  ["content_scripts", 0, "run_at"]], scripts[:evidence]
    assert_includes scripts[:description], "inside frames embedded in pages"
    assert_includes scripts[:description], "before the page's own scripts"
    assert_equal 1, by_rule(findings, "content_script.main_world_all_sites").size
    assert_resolves(scripts)

    plain = by_rule(findings_for("content_scripts" => [{ "matches" => ["<all_urls>"], "all_frames" => false, "run_at" => "document_idle" }]),
                    "content_script.all_sites").sole
    assert_equal [["content_scripts", 0, "matches", 0]], plain[:evidence]
    assert_not_includes plain[:description], "frames"
  end

  # --- externally_connectable ----------------------------------------------------

  test "externally_connectable is Medium with subdomain wildcards or plain http, otherwise Low; ids alone raise nothing" do
    wide = by_rule(findings_for("externally_connectable" => { "matches" => ["https://*.example.com/*", "https://app.test/*"] }),
                   "externally_connectable.wide").sole
    assert_equal "Medium", wide[:severity]
    assert_equal [["externally_connectable", "matches", 0], ["externally_connectable", "matches", 1]], wide[:evidence]
    assert_includes wide[:description], "flaw"

    http = findings_for("externally_connectable" => { "matches" => ["http://app.test/*"] })
    assert by_rule(http, "externally_connectable.wide").one?

    narrow = by_rule(findings_for("externally_connectable" => { "matches" => ["https://app.test/*", "nonsense"] }),
                     "externally_connectable").sole
    assert_equal "Low", narrow[:severity]
    assert_equal [["externally_connectable", "matches", 0]], narrow[:evidence]
    assert_includes narrow[:description], "app.test"

    ids_only = findings_for("externally_connectable" => { "ids" => ["*"] })
    assert_empty ids_only.select { |f| f[:rule].to_s.start_with?("externally_connectable") }
  end

  # --- web_accessible_resources ------------------------------------------------

  test "resources open to all sites are Low, everything open is Medium, named sites and other extensions raise nothing" do
    v3 = findings_for("web_accessible_resources" => [
                        { "resources" => ["inject.js", "img/*.png"], "matches" => ["https://a.test/*", "<all_urls>"] },
                        { "resources" => ["only-a.js"], "matches" => ["https://a.test/*"] },
                        { "resources" => ["for-extensions.js"], "extension_ids" => ["*"] }
                      ])
    open = by_rule(v3, "web_accessible_resources.all_sites").sole
    assert_equal "Low", open[:severity]
    assert_equal [["web_accessible_resources", 0, "matches", 1]], open[:evidence]
    assert_includes open[:description], "inject.js, img/*.png"
    assert_not_includes open[:description], "only-a.js"

    v2 = by_rule(findings_for("manifest_version" => 2, "web_accessible_resources" => ["page.html", "*"]),
                 "web_accessible_resources.everything").sole
    assert_equal "Medium", v2[:severity]
    assert_equal [["web_accessible_resources", 0], ["web_accessible_resources", 1]], v2[:evidence]
  end

  # --- update_url --------------------------------------------------------------------

  test "an update URL that is not Google's is High; the store's is nothing" do
    other = by_rule(findings_for("update_url" => "https://updates.example.com/crx.xml"), "update_url.external").sole
    assert_equal "High", other[:severity]
    assert_equal [["update_url"]], other[:evidence]
    assert_includes other[:description], "updates.example.com"

    assert_empty by_rule(findings_for("update_url" => "https://clients2.google.com/service/update2/crx"), "update_url.external")
  end

  # --- oauth2 ----------------------------------------------------------------------

  test "oauth2 scopes for account data are Medium and named; sign-in only is Low" do
    data = by_rule(findings_for("oauth2" => { "client_id" => "x", "scopes" => [
                                  "openid", "https://www.googleapis.com/auth/gmail.readonly",
                                  "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/calendar",
                                  "https://www.googleapis.com/auth/userinfo.email", 5
                                ] }), "oauth2.account_data").sole
    assert_equal "Medium", data[:severity]
    assert_includes data[:description], "Gmail, Google Drive, Google Calendar"
    assert_equal (1..3).map { |i| ["oauth2", "scopes", i] }, data[:evidence],
                 "the note goes under the scopes that reach data, not the sign-in ones"

    sign_in = by_rule(findings_for("oauth2" => { "scopes" => %w[openid email profile https://www.googleapis.com/auth/userinfo.profile] }),
                      "oauth2.sign_in").sole
    assert_equal "Low", sign_in[:severity]
    assert_empty by_rule(findings_for("oauth2" => { "scopes" => [] }), "oauth2.sign_in")
  end

  # --- review bullet two: permissions said to be on neither list -----------------

  test "every permission named in the review produces a rated finding" do
    names = %w[scripting declarativeNetRequest declarativeNetRequestWithHostAccess declarativeNetRequestFeedback
               nativeMessaging desktopCapture tabCapture pageCapture browsingData contentSettings topSites sessions
               userScripts offscreen webRequestAuthProvider]
    findings = findings_for("permissions" => names)
    rated = by_rule(findings, "permission").to_h { |f| [f[:title].split(": ").last, f[:severity]] }

    assert_equal names.sort, rated.keys.sort
    names.each { |name| assert_equal ExtensionAnalyzerData.permission_level(name), rated[name], name }
  end

  # --- the data for the help page -----------------------------------------------

  test "each new rule is listed with a fixed level, a name and a summary" do
    expected = {
      "settings.search_provider" => "High", "content_script.main_world_all_sites" => "High", "update_url.external" => "High",
      "settings.homepage" => "Medium", "url_overrides" => "Medium", "content_script.main_world" => "Medium",
      "externally_connectable.wide" => "Medium", "web_accessible_resources.everything" => "Medium",
      "oauth2.account_data" => "Medium", "externally_connectable" => "Low", "web_accessible_resources.all_sites" => "Low",
      "oauth2.sign_in" => "Low"
    }
    expected.each do |id, level|
      rule = ExtensionAnalyzerData.rule(id)
      assert_equal level, rule&.severity, id
      assert rule.name.present? && rule.summary.present?, id
    end
    assert_equal 3, ExtensionSecurityAnalyzer::RULES_VERSION
  end

  test "the new rules land in sensible Overview areas" do
    findings = findings_for(
      "chrome_settings_overrides" => { "search_provider" => { "search_url" => "https://s.test/?q={searchTerms}" } },
      "chrome_url_overrides" => { "newtab" => "n.html" },
      "content_scripts" => [{ "matches" => ["https://a.test/*"], "world" => "MAIN" }],
      "externally_connectable" => { "matches" => ["https://a.test/*"] },
      "web_accessible_resources" => ["x.js"], "update_url" => "https://u.test/", "oauth2" => { "scopes" => ["openid"] }
    )
    groups = ScanPage::FindingGroups.new(findings)
    areas = groups.findings.to_h { |f| [f.rule, groups.area_for(f)] }
    assert_equal({ "settings.search_provider" => :browser, "url_overrides" => :browser, "oauth2.sign_in" => :browser,
                   "content_script.main_world" => :site_access, "externally_connectable" => :site_access,
                   "web_accessible_resources.all_sites" => :site_access, "update_url.external" => :code_policy },
                 areas.except("manifest.v2"))
  end

  # --- junk ------------------------------------------------------------------------

  test "junk in the new keys never raises" do
    junk_values = [nil, 5, "x", [], {}, [nil, 3, "a"], { "a" => { "b" => [1] } }, true, 2.5]
    keys = %w[chrome_settings_overrides chrome_url_overrides externally_connectable web_accessible_resources update_url oauth2]
    nested = [
      { "chrome_settings_overrides" => { "search_provider" => [1, 2], "homepage" => 5, "startup_pages" => "https://a.test/" } },
      { "chrome_settings_overrides" => { "search_provider" => { "search_url" => nil, "name" => ["x"], "is_default" => "true" } } },
      { "chrome_url_overrides" => { "newtab" => 5, "history" => nil, "bookmarks" => ["x"] } },
      { "content_scripts" => [{ "world" => "MAIN" }, { "world" => 5, "matches" => "<all_urls>" }, { "matches" => [nil, 3], "world" => "main" },
                              { "matches" => ["<all_urls>"], "all_frames" => "yes", "run_at" => 5 }] },
      { "externally_connectable" => { "matches" => "https://a.test/*", "ids" => 5 } },
      { "externally_connectable" => { "matches" => [nil, 5, { "a" => 1 }, "*"] } },
      { "web_accessible_resources" => [nil, 5, ["x"], { "resources" => "x", "matches" => ["<all_urls>"] },
                                       { "resources" => [1, nil], "matches" => ["<all_urls>"] }, { "matches" => "<all_urls>" }] },
      { "oauth2" => { "scopes" => "openid" } }, { "oauth2" => { "scopes" => [nil, 5, "", "  "] } }, { "update_url" => "   " }
    ]
    cases = keys.product(junk_values).map { |key, value| { key => value } } + nested
    cases.each do |raw|
      [raw, raw.deep_symbolize_keys].each do |variant|
        manifest = { raw: variant.merge("manifest_version" => 3) }
        findings = nil
        assert_nothing_raised { findings = ExtensionSecurityAnalyzer.rule_findings(manifest) }
        findings.drop(1).each do |f|
          assert_includes ExtensionAnalyzerData::RULE_IDS, f[:rule]
          assert f[:evidence].all? { |path| path.all? { |step| step.is_a?(String) || step.is_a?(Integer) } }
        end
      end
    end
  end
end
