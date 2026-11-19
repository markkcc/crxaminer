require "test_helper"

# The rule engine on its own (no AI step, no tweet). Each "defect" test
# covers one item of the rule-engine review and fails on the engine it
# replaced.
class ExtensionSecurityAnalyzerRulesTest < ActiveSupport::TestCase
  # What ExtensionAnalyzer#extract_manifest returns for a manifest.json.
  def extracted(raw)
    csp = raw["content_security_policy"]
    csp = case csp
          when Hash then csp.map { |k, v| "#{k}: #{v}" }
          when nil then []
          else [csp]
          end
    {
      manifest_version: raw["manifest_version"], name: raw["name"], version: raw["version"],
      permissions: raw["permissions"] || [], optional_permissions: raw["optional_permissions"] || [],
      host_permissions: raw["host_permissions"] || [], optional_host_permissions: raw["optional_host_permissions"] || [],
      content_scripts: raw["content_scripts"], embedded_urls: [], content_security_policy: csp, raw: raw
    }
  end

  # The same manifest after a round trip through the database.
  def stored(manifest)
    ScanResult.new(manifest: manifest).manifest
  end

  def findings_for(raw, version = 3)
    raw = { "manifest_version" => version }.merge(raw)
    fresh = ExtensionSecurityAnalyzer.rule_findings(extracted(raw))
    assert_equal fresh, ExtensionSecurityAnalyzer.rule_findings(stored(extracted(raw))), "fresh and stored manifests must agree"
    fresh
  end

  def overall(findings)
    findings.first[:severity]
  end

  def by_rule(findings, rule)
    findings.select { |f| f[:rule] == rule }
  end

  def rules(findings)
    findings.drop(1).map { |f| f[:rule] }
  end

  # The raw manifest value at an evidence path.
  def resolve(raw, path)
    path.reduce(raw) { |node, step| node.is_a?(Hash) ? node.fetch(step) : node.fetch(step) }
  end

  # --- defect 1: any wildcard counted as "broad" ---------------------------

  test "defect 1: a wildcard subdomain is a named site, not access to all sites" do
    findings = findings_for("host_permissions" => ["https://*.example.com/*"])

    assert_empty by_rule(findings, "host.all_sites")
    assert_not findings.any? { |f| f[:title] == "Broad Host Permissions" }
    assert_equal "Minimal", overall(findings)
  end

  test "a wildcard over a whole public suffix is all sites and says so" do
    findings = findings_for("host_permissions" => ["https://a.test/*", "*://*.com/*", "https://*.co.uk/*"])
    all = by_rule(findings, "host.all_sites").sole

    assert_equal "High", all[:severity]
    assert_equal [["host_permissions", 1], ["host_permissions", 2]], all[:evidence]
    assert_includes all[:description], "covers every site ending in .com"
    assert_includes all[:description], "covers every site ending in .co.uk"
  end

  # --- defect 2: content scripts needed an exact match ---------------------

  test "defect 2: content scripts on https://*/* run on all sites" do
    findings = findings_for("content_scripts" => [{ "matches" => ["https://a.test/*"] },
                                                  { "matches" => ["https://*/*", "http://*/*"] }])
    scripts = by_rule(findings, "content_script.all_sites").sole

    assert_equal "High", scripts[:severity]
    assert_equal [["content_scripts", 1, "matches", 0], ["content_scripts", 1, "matches", 1]], scripts[:evidence]
    assert_equal "High", overall(findings)
  end

  # --- defect 3: Manifest V2 host patterns were skipped ---------------------

  test "defect 3: Manifest V2 match patterns in permissions grant site access" do
    findings = findings_for({ "permissions" => ["tabs", "*://*/*", "http://*/"] }, 2)
    all = by_rule(findings, "host.all_sites").sole

    assert_equal [["permissions", 1], ["permissions", 2]], all[:evidence]
    # They are patterns, not API permissions.
    assert_equal ["Permission: tabs"], by_rule(findings, "permission").map { |f| f[:title] }
  end

  test "Manifest V3 ignores match patterns in permissions, as Chrome does" do
    findings = findings_for("permissions" => ["*://*/*", "<all_urls>"])
    assert_equal [], rules(findings)
  end

  # --- defect 4: 'wasm-unsafe-eval' rated High and hiding 'unsafe-eval' ----

  test "defect 4: 'wasm-unsafe-eval' is Low and does not hide 'unsafe-eval'" do
    wasm = findings_for("content_security_policy" => { "extension_pages" => "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" })
    assert_equal ["csp.wasm_unsafe_eval"], rules(wasm)
    assert_equal "Low", overall(wasm)
    assert_includes wasm[1][:description], "standard way to use WebAssembly"
    assert_equal [["content_security_policy", "extension_pages"]], wasm[1][:evidence]

    both = findings_for({ "content_security_policy" => "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'; object-src 'self'" }, 2)
    assert_equal "High", by_rule(both, "csp.unsafe_eval").sole[:severity]
    assert_equal "Low", by_rule(both, "csp.wasm_unsafe_eval").sole[:severity]
    assert_equal [["content_security_policy"]], by_rule(both, "csp.unsafe_eval").sole[:evidence]
  end

  test "only the extension pages policy counts; sandbox pages and other directives do not" do
    sandbox = findings_for("content_security_policy" => { "sandbox" => "sandbox allow-scripts; script-src 'self' 'unsafe-eval'",
                                                         "extension_pages" => "script-src 'self'" })
    assert_equal [], rules(sandbox)

    # 'unsafe-eval' outside the directive that governs eval does not count;
    # default-src counts when there is no script-src.
    style = findings_for("content_security_policy" => { "extension_pages" => "script-src 'self'; style-src 'unsafe-eval'" })
    assert_equal [], rules(style)
    fallback = findings_for("content_security_policy" => { "extension_pages" => "default-src 'self' 'unsafe-eval'" })
    assert_equal ["csp.unsafe_eval"], rules(fallback)
  end

  test "a stored manifest without raw is read from the flattened policy strings" do
    manifest = { manifest_version: 3, content_security_policy: ["sandbox: script-src 'unsafe-eval'", "extension_pages: script-src 'self' 'unsafe-eval'"] }
    findings = ExtensionSecurityAnalyzer.rule_findings(manifest)
    assert_equal [["content_security_policy", "extension_pages"]], by_rule(findings, "csp.unsafe_eval").sole[:evidence]
  end

  # --- defect 5: sensitive domains matched by substring ---------------------

  test "defect 5: unrelated hosts that contain a brand or a word are not sensitive" do
    hosts = %w[https://fonts.googleapis.com/* https://otherwise.com/* https://mytarget.example/* https://squarespace.com/*
               https://bankrate.com/* https://gemini.example.org/* https://*.googleusercontent.com/* https://cryptozoo.com/*]
    findings = findings_for("host_permissions" => hosts)

    assert_empty by_rule(findings, "host.sensitive")
    assert_not findings.any? { |f| f[:title] == "Access to Sensitive Domains" }
  end

  test "sensitive sites match by registrable domain, and brands across country domains" do
    hosts = %w[https://www.paypal.com/* https://*.google.de/* https://amazon.co.uk/* https://github.com/me/*
               https://login.chase.com/* https://a.test/*]
    sensitive = by_rule(findings_for("host_permissions" => hosts), "host.sensitive").sole

    assert_equal "Medium", sensitive[:severity]
    assert_equal (0..4).map { |i| ["host_permissions", i] }, sensitive[:evidence]
    %w[paypal.com google.de amazon.co.uk github.com chase.com].each { |d| assert_includes sensitive[:description], d }
    assert_not_includes sensitive[:description], "a.test"
  end

  test "all-site patterns are not sensitive sites" do
    assert_empty by_rule(findings_for("host_permissions" => ["<all_urls>"]), "host.sensitive")
  end

  # --- defect 6: Critical was only a count -----------------------------------

  test "defect 6: many High permissions stay High; Critical needs an explicit rule" do
    many = findings_for("permissions" => %w[history privacy webNavigation browsingData clipboardRead tabCapture])
    assert_equal 6, by_rule(many, "permission").count { |f| f[:severity] == "High" }
    assert_equal "High", overall(many)

    debugger = findings_for("permissions" => %w[debugger])
    assert_equal "Critical", overall(debugger)
    assert_equal "Permission: debugger", debugger[1][:title]
  end

  test "all sites plus cookies is one Critical finding pointing at every entry, and the parts are still reported" do
    raw = { "permissions" => %w[storage cookies], "host_permissions" => ["https://*/*", "http://*/*"] }
    findings = findings_for(raw)
    combo = by_rule(findings, "combination.all_sites_cookies").sole

    assert_equal "Critical", combo[:severity]
    assert_equal "Critical", overall(findings)
    assert_equal [["host_permissions", 0], ["host_permissions", 1], ["permissions", 1]], combo[:evidence]
    assert by_rule(findings, "host.all_sites").one?
    assert by_rule(findings, "permission").any? { |f| f[:title] == "Permission: cookies" }
  end

  test "all sites plus webRequest and webRequestBlocking is Critical; either one alone is not" do
    v2 = findings_for({ "permissions" => ["webRequest", "webRequestBlocking", "<all_urls>"] }, 2)
    combo = by_rule(v2, "combination.all_sites_web_request_blocking").sole
    assert_equal [["permissions", 2], ["permissions", 0], ["permissions", 1]], combo[:evidence]

    partial = findings_for({ "permissions" => ["webRequest", "<all_urls>"] }, 2)
    assert_equal "High", overall(partial)

    named = findings_for({ "permissions" => %w[webRequest webRequestBlocking cookies https://a.test/*] }, 2)
    assert_equal "Medium", overall(named)
  end

  test "combinations only count required access" do
    findings = findings_for("permissions" => ["cookies"], "optional_host_permissions" => ["<all_urls>"],
                            "content_scripts" => [{ "matches" => ["<all_urls>"] }])
    assert_empty findings.select { |f| f[:rule].to_s.start_with?("combination.") }
  end

  # --- defect 7: routine permissions were Medium -----------------------------

  test "defect 7: routine permissions are Low and leave the extension Low" do
    findings = findings_for("permissions" => %w[storage notifications contextMenus activeTab])

    assert_equal %w[Low Low Low Low], by_rule(findings, "permission").map { |f| f[:severity] }
    assert_equal "Low", overall(findings)
    assert_equal ["Permission: storage", "Permission: notifications",
                  "Permission: contextMenus", "Permission: activeTab"], findings.drop(1).map { |f| f[:title] }
  end

  test "names that are not in the table produce no finding" do
    assert_equal [], rules(findings_for("permissions" => ["action", "Tabs", "webview", "<all_urls>"]))
  end

  # --- defect 8: optional permissions were never analyzed --------------------

  test "defect 8: optional permissions are rated one level lower and say Chrome asks first" do
    findings = findings_for("permissions" => ["tabs"],
                            "optional_permissions" => %w[tabs debugger history cookies storage],
                            "optional_host_permissions" => ["https://*/*", "https://www.paypal.com/*"])
    optional = findings.select { |f| f[:rule].to_s.start_with?("optional.") }
    levels = optional.to_h { |f| [f[:title], f[:severity]] }

    assert_equal({ "Optional Permission: debugger" => "High", "Optional Permission: history" => "Medium",
                   "Optional Permission: cookies" => "Low", "Optional Permission: storage" => "Low",
                   "Optional Access to All Websites" => "Medium", "Optional Access to Sensitive Sites" => "Low" }, levels)
    optional.each { |f| assert_includes f[:description], "Chrome asks you" }
    assert_equal [["optional_permissions", 1]], optional.find { |f| f[:title] == "Optional Permission: debugger" }[:evidence]
    assert_equal [["optional_host_permissions", 0]], by_rule(findings, "optional.host.all_sites").sole[:evidence]
    # Never Critical, and the optional debugger does not make the extension Critical.
    assert_equal "High", overall(findings)
  end

  test "Manifest V2 optional patterns live in optional_permissions" do
    findings = findings_for({ "optional_permissions" => ["*://*/*", "file:///*"] }, 2)
    assert_equal [["optional_permissions", 0]], by_rule(findings, "optional.host.all_sites").sole[:evidence]
    assert_equal [["optional_permissions", 1]], by_rule(findings, "optional.host.file").sole[:evidence]
  end

  # --- other rules -------------------------------------------------------------

  test "file access is its own Low finding, not all sites" do
    findings = findings_for("host_permissions" => ["file:///*"], "content_scripts" => [{ "matches" => ["file://*/*"] }])

    assert_equal ["host.file"], rules(findings)
    assert_equal [["host_permissions", 0], ["content_scripts", 0, "matches", 0]], findings[1][:evidence]
    assert_equal "Low", overall(findings)
  end

  test "Manifest V2 is Low and points at manifest_version" do
    findings = findings_for({}, 2)
    assert_equal ["manifest.v2"], rules(findings)
    assert_equal "Low", findings[1][:severity]
    assert_equal [["manifest_version"]], findings[1][:evidence]
  end

  test "the overall finding states its basis and the rules version" do
    findings = findings_for("permissions" => %w[tabs storage history])
    assert_equal({ severity: "High", title: "Overall Risk: High",
                   description: "Access: Broad reach (the highest of 3 rule findings). Trust: Unproven. " \
                                "Install it only if you know and trust the publisher.",
                   rules_version: ExtensionSecurityAnalyzer::RULES_VERSION, access: "High", trust: "unproven",
                   headline: "Powerful, unproven publisher" }, findings.first)

    none = findings_for({})
    assert_equal "Overall Risk: Minimal", none.first[:title]
    assert_equal 1, none.size
  end

  test "repeated entries are one finding pointing at each" do
    findings = findings_for("permissions" => %w[tabs storage tabs])
    assert_equal [["permissions", 0], ["permissions", 2]], findings.find { |f| f[:title] == "Permission: tabs" }[:evidence]
  end

  test "every evidence path resolves to the entry in the raw manifest" do
    raw = {
      "manifest_version" => 2,
      "permissions" => ["cookies", "webRequest", "webRequestBlocking", "<all_urls>", "debugger", "file:///*", "https://github.com/*"],
      "optional_permissions" => ["history", "https://*.co.uk/*"],
      "optional_host_permissions" => ["https://www.paypal.com/*"],
      "content_scripts" => [{ "matches" => ["https://a.test/*"] }, { "matches" => ["*://*/*"] }],
      "content_security_policy" => "script-src 'self' 'unsafe-eval'"
    }
    findings = findings_for(raw, 2).drop(1)

    assert findings.all? { |f| f[:rule] && f[:evidence].present? }
    findings.each do |f|
      f[:evidence].each { |path| assert_not_nil resolve(raw, path), "#{f[:title]} #{path.inspect}" }
    end
    resolved = findings.flat_map { |f| f[:evidence].map { |p| resolve(raw, p) } }.uniq
    assert_includes resolved, "<all_urls>"
    assert_includes resolved, "*://*/*"
    assert_includes resolved, "https://github.com/*"
  end

  # --- junk input ----------------------------------------------------------------

  test "junk manifests never raise" do
    junk = [
      nil, "string", 5, [], {},
      { permissions: "tabs", host_permissions: "<all_urls>", content_scripts: "x", optional_permissions: { a: 1 } },
      { permissions: [nil, 5, 3.2, ["tabs"], { "tabs" => true }, "", "debugger"], host_permissions: [nil, 7, {}, "*", "http://"],
        content_scripts: [nil, 5, "x", { matches: "<all_urls>" }, { "matches" => [nil, 3, "*://*/*"] }, { matches: { a: 1 } }],
        content_security_policy: { extension_pages: 5, sandbox: nil }, manifest_version: "three" },
      { raw: "not a hash", permissions: ["tabs"] },
      { raw: { "permissions" => "tabs", "content_security_policy" => 42, "manifest_version" => [3] } },
      { raw: { "manifest_version" => 3.0, "content_security_policy" => ["script-src 'unsafe-eval'"] } },
      { manifest_version: 2.5, content_security_policy: "script-src 'unsafe-eval'" },
      { raw: { "optional_host_permissions" => [nil, 1, "https://*.co.uk/*"], "optional_permissions" => "x" } }
    ]
    junk.each do |manifest|
      findings = nil
      assert_nothing_raised { findings = ExtensionSecurityAnalyzer.rule_findings(manifest) }
      assert findings.first[:title].start_with?("Overall Risk: ")
      assert_includes ExtensionAnalyzerData::OVERALL_LEVELS, findings.first[:severity]
      findings.drop(1).each do |f|
        assert_includes ExtensionAnalyzerData::LEVELS, f[:severity]
        assert_includes ExtensionAnalyzerData::RULE_IDS, f[:rule]
        assert f[:evidence].all? { |path| path.all? { |s| s.is_a?(String) || s.is_a?(Integer) } }
      end
    end

    # The valid parts of a junk manifest are still rated.
    mixed = ExtensionSecurityAnalyzer.rule_findings(junk[6])
    assert_equal "Critical", mixed.first[:severity] # debugger
    assert_equal [["content_scripts", 4, "matches", 2]], by_rule(mixed, "content_script.all_sites").sole[:evidence]
    assert_empty by_rule(mixed, "host.all_sites") # a bare "*" is not a match pattern
  end

  test "a missing manifest gives no findings at all from analyze" do
    assert_equal [], ExtensionSecurityAnalyzer.new(nil).analyze
  end

  # --- the read-only API for the help page ---------------------------------------

  test "the rule data is complete and consistent" do
    data = ExtensionAnalyzerData
    assert_equal %w[Critical High Medium Low], data::LEVELS
    assert_equal %w[Critical High Medium Low Minimal], data::OVERALL_LEVELS
    assert_equal data::RULE_IDS.uniq, data::RULE_IDS
    assert_equal %w[combination.all_sites_cookies combination.all_sites_web_request_blocking], data.critical_combinations.map(&:id)
    data.rules.each do |rule|
      assert rule.severity.nil? || data::LEVELS.include?(rule.severity), rule.id
      assert rule.name.present? && rule.summary.present?, rule.id
    end

    by_level = data.permissions_by_level
    assert_equal data::LEVELS, by_level.keys
    assert_equal %w[debugger management nativeMessaging proxy], by_level["Critical"]
    assert_equal data::PERMISSIONS.size, by_level.values.sum(&:size)
    assert_includes by_level["Low"], "activeTab"
    data::PERMISSIONS.each_value do |p|
      assert p.allows.present?, p.name
      assert_equal p.level == "Low", p.why.nil?, "#{p.name}: a reason is given exactly for levels above Low"
    end

    assert_equal "High", data.optional_level("Critical")
    assert_equal "Low", data.optional_level("Low")
    assert_nil data.optional_level("Bogus")
    assert_equal "Payments and investing", data.sensitive_category("paypal.de", "paypal")
    assert_nil data.sensitive_category("googleapis.com", "googleapis")
    assert data.sensitive_sites.key?("Banking")
  end
end
