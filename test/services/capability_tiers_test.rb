require "test_helper"

# Part 1: finding levels are capability tiers, with the R3 full-control
# items at Critical and factual titles.
class CapabilityTiersTest < ActiveSupport::TestCase
  def findings_for(raw, version = 3)
    raw = { "manifest_version" => version }.merge(raw)
    manifest = { manifest_version: version, permissions: raw["permissions"] || [], host_permissions: raw["host_permissions"] || [],
                 optional_permissions: raw["optional_permissions"] || [], content_scripts: raw["content_scripts"], raw: raw }
    fresh = ExtensionSecurityAnalyzer.rule_findings(manifest)
    assert_equal fresh, ExtensionSecurityAnalyzer.rule_findings(ScanResult.new(manifest: manifest).manifest), "fresh and stored agree"
    fresh
  end

  def access(findings)
    findings.first[:access]
  end

  test "nativeMessaging, proxy and management are full control, with plain titles" do
    %w[nativeMessaging proxy management debugger].each do |name|
      findings = findings_for("permissions" => [name, "storage"])
      finding = findings.find { |f| f[:rule] == "permission" && f[:title] == "Permission: #{name}" }
      assert_equal "Critical", finding[:severity], name
      assert_equal "Critical", access(findings), name
      assert_equal "Full control", ScanRating.access_tier(access(findings)).name
    end
  end

  test "main-world scripts on all sites and an outside update server are full control" do
    main = findings_for("content_scripts" => [{ "matches" => ["<all_urls>"], "world" => "MAIN" }])
    assert_equal "Critical", main.find { |f| f[:rule] == "content_script.main_world_all_sites" }[:severity]
    assert_equal "Critical", access(main)

    named = findings_for("content_scripts" => [{ "matches" => ["https://a.test/*"], "world" => "MAIN" }])
    assert_equal "Medium", access(named), "main-world scripts on named sites stay scoped"

    update = findings_for("update_url" => "https://updates.example.net/x.xml")
    assert_equal "Critical", access(update)
    assert_equal "Minimal", access(findings_for("update_url" => "https://clients2.google.com/service/update2/crx"))
  end

  test "all-site access plus scripting is broad reach, the same tier as content scripts on all sites" do
    scripting = findings_for("permissions" => ["scripting"], "host_permissions" => ["<all_urls>"])
    declared = findings_for("content_scripts" => [{ "matches" => ["<all_urls>"], "js" => ["a.js"] }])
    assert_equal "High", access(scripting)
    assert_equal access(declared), access(scripting)
    assert scripting.none? { |f| f[:severity] == "Critical" }
  end

  test "optional items stay one level lower and never Critical" do
    findings = findings_for("optional_permissions" => %w[nativeMessaging proxy management debugger])
    optional = findings.select { |f| f[:rule] == "optional.permission" }
    assert_equal %w[High High High High], optional.map { |f| f[:severity] }
    assert_equal "High", access(findings)
    assert_equal "High", ScanPage::PermissionCatalog.rating("proxy", optional: true)
    assert_equal "Critical", ScanPage::PermissionCatalog.rating("proxy")
  end

  test "every full-control item has a one-sentence reason, and only those" do
    critical = ExtensionAnalyzerData.permissions_by_level.fetch("Critical") +
               ExtensionAnalyzerData.rules.select { |r| r.severity == "Critical" }.map(&:id)
    assert_equal critical.sort, ExtensionAnalyzerData::FULL_CONTROL_REASONS.keys.sort
    assert_equal %w[debugger management nativeMessaging proxy], ExtensionAnalyzerData.permissions_by_level.fetch("Critical")
    ExtensionAnalyzerData::FULL_CONTROL_REASONS.each do |key, reason|
      assert_equal reason, ExtensionAnalyzerData.full_control_reason(key)
      assert_equal 1, reason.scan(/[.!?](\s|\z)/).size, "#{key}: one sentence"
    end
    assert_nil ExtensionAnalyzerData.full_control_reason("scripting")
    assert_nil ExtensionAnalyzerData.full_control_reason(nil)
    assert_equal 4, ExtensionSecurityAnalyzer::RULES_VERSION
  end

  test "titles state facts, not ratings" do
    raw = {
      "permissions" => ExtensionAnalyzerData::PERMISSIONS.keys + ["<all_urls>"],
      "optional_permissions" => %w[history], "optional_host_permissions" => ["https://*/*"],
      "content_scripts" => [{ "matches" => ["<all_urls>"], "world" => "MAIN" }],
      "content_security_policy" => "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'",
      "update_url" => "https://u.test/x", "chrome_settings_overrides" => { "homepage" => "https://h.test" },
      "web_accessible_resources" => ["*"], "externally_connectable" => { "matches" => ["http://*.a.test/*"] }
    }
    titles = findings_for(raw, 2).drop(1).map { |f| f[:title] }
    assert_operator titles.size, :>, 80
    titles.each { |title| assert_no_match(/risk|unsafe|danger/i, title) }
    assert_includes titles, "Text Can Be Run as Code"
  end

  test "the scan page still reads old and new permission titles alike" do
    old = { severity: "Medium", title: "Medium-Risk Permission: storage", description: "old" }
    new_low = { severity: "Low", title: "Permission: alarms", description: "new", rule: "permission" }
    new_high = { "severity" => "High", "title" => "Permission: history", "description" => "new", "rule" => "permission" }
    legacy_high = { severity: "High", title: "High-Risk Permission: tabs", description: "old" }
    groups = ScanPage::FindingGroups.new([new_low, old, new_high, legacy_high, "junk", nil])

    browser = groups.areas.find { |a| a.key == :browser }
    assert_equal %w[alarms storage], browser.routine.map(&:permission).sort
    assert_equal ["Permission: history", "High-Risk Permission: tabs"].sort, browser.findings.map(&:title).sort
    assert_equal %w[history tabs], groups.findings.select { |f| f.severity == "High" }.map(&:permission).sort
    assert_nil ScanPage::FindingGroups.new([{ title: "Optional Permission: x" }]).findings.first.permission,
               "an optional title without a rule id is not a permission"
  end

  test "required items come before optional ones of the same level" do
    findings = findings_for("permissions" => %w[alarms storage], "optional_permissions" => %w[contextMenus])
    low = ScanPage::FindingGroups.new(findings).findings.select { |f| f.severity == "Low" }
    assert_equal [false, false, true], low.map(&:optional)
  end
end
