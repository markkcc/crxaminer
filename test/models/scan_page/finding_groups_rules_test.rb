require "test_helper"

# Findings written by the current rule engine, which carry rule ids.
class ScanPage::FindingGroupsRulesTest < ActiveSupport::TestCase
  RAW = {
    "manifest_version" => 2,
    "permissions" => %w[storage alarms tabs debugger cookies <all_urls> file:///* https://github.com/*],
    "optional_permissions" => %w[contextMenus history],
    "optional_host_permissions" => ["https://*/*"],
    "content_scripts" => [{ "matches" => ["*://*/*"] }],
    "content_security_policy" => "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'"
  }.freeze

  def area(groups, key)
    groups.areas.find { |a| a.key == key }
  end

  def groups
    @groups ||= ScanPage::FindingGroups.new(ExtensionSecurityAnalyzer.rule_findings(raw: RAW))
  end

  test "new findings are grouped by rule id" do
    assert_equal %i[site_access browser code_policy network], groups.areas.map(&:key)
    site = area(groups, :site_access).findings.map(&:rule)
    # Optional access to all sites adds nothing when all sites are already granted.
    assert_equal %w[content_script.all_sites host.all_sites host.file host.sensitive], site.sort
    browser = (area(groups, :browser).findings + area(groups, :browser).routine).map(&:rule).uniq.sort
    assert_equal %w[combination.all_sites_cookies optional.permission permission], browser
    assert_equal %w[csp.unsafe_eval csp.wasm_unsafe_eval manifest.v2].sort, area(groups, :code_policy).findings.map(&:rule).sort
  end

  test "routine folding follows the Low rating of the permission table, optional ones are marked" do
    browser = area(groups, :browser)
    assert_equal %w[alarms contextMenus storage], browser.routine.map(&:permission).sort
    assert_equal "3 routine permissions: alarms · storage · contextMenus (optional)", browser.routine_label
    # Optional history is rated one level lower but is not routine.
    history = browser.findings.find { |f| f.permission == "history" }
    assert history.optional
    assert_equal "Medium", history.severity
    assert_equal "Optional Permission: history", history.title
    assert_not browser.findings.find { |f| f.permission == "tabs" }.optional
  end

  test "evidence is passed through for the page" do
    debugger = area(groups, :browser).findings.find { |f| f.permission == "debugger" }
    assert_equal [["permissions", 3]], debugger.evidence
    assert_equal "Critical", debugger.severity
  end

  test "old findings without a rule still use the title mapping, and old routine permissions fold" do
    old = ScanPage::FindingGroups.new([
      { severity: "Medium", title: "Medium-Risk Permission: storage", description: "d" },
      { severity: "Medium", title: "Medium-Risk Permission: alarms", description: "d" },
      { severity: "High", title: "Broad Host Permissions", description: "d" },
      { severity: "High", title: "Unsafe WebAssembly Execution", description: "d" }
    ])
    assert_equal %w[alarms storage], area(old, :browser).routine.map(&:permission).sort
    assert_equal ["Broad Host Permissions"], area(old, :site_access).findings.map(&:title)
    assert_equal ["Unsafe WebAssembly Execution"], area(old, :code_policy).findings.map(&:title)
  end

  test "an unknown rule id falls back to the title, then to Other" do
    groups = ScanPage::FindingGroups.new([{ severity: "Low", title: "Broad Host Permissions", rule: "future.rule" },
                                          { severity: "Low", title: "Something new", rule: "future.other" }])
    assert_equal ["Broad Host Permissions"], area(groups, :site_access).findings.map(&:title)
    assert_equal ["Something new"], area(groups, :other).findings.map(&:title)
  end

  test "the rules version comes from the overall finding" do
    assert_equal ExtensionSecurityAnalyzer::RULES_VERSION,
                 ScanPage::FindingGroups.rules_version(ExtensionSecurityAnalyzer.rule_findings({}))
    assert_equal 1, ScanPage::FindingGroups.rules_version([{ title: "Overall Risk: High" }])
    assert_equal 1, ScanPage::FindingGroups.rules_version([{ title: "Overall Risk: High", rules_version: "2" }])
    assert_equal 1, ScanPage::FindingGroups.rules_version(nil)
    assert_equal 1, ScanPage::FindingGroups.rules_version(["junk", 5])
  end
end
