require "test_helper"

class ExtensionSecurityAnalyzerOrderTest < ActiveSupport::TestCase
  # 35 routine permissions, then the ones that matter, as an extension might list them.
  ROUTINE = ExtensionAnalyzerData.permissions_by_level.fetch("Low").first(35).freeze
  MANIFEST = {
    manifest_version: 3, name: "Long list", version: "1.0",
    permissions: ROUTINE + %w[cookies history], host_permissions: ["<all_urls>"],
    content_scripts: nil, content_security_policy: [], embedded_urls: []
  }.freeze

  test "rule findings are stored most severe first, after the overall rating" do
    findings = ExtensionSecurityAnalyzer.rule_findings(MANIFEST)

    assert_equal "Overall Risk: Critical", findings.first[:title]
    levels = findings.drop(1).map { |f| ExtensionAnalyzerData::LEVELS.index(f[:severity]) }
    assert_equal levels.sort, levels
    assert_equal "combination.all_sites_cookies", findings[1][:rule]
    assert_equal ROUTINE.map { |name| "Low-Risk Permission: #{name}" }, findings.last(35).map { |f| f[:title] },
                 "within a level the manifest order is kept"
  end

  test "the AI request keeps the serious findings of a long list" do
    findings = ExtensionSecurityAnalyzer.rule_findings(MANIFEST)
    sent = AiContextAnalysis.build_payload(manifest: MANIFEST, extension_details: {}, extension_name: "Long list",
                                           findings: findings)[:findings]

    assert_operator findings.size, :>, sent.size, "the list is longer than what is sent"
    assert_includes sent, "Critical: All Websites Plus Cookies"
    assert_includes sent, "High: Access to All Websites"
    assert_includes sent, "High: High-Risk Permission: history"
    assert_includes sent, "Medium: Medium-Risk Permission: cookies"
  end
end
