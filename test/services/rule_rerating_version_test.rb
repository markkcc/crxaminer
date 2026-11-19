require "test_helper"

class RuleReratingVersionTest < ActiveSupport::TestCase
  RAW = { "manifest_version" => 3, "chrome_url_overrides" => { "newtab" => "n.html" } }.freeze

  test "scans rated with rules version 2 are picked up again and gain the new findings" do
    ScanResult.delete_all
    v2 = ScanResult.create!(extension_id: "1" * 32, manifest: { manifest_version: 3, raw: RAW },
                            security_findings: [{ severity: "Minimal", title: "Overall Risk: Minimal",
                                                  description: "x", rules_version: 2 }])
    current = ScanResult.create!(extension_id: "2" * 32, manifest: { manifest_version: 3, raw: RAW },
                                 security_findings: ExtensionSecurityAnalyzer.rule_findings(raw: RAW))

    assert_equal [v2.id], RuleRerating.candidates.pluck(:id)
    result = RuleRerating.new(all: true, out: StringIO.new).run

    assert_equal 1, result.updated
    assert_equal({ %w[Minimal Medium] => 1 }, result.changes)
    findings = v2.reload.security_findings
    assert_equal 4, findings.first[:rules_version]
    assert_equal ["url_overrides"], findings.drop(1).map { |f| f[:rule] }
    assert_empty RuleRerating.candidates
    assert current.reload.security_findings.first[:rules_version] == 4
  end
end
