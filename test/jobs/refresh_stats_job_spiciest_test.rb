require "test_helper"

class RefreshStatsJobSpiciestTest < ActiveJob::TestCase
  test "spiciest counts rule findings but not the overall rating, the AI verdict or routine permissions" do
    ScanResult.delete_all
    routine = %w[storage alarms notifications contextMenus activeTab unlimitedStorage].map do |name|
      { severity: "Low", title: "Low-Risk Permission: #{name}", description: "x", rule: "permission" }
    end
    ai = { severity: "Info", title: "AI Context Analysis", description: "Risk Level: Low" }
    ScanResult.create!(extension_id: "a" * 32, extension_name: "Routine", manifest: {},
                       security_findings: [{ severity: "Low", title: "Overall Risk: Low", description: "x" }] + routine + [ai])
    ScanResult.create!(extension_id: "b" * 32, extension_name: "Risky", manifest: {},
                       security_findings: ExtensionSecurityAnalyzer.rule_findings(permissions: %w[debugger history]))

    RefreshStatsJob.perform_now

    counts = StatCache.first.spiciest_extensions.to_h { |e| [e["extension_name"] || e[:extension_name], e["finding_count"] || e[:finding_count]] }
    assert_equal({ "Risky" => 2, "Routine" => 0 }, counts)
    assert_equal 1, StatCache.first.severity_counts["Critical"]
  end
end
