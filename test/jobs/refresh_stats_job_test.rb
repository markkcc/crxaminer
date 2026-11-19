require "test_helper"

class RefreshStatsJobTest < ActiveJob::TestCase
  test "counts the AI risk level from the stored description and falls back to the overall risk" do
    ScanResult.delete_all
    overall = { severity: "Medium", title: "Overall Risk: Medium", description: "x" }
    ai = { severity: "Info", title: "AI Context Analysis",
           description: "Risk Level: Critical\ns\n\nConcerns:\n- c",
           ai: { risk_level: "Critical" } }
    ScanResult.create!(extension_id: "6" * 32, manifest: {}, security_findings: [overall, ai])
    ScanResult.create!(extension_id: "7" * 32, manifest: {}, security_findings: [overall])

    RefreshStatsJob.perform_now

    counts = StatCache.first.severity_counts
    assert_equal 1, counts["Critical"]
    assert_equal 1, counts["Medium"]
  end
end
