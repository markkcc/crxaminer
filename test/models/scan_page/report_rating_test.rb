require "test_helper"

class ScanPage::ReportRatingTest < ActiveSupport::TestCase
  def report(findings)
    ScanPage::Report.new(manifest: {}, security_findings: findings, extension_details: { users: "300" })
  end

  test "exposes the display level and the AI check in the current format only" do
    new_ai = { "severity" => "Info", "title" => "AI Context Analysis", "description" => "x",
               "ai" => { "concern_level" => "some", "purpose_fit" => "fits", "summary" => "S", "concerns" => ["c", 5, nil],
                         "trust_factors" => "nope", "model" => "m", "analyzed_at" => "2026-11-19T00:00:00Z" } }
    r = report([{ title: "Overall Risk: High", severity: "High", rules_version: 4, access: "Medium" }, new_ai])
    assert_equal "High", r.display_level
    assert_equal new_ai, r.ai_finding
    check = r.ai_check
    assert_equal ["some", "fits", "S", ["c"], [], [], "m"],
                 check.to_h.values_at(:concern_level, :purpose_fit, :summary, :concerns, :trust_factors, :recommendations, :model)
    assert_equal "concerns", r.rating.trust.key

    old = report([{ title: "Overall Risk: High", severity: "High" },
                  { severity: "Info", title: "AI Context Analysis", description: "Risk Level: Low", ai: { risk_level: "Low" } }])
    assert_equal "Low", old.display_level
    assert old.ai_finding
    assert_nil old.ai_check

    [nil, "junk", [nil, 5], [{ severity: "Info", title: "AI Context Analysis", ai: "?" }]].each do |junk|
      assert_nothing_raised { [report(junk).display_level, report(junk).ai_check, report(junk).rating.overall] }
      assert_nil report(junk).ai_check
    end
  end
end
