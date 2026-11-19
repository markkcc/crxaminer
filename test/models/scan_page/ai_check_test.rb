require "test_helper"

class ScanPage::AiCheckTest < ActiveSupport::TestCase
  def check(finding)
    ScanPage::AiCheck.for([{ title: "Overall Risk: High", severity: "High" }, finding])
  end

  def ai_finding(**fields)
    { title: "AI Context Analysis", severity: "Info" }.merge(fields)
  end

  test "a scan without an AI finding has no check" do
    assert_nil ScanPage::AiCheck.for([{ title: "Overall Risk: High", severity: "High" }])
    assert_nil ScanPage::AiCheck.for(nil)
    assert_nil ScanPage::AiCheck.for("junk")
    assert_nil ScanPage::AiCheck.for([{ title: "AI Context Analysis", severity: "High" }]), "only the Info finding is the AI's"
  end

  test "the current format gives purpose fit and concern level, the summary and the lists" do
    ai = check(ai_finding(ai: { concern_level: "some", purpose_fit: "broader_than_needed", summary: " It reads pages. ",
                                trust_factors: ["Known publisher", 3, ""], concerns: ["Reads all pages"], recommendations: [],
                                model: "model-x", analyzed_at: "2026-11-16T12:00:00Z" }))
    assert_equal :current, ai.format
    assert ai.current?
    assert_equal [:caution, "Broader than its purpose needs"], ai.purpose_fit
    assert_equal [:caution, "Some concerns"], ai.concern_level
    assert_nil ai.earlier_level
    assert_equal ["It reads pages."], ai.summary
    assert_equal({ trust_factors: ["Known publisher"], concerns: ["Reads all pages"] }, ai.lists)
    assert_equal "model-x", ai.model
    assert_equal Time.utc(2026, 11, 16, 12), ai.analyzed_at
    assert ai.byline?

    { "fits" => :good, "does_not_fit" => :bad }.each do |fit, tone|
      assert_equal tone, check(ai_finding(ai: { purpose_fit: fit })).purpose_fit.first
    end
    { "none" => :good, "serious" => :bad }.each do |level, tone|
      assert_equal tone, check(ai_finding(ai: { "concern_level" => level })).concern_level.first, "string keys work too"
    end
  end

  test "unknown values in the current format are left out" do
    ai = check(ai_finding(ai: { concern_level: "excellent", purpose_fit: ["fits"], summary: { a: 1 }, concerns: "x",
                                model: 5, analyzed_at: "not a time" }))
    assert_nil ai.purpose_fit
    assert_nil ai.concern_level
    assert_equal [], ai.summary
    assert_equal({}, ai.lists)
    assert_nil ai.model
    assert_nil ai.analyzed_at
  end

  test "the earlier hash format keeps its text and reports its own level as history" do
    ai = check(ai_finding(ai: { risk_level: "low", summary: "Fine.", concerns: ["One"], model: "m" }))
    assert_equal :earlier, ai.format
    assert_not ai.current?
    assert_equal "Low", ai.earlier_level
    assert_nil ai.purpose_fit
    assert_nil ai.concern_level
    assert_equal ["Fine."], ai.summary
    assert_equal({ concerns: ["One"] }, ai.lists)
    assert ai.byline?

    assert_nil check(ai_finding(ai: { risk_level: "<b>bad</b>" })).earlier_level, "only a known level is repeated"
    assert_nil check(ai_finding(ai: { "risk_level" => nil, concern_level: "serious" })).concern_level,
               "a hash with risk_level is the earlier format, whatever else it has"
  end

  test "the earliest text format is parsed into a level, a summary and the lists" do
    description = "Risk Level: Medium\nFirst paragraph.\n\nSecond <b>one</b>.\nTrust Factors:\n- Known\n- Popular\n" \
                  "Concerns:\n- Reads pages\nRecommendations:\n- Be careful\nTrailing note."
    ai = check(ai_finding(description: description))
    assert_equal :earliest, ai.format
    assert_equal "Medium", ai.earlier_level
    assert_equal ["First paragraph.", "Second <b>one</b>.", "Trailing note."], ai.summary
    assert_equal({ trust_factors: %w[Known Popular], concerns: ["Reads pages"], recommendations: ["Be careful"] }, ai.lists)
    assert_not ai.byline?, "the earliest format kept no model or date"

    junk = check(ai_finding(description: { a: [1] }))
    assert_nil junk.earlier_level
    assert_equal ['{"a":[1]}'], junk.summary
    assert_equal({}, check(ai_finding(description: nil)).lists)
    assert_equal ["- stray item"], check(ai_finding(description: "- stray item")).summary, "an item before any heading stays text"
  end
end
