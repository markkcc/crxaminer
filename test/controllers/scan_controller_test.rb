require "test_helper"

class ScanControllerTest < ActionDispatch::IntegrationTest
  MANIFEST = { manifest_version: 3, name: "X", version: "1.0", permissions: ["tabs"], raw: { "name" => "X" } }.freeze
  OVERALL = { severity: "Medium", title: "Overall Risk: Medium", description: "Based on 1 total findings." }.freeze

  def create_scan(id, ai_finding = nil)
    ScanResult.create!(extension_id: id, extension_name: "Demo <b>Ext</b>", manifest: MANIFEST,
                       extension_details: { author: "Acme" },
                       security_findings: [OVERALL, ai_finding].compact)
  end

  def verdict_heading
    css_select("h2").map { |h| h.text.strip }.find { |t| ["Context-Aware Verdict", "Rule-based rating"].include?(t) }
  end

  test "without an AI analysis the card is titled Rule-based rating and says AI context is unavailable" do
    create_scan("f" * 32)
    get scan_path("f" * 32), xhr: true

    assert_response :success
    assert_equal "Rule-based rating", verdict_heading
    assert_includes response.body, "AI context is unavailable for this scan."
    assert_includes response.body, "MEDIUM"
    assert_not_includes response.body, "Claude-based AI analysis"
  end

  test "a structured AI analysis renders lists, model and time, all escaped" do
    finding = {
      severity: "Info", title: "AI Context Analysis",
      description: "Risk Level: High\n<script>alert(1)</script>",
      ai: { risk_level: "High", summary: "<script>alert(1)</script>", trust_factors: ["Known <i>publisher</i>"],
            concerns: ["Reads all pages"], recommendations: [], model: "claude-opus-5-5",
            prompt_version: AiContextAnalysis::PROMPT_VERSION, input_digest: "abc", analyzed_at: "2026-11-16T12:00:00Z" }
    }
    create_scan("a1" * 16, finding)
    get scan_path("a1" * 16), xhr: true

    assert_response :success
    assert_equal "Context-Aware Verdict", verdict_heading
    assert_includes response.body, "HIGH"
    assert_includes response.body, "Reads all pages"
    assert_includes response.body, "AI analysis by claude-opus-5-5 on 2026-11-16 12:00 UTC"
    assert_includes response.body, "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert_includes response.body, "Known &lt;i&gt;publisher&lt;/i&gt;"
    assert_not_includes response.body, "<script>alert(1)</script>"
    assert_not_includes response.body, "Recommendations"
  end

  test "a legacy text-only AI analysis still renders line by line" do
    finding = { severity: "Info", title: "AI Context Analysis",
                description: "Risk Level: Low\nLooks fine.\nConcerns:\n- <b>None</b>" }
    create_scan("b2" * 16, finding)
    get scan_path("b2" * 16), xhr: true

    assert_response :success
    assert_equal "Context-Aware Verdict", verdict_heading
    assert_includes response.body, "LOW"
    assert_includes response.body, "Looks fine."
    assert_includes response.body, "- &lt;b&gt;None&lt;/b&gt;"
  end

  test "the home page shows the dated upgrade notice" do
    get root_path

    assert_response :success
    assert_select "[role=status]", count: 1 do
      assert_select "time[datetime='2026-11-16']", text: "November 16, 2026"
    end
    notice = css_select("[role=status]").first.text.squish
    assert_includes notice, "We are pushing major experimental upgrades, which may affect the app's availability."
  end

  test "the upgrade notice is only on the home page" do
    create_scan("o" * 32)

    get scan_path("o" * 32)
    assert_response :success
    assert_select "[role=status]", count: 0

    get stats_scan_index_path
    assert_response :success
    assert_select "[role=status]", count: 0
  end
end
