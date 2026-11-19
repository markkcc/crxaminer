require "test_helper"

# The AI check's lists (trust factors, concerns, recommendations): one column
# per list that has items, each with its tone and icon, and rules between
# columns only (the grid's dividers), so a missing list leaves no gap.
class ScanAiListsTest < ActionDispatch::IntegrationTest
  MANIFEST = { manifest_version: 3, name: "X", version: "1.0", permissions: [], raw: { "name" => "X" } }.freeze
  OVERALL = { severity: "Low", title: "Overall Risk: Low", description: "Based on 1 total findings." }.freeze
  HOSTILE = %("><img src=x onerror=alert(1)><script>alert(1)</script>).freeze

  def show_ai(id, current: true, **lists)
    ai = { summary: "Summary.", model: "model-x", analyzed_at: "2026-11-16T12:00:00Z" }.merge(lists)
    ai = current ? ai.merge(concern_level: "some", purpose_fit: "fits") : ai.merge(risk_level: "Low")
    finding = { severity: "Info", title: "AI Context Analysis", description: "", ai: ai }
    ScanResult.create!(extension_id: id, extension_name: "Lists", manifest: MANIFEST,
                       extension_details: {}, security_findings: [OVERALL, finding])
    get scan_path(id), xhr: true
    assert_response :success
  end

  def columns
    css_select("#ai-check .ai-lists > [data-ai-list]")
  end

  test "three lists sit in three columns with a rule between each, each with its tone, icon and heading" do
    show_ai("la" * 16, trust_factors: ["Known publisher"], concerns: ["Reads pages", "Sends data"], recommendations: ["Update it"])

    assert_select "#ai-check .ai-lists[data-ai-lists='3']", count: 1
    grid = css_select("#ai-check .ai-lists").first
    classes = grid["class"].split
    assert_includes classes, "md:grid-cols-3"
    assert_includes classes, "md:divide-x"
    assert_includes classes, "divide-y"
    assert_includes classes, "md:divide-y-0"

    assert_equal %w[trust_factors concerns recommendations], columns.map { |c| c["data-ai-list"] }
    assert_equal %w[good caution brand], columns.map { |c| c["data-tone"] }
    assert_equal ["Trust factors", "Concerns", "Recommendations"], columns.map { |c| c.at_css("h3").text.squish }
    columns.each do |column|
      heading = column.at_css("h3")
      assert_equal heading["id"], column["aria-labelledby"]
      assert_equal "true", column.at_css(".ai-list-icon")["aria-hidden"]
      assert column.at_css(".ai-list-icon svg"), "an icon"
    end
    assert_equal ["Reads pages", "Sends data"], css_select("[data-ai-list=concerns] li").map(&:text)

    # The chips, summary and model line are unchanged.
    assert_equal ["Fits its stated purpose", "Some concerns"], css_select("#ai-check [data-badge=signal]").map { |b| b.text.squish }
    assert_select "#ai-check p", text: "Summary."
    assert_select "#ai-byline", text: "AI analysis by model-x on 2026-11-16 12:00 UTC"
  end

  test "two lists take two columns, with one rule and no empty column" do
    show_ai("lb" * 16, trust_factors: ["Known publisher"], concerns: [], recommendations: ["Update it"])

    grid = css_select("#ai-check .ai-lists").first
    assert_equal "2", grid["data-ai-lists"]
    assert_includes grid["class"].split, "md:grid-cols-2"
    assert_not_includes grid["class"].split, "md:grid-cols-3"
    assert_equal %w[trust_factors recommendations], columns.map { |c| c["data-ai-list"] }
    assert_select "[data-ai-list=concerns]", count: 0
  end

  test "one list takes the whole width with no column classes" do
    show_ai("lc" * 16, concerns: ["Reads pages"])

    grid = css_select("#ai-check .ai-lists").first
    assert_equal "1", grid["data-ai-lists"]
    assert_empty grid["class"].split.grep(/grid-cols-[23]/)
    assert_equal %w[concerns], columns.map { |c| c["data-ai-list"] }
    assert_equal "caution", columns.first["data-tone"]
  end

  test "no lists leaves no list grid" do
    show_ai("ld" * 16, trust_factors: [], concerns: [], recommendations: [])
    assert_select "#ai-check", count: 1
    assert_select "#ai-check .ai-lists", count: 0
  end

  test "the earlier format, folded away, gets the same columns, and list items are escaped" do
    show_ai("le" * 16, trust_factors: [HOSTILE], concerns: ["Old concern"], current: false)

    assert_select "#ai-check[data-format=earlier] details#ai-earlier-text .ai-lists[data-ai-lists='2']", count: 1
    assert_equal %w[good caution], columns.map { |c| c["data-tone"] }
    assert_equal [HOSTILE], css_select("[data-ai-list=trust_factors] li").map(&:text)
    assert_not_includes response.body, "<img src=x"
    assert_not_includes response.body, "<script>alert(1)"
  end
end
