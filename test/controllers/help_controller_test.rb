require "test_helper"

class HelpControllerTest < ActionDispatch::IntegrationTest
  WRITE_UP = "https://astarte.security/docs/tools/crxaminer".freeze

  test "the help page explains the scan and the rules, and ends with the write-up link" do
    get help_path

    assert_response :success
    assert_select "title", text: /How it works/
    assert_select "h1", count: 1, text: "How CRXaminer works"
    assert_equal ["What a scan does", "The rule engine", "Reading the result"], css_select("article h2").map { |h| h.text.strip }
    assert_select "article ol li", count: 4

    links = css_select("article a")
    assert_equal WRITE_UP, links.last["href"], "the write-up link comes last"
    assert_equal "_blank", links.last["target"]
    assert_includes links.last["rel"].to_s, "noopener"
  end

  test "the rating levels come from the rule engine's data" do
    get help_path

    data = ExtensionAnalyzerData
    assert_equal data::OVERALL_LEVELS, css_select("#rating-levels [data-level]").map { |row| row["data-level"] }

    data::LEVELS.each do |level|
      row = css_select("#rating-levels [data-level='#{level}']").first
      rules = data.rules.select { |rule| rule.severity == level && !rule.id.start_with?("optional.") }
      assert rules.any? || data.permissions_by_level[level].any?, "#{level} has something to show"
      rules.each do |rule|
        assert_includes row.text, rule.name
        assert_includes row.text, rule.summary
      end
      data.permissions_by_level[level].each { |name| assert_includes row.css("[data-permissions]").text, name }
    end
    assert_select "#rating-levels [data-level='Critical'] details", count: 0, message: "a short list is shown, not folded"
    assert_select "#rating-levels [data-level='Low'] details summary", text: /\d+ routine permissions/

    critical = css_select("#rating-levels [data-level='Critical']").first.text
    assert_includes critical, "debugger"
    assert_includes critical, "All sites plus cookies"
    assert_no_match(/optional/i, css_select("#rating-levels").text, "optional items are covered by one sentence below the table")
    assert_includes css_select("article").text, "Optional permissions are rated one level lower"
  end

  test "the help link in the navigation opens the help page and is marked current there" do
    get root_path
    assert_select "header nav a[href='#{help_path}']", count: 1, text: "[ help ]"
    assert_select "header nav a[href='#{help_path}'][target]", count: 0, message: "it is a page of this site, opened in the same tab"
    assert_select "header nav a[href='#{WRITE_UP}']", count: 0

    get help_path
    assert_select "header nav a[aria-current=page]", count: 1, text: "[ help ]"
    assert_select "header a[href='/'] svg[aria-label=CRXaminer]", count: 1
    assert_select "footer a", count: 2
  end
end
