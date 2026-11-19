require "test_helper"

class HelpControllerTest < ActionDispatch::IntegrationTest
  WRITE_UP = "https://astarte.security/docs/tools/crxaminer".freeze

  test "the help page explains the scan and the two ratings, and ends with the write-up link" do
    get help_path

    assert_response :success
    assert_select "title", text: /How it works/
    assert_select "h1", count: 1, text: "How CRXaminer works"
    assert_equal ["What a scan does", "Reading the result", "Access: what it could do", "Trust: who stands behind it", "How they combine"],
                 css_select("article h2").map { |h| h.text.strip }
    assert_select "article ol li", count: 4
    assert_select "#help-ai-check", text: "The AI check can lower trust, never raise it, and it never changes access."

    links = css_select("article a")
    assert_equal WRITE_UP, links.last["href"], "the write-up link comes last"
    assert_equal "_blank", links.last["target"]
    assert_includes links.last["rel"].to_s, "noopener"
  end

  test "the access tiers come from the rule engine's data, named as tiers" do
    get help_path

    data = ExtensionAnalyzerData
    assert_equal ScanRating::ACCESS_TIERS.map(&:key), css_select("#access-tiers [data-tier]").map { |row| row["data-tier"] }
    assert_equal data::OVERALL_LEVELS, css_select("#access-tiers [data-tier]").map { |row| row["data-level"] }

    ScanRating::ACCESS_TIERS.each do |tier|
      row = css_select("#access-tiers [data-tier='#{tier.key}']").first
      assert_equal tier.name, row.at_css("dt [data-badge=access]").text.strip
      assert_includes row.at_css("dt [data-badge=access]")["class"], "bg-severity-#{tier.level.downcase}"
      assert_equal tier.summary, row.at_css("[data-summary]").text.strip
      next if tier.level == "Minimal"

      rules = data.rules.select { |rule| rule.severity == tier.level && !rule.id.start_with?("optional.") }
      assert rules.any? || data.permissions_by_level[tier.level].any?, "#{tier.name} has something to show"
      rules.each do |rule|
        assert_includes row.text, rule.name
        assert_includes row.text, rule.summary
      end
      data.permissions_by_level[tier.level].each { |name| assert_includes row.css("[data-permissions]").text, name }
    end
    assert_select "#access-tiers [data-tier=full_control] details", count: 0, message: "a short list is shown, not folded"
    assert_select "#access-tiers [data-tier=routine] details summary", text: /\d+ routine permissions/

    full = css_select("#access-tiers [data-tier=full_control]").first.text
    assert_includes full, "debugger"
    assert_includes full, "All sites plus cookies"
    assert_no_match(/optional/i, css_select("#access-tiers").text, "optional items are covered by one sentence below the list")
    assert_includes css_select("article").text, "Optional permissions are rated one tier lower"
  end

  test "the trust levels come from the rating model, with the thresholds it uses" do
    get help_path

    assert_equal ScanRating::TRUST_LEVELS.map(&:key), css_select("#trust-levels [data-trust]").map { |row| row["data-trust"] }
    ScanRating::TRUST_LEVELS.each do |level|
      row = css_select("#trust-levels [data-trust='#{level.key}']").first
      assert_equal level.name, row.at_css("[data-badge=trust][data-level='#{level.key}']").text.strip
      assert_equal level.summary, row.at_css("[data-summary]").text.strip
      assert row.at_css("[data-evidence]").text.strip.present?
    end
    established = css_select("#trust-levels [data-trust=established] [data-evidence]").text
    assert_includes established, "100,000 users"
    assert_includes established, "1,000,000 users and 1,000 ratings"
    assert_includes css_select("#trust-levels [data-trust=some] [data-evidence]").text, "10,000 users and 50 ratings"
  end

  test "the combination grid is drawn from ScanRating::OVERALL" do
    get help_path

    assert_equal ScanRating::TRUST_LEVELS.map(&:name), css_select("#rating-grid thead [data-badge=trust]").map { |b| b.text.strip }
    rows = css_select("#rating-grid tbody tr")
    assert_equal ScanRating::ACCESS_TIERS.map(&:key), rows.map { |r| r["data-tier"] }
    rows.each do |row|
      cells = row.css("td[data-overall]")
      assert_equal ScanRating::OVERALL.fetch(row["data-tier"]), cells.map(&:text)
      cells.each { |cell| assert_includes cell["class"], "bg-severity-#{cell.text.downcase}" }
    end
  end

  test "the help page is as wide as the statistics and scan pages" do
    get stats_scan_index_path
    assert_select "div.max-w-7xl", count: 1

    get help_path
    assert_select "#help-page.max-w-7xl", count: 1
    assert_select "#help-page article #help-columns > section", count: 2, message: "the two short sections sit side by side"
    assert_select "#access-tiers.lg\\:columns-2 > .break-inside-avoid", count: ScanRating::ACCESS_TIERS.size,
                  message: "the tiers flow into two columns and are never split"
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
