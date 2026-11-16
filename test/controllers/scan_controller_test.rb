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

  NAV_LABELS = ["[ new scan ]", "[ statistics ]", "[ github ]", "[ twitter ]", "[ help ]"].freeze

  def assert_shared_header(current: nil)
    assert_select "header nav[aria-label=Main]", count: 1 do
      assert_equal NAV_LABELS, css_select("header nav a").map { |a| a.text.strip }
      if current
        assert_select "a[aria-current=page]", count: 1, text: current
      else
        assert_select "a[aria-current]", count: 0
      end
    end
    assert_select "footer a[href='https://astarte.security/']", count: 1
  end

  test "every page uses the shared header and footer, marking the current page" do
    create_scan("c" * 32)

    get root_path
    assert_shared_header(current: "[ new scan ]")

    get stats_scan_index_path
    assert_shared_header(current: "[ statistics ]")
    assert_select "header a[href='/'] svg[aria-label=CRXaminer]", count: 1

    get scan_path("c" * 32)
    assert_shared_header

    get "/no-such-page"
    assert_response :not_found
    assert_shared_header
  end

  test "pages have a language, a description and their own title" do
    get root_path
    assert_select "html[lang=en]"
    assert_select "meta[name=description][content]"
    assert_select "title", text: "CRXaminer: Chrome extension security scanner"

    get stats_scan_index_path
    assert_select "title", text: "Statistics · CRXaminer"

    create_scan("d" * 32)
    get scan_path("d" * 32)
    assert_select "title", text: "Demo <b>Ext</b> · CRXaminer"
    assert_includes response.body, "<title>Demo &lt;b&gt;Ext&lt;/b&gt; · CRXaminer</title>"
  end

  test "the home page search box is set up for pasting IDs" do
    get root_path
    assert_select "input[name=id][autofocus][autocapitalize=off][autocorrect=off][spellcheck=false][aria-label]", count: 1
  end

  test "result tabs are a tablist wired to their panels" do
    create_scan("e" * 32)
    get scan_path("e" * 32), xhr: true

    assert_select "[role=tablist][aria-label]", count: 1 do
      assert_select "[role=tab]", count: 4
    end
    tabs = css_select("[role=tab]")
    assert_equal %w[analysis details manifest secure-annex], tabs.map { |t| t["aria-controls"] }
    assert_equal %w[true false false false], tabs.map { |t| t["aria-selected"] }
    assert_equal %w[0 -1 -1 -1], tabs.map { |t| t["tabindex"] }
    tabs.each do |tab|
      assert_select "##{tab['aria-controls']}[role=tabpanel][aria-labelledby=#{tab['id']}]", count: 1
    end
  end

  test "info popovers have a name and report whether they are open" do
    create_scan("e" * 32)
    get scan_path("e" * 32), xhr: true

    buttons = css_select("button[data-popover-target]")
    assert_equal 2, buttons.size
    buttons.each do |button|
      assert button["aria-label"].present?
      assert_equal "false", button["aria-expanded"]
      assert_equal button["data-popover-target"], button["aria-controls"]
      assert_select "##{button['aria-controls']}.hidden", count: 1
    end
  end

  test "a scan with no findings besides the overall risk says so" do
    create_scan("f" * 32)
    get scan_path("f" * 32), xhr: true

    assert_select "#no-findings", text: "No rule-based findings were raised for this extension."
  end

  test "a scan with findings does not show the empty message" do
    ScanResult.create!(extension_id: "g" * 32, extension_name: "G", manifest: MANIFEST, extension_details: {},
                       security_findings: [OVERALL, { severity: "High", title: "Broad access", description: "x" }])
    get scan_path("g" * 32), xhr: true

    assert_select "#no-findings", count: 0
    assert_select "#analysis div", text: "HIGH"
  end

  test "embedded URLs render one per cell, as plain text, with no empty column" do
    urls = (1..85).map { |i| "https://example#{i}.test/path?q=<b>#{i}</b>" }
    ScanResult.create!(extension_id: "h" * 32, extension_name: "H", manifest: MANIFEST.merge(embedded_urls: urls),
                       extension_details: {}, security_findings: [OVERALL])
    get scan_path("h" * 32), xhr: true

    items = css_select("#embedded-urls-list > li")
    assert_equal 80, items.size
    assert_equal urls.first(80), items.map { |li| li.text.strip }
    assert_select "#embedded-urls-list a", count: 0
    assert_select "#embedded-urls-container td", count: 0
    assert_includes response.body, "q=&lt;b&gt;1&lt;/b&gt;"
    assert_select "#next-page[type=button]", count: 1
  end

  test "an odd number of embedded URLs leaves no blank cell" do
    urls = %w[https://a.test https://b.test https://c.test]
    ScanResult.create!(extension_id: "i" * 32, extension_name: "I", manifest: MANIFEST.merge(embedded_urls: urls),
                       extension_details: {}, security_findings: [OVERALL])
    get scan_path("i" * 32), xhr: true

    assert_equal urls, css_select("#embedded-urls-list > li").map { |li| li.text.strip }
    assert_select "#next-page", count: 0
  end

  test "severity chips on the scan and stats pages use the shared palette" do
    create_scan("j" * 32)
    get scan_path("j" * 32), xhr: true
    assert_select "#analysis .bg-severity-medium.text-severity-medium-fg", text: /MEDIUM/

    get stats_scan_index_path
    assert_select "#recent-scans-tbody span.inline-block.bg-severity-medium", text: "MEDIUM"
    assert_not_includes response.body, "bg-violet"
    assert_not_includes response.body, "bg-purple"
  end
end
