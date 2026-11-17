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

  test "result tabs are a sticky tablist wired to their panels, with counts and old-hash aliases" do
    create_scan("e" * 32)
    get scan_path("e" * 32), xhr: true

    assert_select ".sticky [role=tablist][aria-label]", count: 1 do
      assert_select "[role=tab]", count: 5
    end
    tabs = css_select("[role=tab]")
    assert_equal %w[overview permissions network manifest secure-annex], tabs.map { |t| t["aria-controls"] }
    assert_equal %w[true false false false false], tabs.map { |t| t["aria-selected"] }
    assert_equal %w[0 -1 -1 -1 -1], tabs.map { |t| t["tabindex"] }
    tabs.each do |tab|
      assert_select "##{tab['aria-controls']}[role=tabpanel][aria-labelledby=#{tab['id']}][tabindex='0']", count: 1
    end
    # Panels take focus when opened from a link with a hash: same ring as other controls, no browser outline.
    css_select("[role=tabpanel]").each do |panel|
      assert_includes panel["class"].split, "focus:outline-none"
      assert_includes panel["class"].split, "focus-visible:ring-2"
    end
    # Counts on Permissions (one API permission) and Network (no URLs).
    assert_equal ["1", "0"], css_select("[data-tab-count]").map { |c| c.text.strip }
    assert_equal({ "analysis" => "overview", "details" => "permissions" }, JSON.parse(css_select("#scan-tabs").first["data-aliases"]))
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
    assert_select "#overview [data-area=other] [data-finding] div", text: "HIGH"
  end

  test "embedded URLs are in the page once, escaped, as text and never as links" do
    urls = (1..85).map { |i| "https://example#{i}.test/path?q=<b>#{i}</b>" } + ["http://a.test/\" onmouseover=\"x"]
    ScanResult.create!(extension_id: "h" * 32, extension_name: "H", manifest: MANIFEST.merge(embedded_urls: urls),
                       extension_details: {}, security_findings: [OVERALL])
    get scan_path("h" * 32), xhr: true

    list = css_select("#network-domains").first
    encoded = list["data-domains"]
    urls.each { |url| assert_equal 1, encoded.scan(url).size, url }
    assert_equal 1, response.body.scan("example1.test/path").size
    assert_includes response.body, "q=&lt;b&gt;1&lt;/b&gt;"
    assert_not_includes response.body, "<b>1</b>"
    assert_not_includes response.body, '" onmouseover="x'
    # Rows are built by the script for the rows on screen, so none are in the HTML.
    assert_empty list.children.select(&:element?)
    assert_select "a[href*='example1.test']", count: 0
    assert_select "[role=tab]#network-tab [data-tab-count]", text: "86"
  end

  test "the Network tab has a labelled search, a category filter and the built-in list note" do
    urls = %w[https://www.w3.org/1999/xhtml https://cdn.jsdelivr.net/x http://localhost:3000/ https://bit.ly/a]
    ScanResult.create!(extension_id: "k" * 32, extension_name: "K", manifest: MANIFEST.merge(embedded_urls: urls),
                       extension_details: {}, security_findings: [OVERALL])
    get scan_path("k" * 32), xhr: true

    assert_select "label[for=network-search]", count: 1
    assert_select "input#network-search[type=search]", count: 1
    assert_select "label[for=network-category]", count: 1
    options = css_select("#network-category option").map { |o| o.text.strip }
    assert_equal ["All categories (4)", "Reference (1)", "CDN (1)", "Link shortener (1)", "Local (1)"], options
    assert_includes response.body, "Categories come from a short built-in list"
    assert_select "[data-network-summary]", text: /4 URLs across\s+4 domains/
    assert_select "[data-network-summary] a[href='#network']", count: 1
  end

  test "a scan without URLs says so on both tabs" do
    create_scan("i" * 32)
    get scan_path("i" * 32), xhr: true

    assert_select "#network-empty", text: "No URLs were found in the extension's files."
    assert_select "#network-domains", count: 0
    assert_select "[data-network-summary]", text: /No URLs were found/
  end

  test "the scan page scripts do not log to the console" do
    create_scan("l" * 32)
    get scan_path("l" * 32)

    assert_response :success
    assert_not_includes response.body, "console.log"
    assert_select "script[src*=scan_page]", count: 1
    assert_not_includes Rails.root.join("app/javascript/scan_page.js").read, "console.log"
  end

  test "stats severity filters are toggle buttons and scan dates say UTC" do
    create_scan("m" * 32)
    get stats_scan_index_path

    assert_select "[role=group] button.severity-filter-btn[type=button][aria-pressed=false]", count: 5
    assert_select "div.severity-filter-btn", count: 0
    assert_select "#recent-scans-tbody time[datetime]", text: /\A\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\z/
  end

  test "severity chips on the scan and stats pages use the shared palette" do
    create_scan("j" * 32)
    get scan_path("j" * 32), xhr: true
    assert_select "#overview .bg-severity-medium.text-severity-medium-fg", text: /MEDIUM/

    get stats_scan_index_path
    assert_select "#recent-scans-tbody span.inline-block.bg-severity-medium", text: "MEDIUM"
    assert_not_includes response.body, "bg-violet"
    assert_not_includes response.body, "bg-purple"
  end
  RICH_MANIFEST = {
    manifest_version: 3, name: "R", version: "2.0",
    permissions: %w[tabs storage notifications activeTab action],
    optional_permissions: ["bookmarks"],
    host_permissions: ["https://start.me/"],
    content_security_policy: ["extension_pages: script-src 'self' 'wasm-unsafe-eval'"],
    raw: { manifest_version: 3, name: "R", permissions: %w[tabs storage notifications activeTab action],
           optional_permissions: ["bookmarks"], optional_host_permissions: ["https://later.test/*"],
           host_permissions: ["https://start.me/"],
           content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'" },
           web_accessible_resources: (1..30).map { |i| "file#{i}.js" } }
  }.freeze

  RICH_FINDINGS = [
    OVERALL,
    { severity: "High", title: "High-Risk Permission: tabs", description: "Tabs text." },
    { severity: "Medium", title: "Medium-Risk Permission: storage", description: "Storage text." },
    { severity: "Medium", title: "Medium-Risk Permission: notifications", description: "Notifications text." },
    { severity: "Medium", title: "Medium-Risk Permission: activeTab", description: "ActiveTab text." },
    { severity: "High", title: "Unsafe WebAssembly Execution", description: "Wasm text." }
  ].freeze

  def create_rich_scan(id)
    ScanResult.create!(extension_id: id, extension_name: "Rich", manifest: RICH_MANIFEST,
                       extension_details: {}, security_findings: RICH_FINDINGS)
  end

  test "the Overview groups findings by area and folds routine permissions" do
    create_rich_scan("p" * 32)
    get scan_path("p" * 32), xhr: true

    areas = css_select("#overview section[data-area]").map { |a| a["data-area"] }
    assert_equal %w[site_access browser code_policy network], areas
    assert_select "#overview [data-area=site_access]", text: /Nothing found in this area\./
    assert_select "#overview [data-area=browser] > ul [data-finding]", count: 1
    assert_select "#overview [data-area=browser] details[data-routine] summary",
                  text: /\A▸\s+3 routine permissions: activeTab · notifications · storage\z/
    # Folded findings keep their stored severity and text.
    assert_select "#overview details[data-routine] [data-finding]", count: 3
    assert_select "#overview details[data-routine] .bg-severity-medium", text: "MEDIUM", count: 3
    assert_select "#overview details[data-routine]", text: /Storage text\./
  end

  test "each finding offers a jump to the manifest lines that produced it" do
    create_rich_scan("q" * 32)
    get scan_path("q" * 32), xhr: true

    tabs_button = css_select("[data-finding]").find { |f| f.text.include?("High-Risk Permission: tabs") }.at_css("button[data-manifest-lines]")
    line = tabs_button["data-manifest-lines"]
    assert_match(/\AShow line #{line} in the manifest\z/, tabs_button.text.squish)
    assert_select "#manifest-line-#{line}.manifest-flagged code", text: '"tabs",'
    assert_select "#manifest-line-#{line} .sr-only", text: /flagged by: High-Risk Permission: tabs/

    wasm = css_select("[data-finding]").find { |f| f.text.include?("Unsafe WebAssembly") }.at_css("button[data-manifest-lines]")
    assert_select "#manifest-line-#{wasm['data-manifest-lines']} code", text: /"extension_pages":/
  end

  test "the Manifest tab has tools, line numbers and folded long arrays" do
    create_rich_scan("r" * 32)
    get scan_path("r" * 32), xhr: true

    assert_select "#manifest-copy[type=button]", text: "Copy"
    assert_select "#manifest-download[type=button]", text: "Download manifest.json"
    assert_select "#manifest-wrap[type=button][aria-pressed=false]", text: "Wrap lines"
    lines = css_select("#manifest-code .manifest-line")
    assert_equal JSON.pretty_generate(RICH_MANIFEST[:raw]).lines.size, lines.size
    assert_equal (1..lines.size).map(&:to_s), lines.map { |l| l["data-line"] }
    # The 30-entry array is folded behind one button; its brackets stay visible.
    assert_select "#manifest-code [data-group-toggle][aria-expanded=false]", count: 1, text: /Show 30 hidden entries/
    assert_equal 30, lines.count { |l| l["hidden"] }
  end

  test "the Permissions tab explains site access and tables the API permissions" do
    create_rich_scan("s" * 32)
    get scan_path("s" * 32), xhr: true

    assert_select "#site-access-summary[data-kind=named]", text: "1 named site"
    assert_select "#permissions ul[aria-label='Named sites'] li", text: "start.me"
    assert_select "#permissions", text: /It can also use the current tab after you click the extension/
    assert_select "#permissions", text: %r{https://later\.test/\*}

    assert_select "#permissions-required-table thead th[scope=col]", count: 4
    # Below sm the description and docs stack under the name, and their columns hide.
    assert_select "#permissions-required-table thead th.hidden.sm\\:table-cell", count: 2
    rows = css_select("#permissions-required-table tbody tr")
    assert_equal %w[tabs storage notifications activeTab action], rows.map { |r| r.at_css("th[scope=row] > span.font-mono").text.strip }
    tabs = rows.first
    assert_equal "High", tabs.at_css("td:nth-of-type(2) span").text.strip
    assert_equal ["https://developer.chrome.com/docs/extensions/reference/api/tabs"], tabs.css("a").map { |a| a["href"] }.uniq
    assert_equal "noopener noreferrer", tabs.at_css("a")["rel"]
    action = rows.last
    assert_includes action.text, "No description in CRXaminer's list"
    assert_includes action.text, "not flagged"
    assert_nil action.at_css("a")

    assert_select "#permissions-optional-table tbody th > span.font-mono", text: "bookmarks"
    assert_select "#csp-list li", text: "extension_pages: script-src 'self' 'wasm-unsafe-eval'"
    assert_select "[data-tab-count]", text: "6", count: 1
  end

  test "junk stored data renders escaped with status 200" do
    manifest = {
      manifest_version: "<b>2</b>",
      name: "<script>alert('name')</script>",
      permissions: ["<script>alert('perm')</script>", 7, nil, { "x" => "<i>y</i>" }, ["nested"]],
      optional_permissions: "not a list",
      host_permissions: nil,
      content_scripts: [nil, 5, { "matches" => "<all_urls>" }, { matches: [nil, "<script>m</script>"] }],
      embedded_urls: ["<script>alert('url')</script>", "javascript:alert(1)", "https://exa mple.com/", "http://[::1",
                      42, nil, "https://ok.test/?a=<img src=x onerror=alert(1)>"],
      content_security_policy: "not a list",
      raw: { "name" => "<script>alert('raw')</script>", "permissions" => ["<img src=x onerror=alert(1)>"], "deep" => [[[]]] }
    }
    ScanResult.create!(extension_id: "t" * 32, extension_name: "<script>alert('ext')</script>", manifest: manifest,
                       extension_details: { size: nil }, security_findings: [
                         { severity: "<b>High</b>", title: "High-Risk Permission: <script>alert('t')</script>", description: "<img src=x onerror=alert(1)>" },
                         { severity: nil, title: nil, description: nil }
                       ])

    [true, false].each do |xhr|
      get scan_path("t" * 32), xhr: xhr
      assert_response :success
      body = response.body
      assert_not_includes body, "<script>alert("
      assert_not_includes body, "<img src=x"
      assert_not_includes body, "<i>y</i>"
      assert_includes body, "&lt;script&gt;alert(&#39;perm&#39;)&lt;/script&gt;"
      assert_includes body, "&lt;img src=x onerror=alert(1)&gt;"
    end
    assert_select "#permissions-required-table tbody tr", count: 4
    assert_select "#overview [data-finding]", text: /Untitled finding/
  end

  test "a scan with no manifest key at all still renders" do
    ScanResult.create!(extension_id: "u" * 32, extension_name: "U", manifest: { version: "1" }, extension_details: nil, security_findings: nil)
    get scan_path("u" * 32)
    assert_response :success
    assert_select "#site-access-summary", text: "No website access"
    assert_select "#manifest", text: /No manifest data available\./
  end
end
