require "test_helper"

# The Manifest tab: the pretty-printed file, notes under the lines that rule
# findings point at, and its empty states.
class ScanManifestTabTest < ActionDispatch::IntegrationTest
  OVERALL = { severity: "High", title: "Overall Risk: High", description: "Based on 4 total findings." }.freeze
  AI = { severity: "Info", title: "AI Context Analysis", description: "A verdict." }.freeze
  HOSTILE = %(<img src=x onerror=alert(1)>).freeze

  RAW = {
    "manifest_version" => 3,
    "name" => "<script>alert('raw')</script>",
    "permissions" => %w[storage tabs cookies],
    "optional_permissions" => %w[history],
    "host_permissions" => ["<all_urls>"],
    "web_accessible_resources" => (1..30).map { |i| "file#{i}.js" },
    "optional_host_permissions" => (1..25).map { |i| "https://site#{i}.test/*" }
  }.freeze

  EVIDENCE_FINDINGS = [
    OVERALL, AI,
    { severity: "Critical", title: "Reads cookies on every site", description: "Combination #{HOSTILE}.",
      rule: "combo", evidence: [["permissions", 2], ["host_permissions", 0]] },
    { severity: "High", title: "Cookies #{HOSTILE}", description: "Cookie text.", rule: "perm", evidence: [["permissions", 2]] },
    { severity: "Low", title: "Optional history", description: "Asked later.", rule: "optional", evidence: [["optional_permissions", 0]] },
    { severity: "Medium", title: "Optional site", description: "Asked later.", rule: "optional-host",
      evidence: [["optional_host_permissions", 21]] },
    { severity: "Low", title: "Not in this file", description: "x", rule: "gone", evidence: [["no_such_key"]] }
  ].freeze

  def create(id, raw: RAW, findings: EVIDENCE_FINDINGS)
    ScanResult.create!(extension_id: id, extension_name: "M", manifest: { manifest_version: 3, name: "M", version: "1", raw: raw },
                       extension_details: {}, security_findings: findings)
    get scan_path(id), xhr: true
    assert_response :success
  end

  def line_of(text)
    css_select("#manifest-code .ml").find { |l| l.text.strip == text }["data-line"]
  end

  def note_titles(line)
    css_select("#manifest-note-#{line} .mn-item .mn-title").map(&:text)
  end

  test "lines that findings point at carry notes with severity, title and description, most severe first" do
    create("ma" * 16)

    cookies = line_of('"cookies"')
    assert_select "#manifest-code .ml[data-line='#{cookies}'][data-sev=critical][aria-describedby='manifest-note-#{cookies}']"
    assert_equal ["Reads cookies on every site", "Cookies #{HOSTILE}"], note_titles(cookies)
    assert_equal %w[Critical High], css_select("#manifest-note-#{cookies} .mn-sev").map(&:text)
    assert_select "#manifest-note-#{cookies} .mn-desc", text: "Combination #{HOSTILE}."
    assert_select "#manifest-note-#{cookies} .sr-only", text: "Line #{cookies}:"

    # The combination finding is on both of its lines.
    assert_equal ["Reads cookies on every site"], note_titles(line_of('"<all_urls>"'))
    assert_equal ["Optional history"], note_titles(line_of('"history"'))

    # Neither the overall rating nor the AI verdict is ever a note.
    assert_select "#manifest-code .mn-title", text: /Overall Risk|AI Context/, count: 0

    assert_select "#manifest-summary[data-sticky]", text: /4 lines have notes:\s+2 critical,\s+1 medium,\s+1 low\./
    assert_select "#manifest-notes-toggle[aria-pressed=true]", text: "Show notes"
    assert_select "#manifest-prev", text: /Previous/
    assert_select "#manifest-next", text: /Next/
    assert_select "#manifest", text: /1 finding does not point at a line/
  end

  test "note text is escaped" do
    create("mb" * 16)
    body = response.body
    assert_not_includes body, HOSTILE
    assert_not_includes body, "<script>alert('raw')"
    assert_includes body, "Cookies &lt;img src=x onerror=alert(1)&gt;"
  end

  test "the line text, which Copy and Download use, is exactly the file without notes or numbers" do
    create("mc" * 16)
    text = css_select("#manifest-code .ml").map(&:text).join("\n")
    # The database may reorder keys, so compare the parsed file and its layout.
    assert_equal RAW, JSON.parse(text)
    assert_equal JSON.pretty_generate(JSON.parse(text)), text
    # Notes are rows of their own, never inside a line.
    assert_select "#manifest-code .ml .mn, #manifest-code .ml .mn-item", count: 0
    assert_select "#manifest-code .mv-rows > .mn", count: 4
  end

  test "a long array with a note starts open; one without starts folded" do
    create("md" * 16)
    toggles = css_select("#manifest-code [data-group-toggle]")
    assert_equal 2, toggles.size
    resources, hosts = toggles
    assert_equal "false", resources["aria-expanded"]
    assert_match(/\AShow 30 hidden entries \(lines \d+–\d+\)\z/, resources.text)
    assert_equal "true", hosts["aria-expanded"]
    assert_equal "Hide these 25 entries", hosts.text
    assert_match(/, 1 with notes\z/, hosts["data-closed-label"])

    site = line_of('"https://site22.test/*",')
    assert_select "#manifest-code .ml[data-line='#{site}']:not([hidden])"
    assert_select "#manifest-note-#{site}:not([hidden])"
    assert_equal 30, css_select("#manifest-code .ml[hidden]").size
  end

  test "Overview buttons name the finding the note belongs to" do
    create("me" * 16)
    button = css_select("#overview [data-finding]").find { |f| f.text.include?("Reads cookies on every site") }.at_css("button[data-manifest-lines]")
    lines = button["data-manifest-lines"].split
    assert_equal [line_of('"cookies"'), line_of('"<all_urls>"')].sort_by(&:to_i), lines
    ref = button["data-manifest-finding"]
    assert_match(/\A\d+\z/, ref)
    lines.each { |n| assert_select "#manifest-note-#{n} .mn-item[data-note-for='#{ref}'] .mn-title", text: "Reads cookies on every site" }
  end

  test "stored findings without evidence are placed by their titles" do
    create("mf" * 16, findings: [OVERALL, { severity: "High", title: "High-Risk Permission: tabs", description: "Tabs." }])
    assert_equal ["High-Risk Permission: tabs"], note_titles(line_of('"tabs",'))
  end

  test "a scan without rule findings says so instead of showing an empty summary" do
    create("mg" * 16, findings: [OVERALL, AI])
    assert_select "#manifest-no-notes", text: "No rule-based findings were raised for this extension, so no lines have notes."
    assert_select "#manifest-summary[data-sticky]", count: 0
    assert_select "#manifest-prev, #manifest-next, #manifest-notes-toggle, #manifest-code .mn", count: 0
    assert_select "#manifest-copy"
  end

  test "findings that point at no line say so" do
    create("mh" * 16, findings: [OVERALL, { severity: "Low", title: "Something new", description: "x" }])
    assert_select "#manifest-no-notes", text: /None of the findings point at a specific line/
    assert_select "#manifest-code .mn", count: 0
  end

  test "junk severities and findings render as escaped, unrated notes" do
    create("mi" * 16, findings: [
      { severity: "<b>High</b>", title: "High-Risk Permission: tabs", description: HOSTILE },
      { severity: nil, title: nil, description: nil, evidence: [["permissions", 0]] },
      { severity: "High", title: "x", description: "y", evidence: "not paths" }
    ])
    tabs = line_of('"tabs",')
    assert_select "#manifest-code .ml[data-line='#{tabs}'][data-sev=unrated]"
    assert_select "#manifest-note-#{tabs} .mn-sev[data-sev=unrated]", text: "<b>High</b>"
    assert_select "#manifest-note-#{line_of('"storage",')} .mn-item", text: /Unrated\s+Untitled finding/
    assert_not_includes response.body, HOSTILE
  end

  test "no stored manifest keeps a clear empty state" do
    create("mj" * 16, raw: nil)
    assert_select "#manifest", text: /No manifest data available\./
    assert_select "#manifest-code, #manifest-copy, #manifest-summary", count: 0
  end
end
