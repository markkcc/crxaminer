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

  test "Low notes are one slim row that opens to the description" do
    create("mk" * 16, findings: [
      OVERALL,
      { severity: "Low", title: "Low-Risk Permission: storage", description: "Routine #{HOSTILE}.", rule: "p", evidence: [["permissions", 0]] },
      { severity: "Low", title: "Low-Risk Permission: cookies", description: "Cookie basics.", rule: "p", evidence: [["permissions", 2]] },
      { severity: "Critical", title: "All sites plus cookies", description: "Account takeover.", rule: "c",
        evidence: [["permissions", 2], ["host_permissions", 0]] },
      { severity: "Low", title: "Low without text", description: "", rule: "p", evidence: [["permissions", 1]] },
      { severity: "Medium", title: "Optional site", description: "Asked later.", rule: "o", evidence: [["optional_host_permissions", 0]] }
    ])

    # A line with only Low notes: a slim note, closed, title in the summary.
    storage = line_of('"storage",')
    assert_select "#manifest-code .ml[data-line='#{storage}'][data-sev=low]"
    assert_select "#manifest-note-#{storage}[data-slim]" do
      assert_select ".mn-item[data-slim] > details:not([open])", count: 1
      assert_select "summary .mn-sev[data-sev=low]", text: "Low"
      assert_select "summary .mn-title", text: "Low-Risk Permission: storage"
      assert_select "summary .mn-why[aria-hidden=true]", text: "Why?"
      assert_select "details > .mn-desc", text: "Routine #{HOSTILE}."
    end

    # Next to a higher note, the line keeps its card; the Low note inside stays slim.
    cookies = line_of('"cookies"')
    assert_select "#manifest-note-#{cookies}:not([data-slim])" do
      assert_equal ["All sites plus cookies", "Low-Risk Permission: cookies"], css_select("#manifest-note-#{cookies} .mn-title").map(&:text)
      assert_select ".mn-item:not([data-slim]) details", count: 0
      assert_select ".mn-item:not([data-slim]) > .mn-desc", text: "Account takeover."
      assert_select ".mn-item[data-slim] > details .mn-desc", text: "Cookie basics."
    end

    # A Low note with nothing to open is a plain row.
    tabs = line_of('"tabs",')
    assert_select "#manifest-note-#{tabs}[data-slim] .mn-item[data-slim] details", count: 0
    assert_select "#manifest-note-#{tabs} .mn-title", text: "Low without text"

    # Medium and higher keep the open card.
    site = line_of('"https://site1.test/*",')
    assert_select "#manifest-note-#{site}:not([data-slim]) .mn-item:not([data-slim]) > .mn-desc", text: "Asked later."

    assert_select "#manifest", text: /Low-risk notes are kept to one line; open one to see why\./
    assert_not_includes response.body, HOSTILE
    # The line text is still the plain file.
    text = css_select("#manifest-code .ml").map(&:text).join("\n")
    assert_equal JSON.pretty_generate(JSON.parse(text)), text
    assert_no_match(/Why\?|Routine|Low-Risk/, text)
  end

  test "without Low notes the intro does not mention them" do
    create("ml" * 16)
    assert_select "#manifest", text: /Low-risk notes/, count: 1 # "Optional history" is Low
    create("mm" * 16, findings: [OVERALL, { severity: "High", title: "Cookies", description: "x", rule: "p", evidence: [["permissions", 2]] }])
    assert_select "#manifest-code [data-slim]", count: 0
    assert_no_match(/Low-risk notes/, css_select("#manifest").text)
  end

  test "a finding on several lines shows its full note once and a slim row on the later lines" do
    create("mn" * 16, findings: [
      OVERALL,
      { severity: "High", title: "Everywhere #{HOSTILE}", description: "Why #{HOSTILE}.", rule: "w",
        evidence: [["host_permissions", 0], ["permissions", 1], ["permissions", 0]] },
      { severity: "Medium", title: "Tabs alone", description: "Tab text.", rule: "t", evidence: [["permissions", 1]] }
    ])
    storage, tabs, all = line_of('"storage",'), line_of('"tabs",'), line_of('"<all_urls>"')
    assert storage.to_i < tabs.to_i && tabs.to_i < all.to_i

    # First line: the open card, as before.
    assert_select "#manifest-note-#{storage}:not([data-slim]) .mn-item:not([data-slim])" do
      assert_select "details", count: 0
      assert_select ".mn-title", text: "Everywhere #{HOSTILE}"
      assert_select "> .mn-desc", text: "Why #{HOSTILE}."
    end

    # A later line where it is the only note: no card, a slim row pointing back.
    assert_select "#manifest-code .ml[data-line='#{all}'][data-sev=high]", count: 1
    assert_select "#manifest-note-#{all}[data-slim] .mn-item[data-slim] > details:not([open])" do
      assert_select "summary .mn-sev[data-sev=high]", text: "High"
      assert_select "summary .mn-title", text: "Everywhere #{HOSTILE}"
      assert_select "summary .mn-ref", text: "· explained at line #{storage}"
      assert_select ".mn-desc", text: "Why #{HOSTILE}."
      assert_select "button.mn-goto[type=button][data-goto-line='#{storage}']", text: "Go to line #{storage}"
    end

    # A later line with another finding's first note: the card stays, most severe first.
    assert_select "#manifest-note-#{tabs}:not([data-slim])" do
      assert_equal [["Everywhere #{HOSTILE}", true], ["Tabs alone", false]],
                   css_select("#manifest-note-#{tabs} .mn-item").map { |i| [i.at_css(".mn-title").text, i.key?("data-slim")] }
      assert_select ".mn-item[data-slim] .mn-ref", text: "· explained at line #{storage}"
      assert_select ".mn-item:not([data-slim]) > .mn-desc", text: "Tab text."
    end

    # One reference per finding, shared by all its notes and the Overview button.
    refs = css_select("#manifest-code .mn-item").group_by { |i| i.at_css(".mn-title").text }.transform_values { |is| is.map { |i| i["data-note-for"] }.uniq }
    assert_equal 1, refs["Everywhere #{HOSTILE}"].size
    assert_select "#manifest-summary", text: /3 lines have notes:\s+3 high\./
    assert_not_includes response.body, HOSTILE
    text = css_select("#manifest-code .ml").map(&:text).join("\n")
    assert_no_match(/explained|Go to line|Everywhere/, text)
  end

  test "no stored manifest keeps a clear empty state" do
    create("mj" * 16, raw: nil)
    assert_select "#manifest", text: /No manifest data available\./
    assert_select "#manifest-code, #manifest-copy, #manifest-summary", count: 0
  end
end
