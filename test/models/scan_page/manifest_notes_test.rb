require "test_helper"

class ScanPage::ManifestNotesTest < ActiveSupport::TestCase
  RAW = {
    "manifest_version" => 3,
    "name" => "N",
    "permissions" => %w[storage tabs webRequest cookies],
    "optional_permissions" => %w[history bookmarks downloads],
    "host_permissions" => ["<all_urls>"],
    "optional_host_permissions" => ["https://*/*"],
    "content_scripts" => [{ "matches" => ["https://a.test/*"] }, { "matches" => ["<all_urls>", "https://b.test/*"] }],
    "content_security_policy" => { "extension_pages" => "script-src 'self' 'wasm-unsafe-eval'" }
  }.freeze

  def notes_for(findings, raw = RAW)
    groups = ScanPage::FindingGroups.new(findings)
    [ScanPage::ManifestNotes.new(ScanPage::ManifestDocument.new(raw), groups.findings), groups.findings]
  end

  def text_at(notes_doc, line)
    notes_doc.lines[line - 1].text.strip
  end

  def doc
    @doc ||= ScanPage::ManifestDocument.new(RAW)
  end

  test "findings with evidence point at each path's line" do
    notes, findings = notes_for([
      { severity: "Critical", title: "Reads every site's cookies", description: "Combo.", rule: "combo-cookies",
        evidence: [["permissions", 3], ["host_permissions", 0]] },
      { severity: "Low", title: "Optional history", description: "Later.", rule: "optional", evidence: [["optional_permissions", 0]] },
      { severity: "Medium", title: "Optional hosts", description: "Later.", rule: "optional-hosts", evidence: [["optional_host_permissions", 0]] },
      { severity: "High", title: "Content script everywhere", description: "x", rule: "cs",
        evidence: [["content_scripts", 1, "matches", 0]] },
      { severity: "High", title: "Wasm", description: "x", rule: "csp", evidence: [["content_security_policy", "extension_pages"]] }
    ])
    by_title = findings.index_by(&:title)
    assert_equal ['"cookies"', '"<all_urls>"'], notes.lines_for(by_title["Reads every site's cookies"]).map { |n| text_at(doc, n) }
    assert_equal ['"history",'], notes.lines_for(by_title["Optional history"]).map { |n| text_at(doc, n) }
    assert_equal ['"https://*/*"'], notes.lines_for(by_title["Optional hosts"]).map { |n| text_at(doc, n) }
    assert_equal ['"<all_urls>",'], notes.lines_for(by_title["Content script everywhere"]).map { |n| text_at(doc, n) }
    assert_match(/"extension_pages":/, text_at(doc, notes.lines_for(by_title["Wasm"]).first))
  end

  test "evidence wins over the title, even a title the legacy lookup knows" do
    notes, findings = notes_for([
      { severity: "High", title: "High-Risk Permission: tabs", description: "x", rule: "perm", evidence: [["permissions", 0]] }
    ])
    assert_equal ['"storage",'], notes.lines_for(findings.first).map { |n| text_at(doc, n) }
  end

  test "unresolvable paths fall back to the nearest parent, then to the title" do
    notes, findings = notes_for([
      { severity: "High", title: "Gone entry", description: "x", rule: "r", evidence: [["permissions", 40]] },
      { severity: "High", title: "Deep miss", description: "x", rule: "r", evidence: [["content_scripts", 1, "matches", 9, "x"]] },
      { severity: "High", title: "High-Risk Permission: tabs", description: "x", rule: "r", evidence: [["no_such_key", 0]] },
      { severity: "High", title: "Nothing at all", description: "x", rule: "r", evidence: [["no_such_key"]] }
    ])
    by_title = findings.index_by(&:title)
    assert_equal ['"permissions": ['], notes.lines_for(by_title["Gone entry"]).map { |n| text_at(doc, n) }
    assert_equal ['"matches": ['], notes.lines_for(by_title["Deep miss"]).map { |n| text_at(doc, n) }.uniq
    assert_equal ['"tabs",'], notes.lines_for(by_title["High-Risk Permission: tabs"]).map { |n| text_at(doc, n) }
    assert_equal [], notes.lines_for(by_title["Nothing at all"])
    assert_equal 1, notes.unplaced_count
  end

  test "findings without evidence use the legacy title lookup" do
    notes, findings = notes_for([
      { severity: "High", title: "High-Risk Permission: tabs", description: "x" },
      { severity: "High", title: "Dangerous Permission Combination: webRequest + cookies", description: "x" },
      { severity: "Medium", title: "Broad Host Permissions", description: "x" },
      { severity: "Low", title: "A title nobody knows", description: "x" }
    ])
    by_title = findings.index_by(&:title)
    assert_equal ['"tabs",'], notes.lines_for(by_title["High-Risk Permission: tabs"]).map { |n| text_at(doc, n) }
    assert_equal ['"webRequest",', '"cookies"'],
                 notes.lines_for(by_title["Dangerous Permission Combination: webRequest + cookies"]).map { |n| text_at(doc, n) }
    assert_equal ['"<all_urls>"'], notes.lines_for(by_title["Broad Host Permissions"]).map { |n| text_at(doc, n) }
    assert_equal [], notes.lines_for(by_title["A title nobody knows"])
  end

  test "a line with several findings lists them most severe first; a finding with several lines is on each" do
    notes, = notes_for([
      { severity: "Low", title: "Low one", description: "x", rule: "a", evidence: [["permissions", 1]] },
      { severity: "Critical", title: "Combo", description: "x", rule: "b", evidence: [["permissions", 1], ["permissions", 2], ["permissions", 1]] },
      { severity: "Medium", title: "Medium one", description: "x", rule: "c", evidence: [["permissions", 1]] },
      { severity: "High", title: "High-Risk Permission: webRequest", description: "x" }
    ])
    tabs = doc.resolve(["permissions", 1])
    web = doc.resolve(["permissions", 2])
    assert_equal %w[Combo Medium\ one Low\ one], notes.notes_for(tabs).map { |n| n.finding.title }
    assert_equal %w[critical medium low], notes.notes_for(tabs).map(&:severity)
    assert_equal ["Combo", "High-Risk Permission: webRequest"], notes.notes_for(web).map { |n| n.finding.title }
    assert_equal "critical", notes.severity_of(tabs)
    assert_equal [tabs, web], notes.lines
    assert_equal [["critical", 2]], notes.line_counts
    # Each note knows its finding's position, shared with the Overview button.
    combo = notes.notes_for(tabs).first
    assert_equal combo.ref, notes.notes_for(web).first.ref
    assert_equal combo.ref, notes.ref_for(combo.finding)
  end

  test "identical findings each keep their own reference" do
    same = { severity: "High", title: "Same", description: "x", rule: "r", evidence: [["permissions", 0]] }
    notes, findings = notes_for([same, same.dup])
    assert_equal [0, 1], findings.map { |f| notes.ref_for(f) }
    assert_equal 2, notes.notes_for(doc.resolve(["permissions", 0])).size
  end

  test "Low, Minimal and Info notes are quiet; a line is slim only when all its notes are" do
    notes, = notes_for([
      { severity: "Low", title: "Low storage", description: "x", rule: "a", evidence: [["permissions", 0]] },
      { severity: "Minimal", title: "Minimal tabs", description: "x", rule: "b", evidence: [["permissions", 1]] },
      { severity: "Info", title: "Info tabs", description: "x", rule: "c", evidence: [["permissions", 1]] },
      { severity: "Low", title: "Low cookies", description: "x", rule: "d", evidence: [["permissions", 3]] },
      { severity: "Critical", title: "Critical cookies", description: "x", rule: "e", evidence: [["permissions", 3]] },
      { severity: "<b>?</b>", title: "Unrated webRequest", description: "x", rule: "f", evidence: [["permissions", 2]] }
    ])
    storage, tabs, web, cookies = [0, 1, 2, 3].map { |i| doc.resolve(["permissions", i]) }
    assert notes.slim?(storage)
    assert notes.slim?(tabs)
    assert_not notes.slim?(cookies)
    assert_not notes.slim?(web), "an unrated note is never slim"
    assert_not notes.slim?(doc.resolve(["name"])), "a line without notes is not slim"
    assert_equal [false, true], notes.notes_for(cookies).map(&:quiet?)
  end

  test "a finding on several lines is full on its lowest line and a repeat on the others" do
    # Evidence order does not matter: the first occurrence is the lowest line.
    notes, findings = notes_for([
      { severity: "Critical", title: "Combo", description: "x", rule: "c",
        evidence: [["host_permissions", 0], ["permissions", 3], ["permissions", 2]] },
      { severity: "High", title: "High-Risk Permission: webRequest", description: "x" },
      { severity: "Low", title: "Low cookies", description: "x", rule: "l", evidence: [["permissions", 3], ["optional_permissions", 0]] }
    ])
    combo = findings.find { |f| f.title == "Combo" }
    web, cookies, all = doc.resolve(["permissions", 2]), doc.resolve(["permissions", 3]), doc.resolve(["host_permissions", 0])
    assert_equal [web, cookies, all], notes.lines_for(combo)

    first = notes.notes_for(web).find { |n| n.finding.equal?(combo) }
    assert_equal [web, web], [first.line, first.first_line]
    assert_not first.repeat?
    assert_not first.slim?, "a Critical note on its first line is a full card"

    [cookies, all].each do |line|
      repeat = notes.notes_for(line).find { |n| n.finding.equal?(combo) }
      assert repeat.repeat?
      assert repeat.slim?
      assert_equal web, repeat.first_line
      assert_equal "critical", repeat.severity, "a repeat keeps its severity"
      assert_equal "critical", notes.severity_of(line), "and the line keeps its marking"
    end

    # Several findings on one line keep the most severe first, whatever is a repeat.
    assert_equal [["Combo", true], ["Low cookies", false]],
                 notes.notes_for(cookies).map { |n| [n.finding.title, n.repeat?] }
    assert notes.slim?(cookies), "a repeated Critical plus a Low first occurrence are both slim"
    assert_equal [["Combo", false], ["High-Risk Permission: webRequest", false]],
                 notes.notes_for(web).map { |n| [n.finding.title, n.repeat?] }
    assert_not notes.slim?(web)
    assert notes.slim?(all)
    # Line counts still count lines by their most severe note.
    assert_equal [["critical", 3], ["low", 1]], notes.line_counts
  end

  test "the first occurrence is the lowest line even inside a folded array" do
    raw = RAW.merge("web_accessible_resources" => (1..30).map { |i| "f#{i}.js" })
    document = ScanPage::ManifestDocument.new(raw)
    notes, findings = notes_for([
      { severity: "High", title: "Exposed files", description: "x", rule: "w",
        evidence: [["web_accessible_resources", 25], ["web_accessible_resources", 3]] }
    ], raw)
    group = document.groups.find { |g| g.size == 30 }
    lines = notes.lines_for(findings.first)
    first = document.resolve(["web_accessible_resources", 3])
    assert_equal first, lines.first
    assert first > group.first && first < group.last, "the first line sits inside the long array"
    assert_equal [false, true], lines.map { |l| notes.notes_for(l).first.repeat? }
    assert_equal [first], lines.map { |l| notes.notes_for(l).first.first_line }.uniq
  end

  test "severity keys and labels" do
    assert_equal "high", ScanPage::ManifestNotes.severity_key(" High ")
    assert_equal "unrated", ScanPage::ManifestNotes.severity_key("<b>High</b>")
    assert_equal "unrated", ScanPage::ManifestNotes.severity_key(nil)
    assert_equal "Full control", ScanPage::ManifestNotes.severity_label("critical")
    assert_equal "Routine", ScanPage::ManifestNotes.severity_label(" LOW ")
    assert_equal "Minimal", ScanPage::ManifestNotes.severity_label("minimal")
    assert_equal "Info", ScanPage::ManifestNotes.severity_label("info")
    assert_equal "Unrated", ScanPage::ManifestNotes.severity_label(nil)
    assert_equal "Unrated", ScanPage::ManifestNotes.severity_label("  ")
    assert_equal "Severe", ScanPage::ManifestNotes.severity_label("Severe")
    assert_equal "#{'x' * 19}…", ScanPage::ManifestNotes.severity_label("x" * 50)
    assert_equal "7", ScanPage::ManifestNotes.severity_label(7)
  end

  test "junk findings, evidence and manifests never raise" do
    junk = [
      { severity: { "a" => 1 }, title: ["x"], description: 5, rule: 7, evidence: "permissions" },
      { severity: "High", title: "t", description: "d", evidence: [[nil], ["permissions", 1.5], [], "x", [["nested"]], ["permissions", -1]] },
      { severity: "High", title: "t2", description: "d", evidence: [["permissions", 2**70]] },
      { severity: nil, title: nil, description: nil }
    ]
    [RAW, nil, "x", {}, [], { "permissions" => "tabs" }].each do |raw|
      notes, findings = notes_for(junk, raw)
      findings.each { |f| notes.lines_for(f) }
      notes.by_line
      notes.line_counts
      notes.unplaced_count
    end
    notes, findings = notes_for(junk)
    # Index -1 is not an entry; it falls back to the key.
    assert_equal ['"permissions": ['], notes.lines_for(findings.find { |f| f.title == "t" }).map { |n| text_at(doc, n) }
    assert notes_for([], nil).first.lines.empty?
  end

  test "no findings, or none that map, leave no notes" do
    notes, = notes_for([])
    assert_not notes.any?
    assert_not notes.findings?

    notes, = notes_for([{ severity: "Low", title: "Something new", description: "x" }])
    assert_not notes.any?
    assert notes.findings?
    assert_equal 1, notes.unplaced_count
  end
end
