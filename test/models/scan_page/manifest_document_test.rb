require "test_helper"

class ScanPage::ManifestDocumentTest < ActiveSupport::TestCase
  RAW = {
    manifest_version: 2,
    name: "<script>alert(1)</script>",
    permissions: ["storage", "tabs", "webRequest", "webRequestBlocking", "<all_urls>"],
    host_permissions: ["https://a.test/*", "*://*/*"],
    content_scripts: [{ matches: ["https://b.test/*", "<all_urls>"], js: ["c.js"] }],
    content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'", sandbox: "script-src 'self'" },
    empty: {}, none: [], number: 1.5, flag: true, nothing: nil
  }.freeze

  def doc(raw = RAW)
    ScanPage::ManifestDocument.new(raw)
  end

  def line_text(document, number)
    document.lines[number - 1].text.strip
  end

  test "the text matches JSON.pretty_generate" do
    assert_equal JSON.pretty_generate(RAW), doc.text
    data = { "a" => [1, { "b" => [] }], "c" => "x" }
    assert_equal JSON.pretty_generate(data), doc(data).text
  end

  test "values are tokens with Rouge class names, not markup" do
    name = doc.lines.find { |l| l.text.include?("alert") }
    assert_includes name.tokens, ["s2", '"<script>alert(1)</script>"']
    assert_includes name.tokens, ["nl", '"name"']
  end

  test "permission findings point at their exact entries" do
    d = doc
    tabs = d.lines_for("High-Risk Permission: tabs")
    assert_equal ['"tabs",'], tabs.map { |n| line_text(d, n) }
    assert_equal ['"webRequest",', '"webRequestBlocking",'],
                 d.lines_for("Dangerous Permission Combination: webRequest + webRequestBlocking").map { |n| line_text(d, n) }
    assert_equal ['"<all_urls>"'], d.lines_for("High-Risk Permission: <all_urls>").map { |n| line_text(d, n) }
  end

  test "host and content script findings mirror the rule's own matching" do
    d = doc
    # The rule flags patterns that contain any risky pattern, and "*" is one,
    # so https://a.test/* counts too.
    assert_equal ['"https://a.test/*",', '"*://*/*"'], d.lines_for("Broad Host Permissions").map { |n| line_text(d, n) }
    narrow = doc(host_permissions: ["https://a.test/"])
    assert_equal ['"host_permissions": ['], narrow.lines_for("Broad Host Permissions").map { |n| line_text(narrow, n) }
    # Content scripts: exact matches only.
    assert_equal ['"<all_urls>"'], d.lines_for("Broad Content Script Injection").map { |n| line_text(d, n) }
  end

  test "findings without reliable entries point at the key" do
    d = doc
    assert_equal ['"host_permissions": ['], d.lines_for("Access to Sensitive Domains").map { |n| line_text(d, n) }
    assert_equal ['"manifest_version": 2,'], d.lines_for("Older Manifest Version").map { |n| line_text(d, n) }
    # A permission the stored list no longer has falls back to the key.
    assert_equal ['"permissions": ['], d.lines_for("High-Risk Permission: cookies").map { |n| line_text(d, n) }
  end

  test "CSP findings point at the matching policy entry" do
    d = doc
    assert_equal [%("extension_pages": "script-src 'self' 'wasm-unsafe-eval'",)],
                 d.lines_for("Unsafe WebAssembly Execution").map { |n| line_text(d, n) }

    string_csp = doc(content_security_policy: "script-src 'self' 'unsafe-eval'")
    assert_equal [2], string_csp.lines_for("Unsafe JavaScript Evaluation")
  end

  test "unknown titles and missing keys give no lines" do
    assert_equal [], doc.lines_for("Something new")
    assert_equal [], doc.lines_for(nil)
    assert_equal [], doc({ name: "x" }).lines_for("Older Manifest Version")
  end

  test "arrays longer than the limit are collapsed, nested ones too" do
    long = (1..25).map { |i| "p#{i}" }
    nested = { permissions: long, list: [{ inner: (1..30).to_a }] }
    d = doc(nested)

    assert_equal 2, d.groups.size
    outer, inner = d.groups
    assert_equal 25, outer.size
    assert_equal '"permissions": [', line_text(d, outer.first)
    assert_equal "],", line_text(d, outer.last)
    assert_equal [outer.id], d.lines[outer.first].groups
    assert_equal [], d.lines[outer.first - 1].groups
    assert_equal [], d.lines[outer.last - 1].groups
    assert_equal [inner.id], d.lines[inner.first].groups

    line = d.lines_for("Medium-Risk Permission: p22").first
    assert_equal [outer.id], d.lines[line - 1].groups
  end

  test "an array of exactly the limit is not collapsed" do
    assert_equal 0, doc(permissions: (1..20).to_a).groups.size
  end

  test "junk raw values never raise" do
    [nil, "", "just a string", 5, [], {}, [1, [2, [3]]], { "a" => Object.new }, { a: "\xFF".dup.force_encoding("BINARY") }].each do |raw|
      d = doc(raw)
      d.text
      assert_equal [], d.lines_for("Broad Host Permissions")
    end
    assert doc(nil).empty?
    assert doc({}).empty?
  end
end
