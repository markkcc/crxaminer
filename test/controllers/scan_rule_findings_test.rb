require "test_helper"

# The scan page with findings written by the current rule engine, next to
# findings stored by the older one.
class ScanRuleFindingsTest < ActionDispatch::IntegrationTest
  RAW = {
    "manifest_version" => 3, "name" => "New", "version" => "1",
    "permissions" => %w[storage alarms tabs cookies],
    "optional_permissions" => %w[history contextMenus],
    "host_permissions" => ["<all_urls>", "https://www.paypal.com/*"],
    "optional_host_permissions" => ["file:///*"],
    "content_security_policy" => { "extension_pages" => "script-src 'self' 'wasm-unsafe-eval'" }
  }.freeze
  MANIFEST = {
    manifest_version: 3, name: "New", version: "1", permissions: RAW["permissions"],
    optional_permissions: RAW["optional_permissions"], host_permissions: RAW["host_permissions"],
    optional_host_permissions: RAW["optional_host_permissions"],
    content_security_policy: ["extension_pages: script-src 'self' 'wasm-unsafe-eval'"], embedded_urls: [], raw: RAW
  }.freeze

  def create_new_scan(id)
    ScanResult.create!(extension_id: id, extension_name: "New", manifest: MANIFEST, extension_details: {},
                       security_findings: ExtensionSecurityAnalyzer.rule_findings(MANIFEST))
  end

  test "new findings are grouped by rule, routine ones fold by the table, optional ones say so" do
    create_new_scan("n" * 32)
    get scan_path("n" * 32), xhr: true
    assert_response :success

    assert_select "#overview [data-area=site_access] [data-finding]", text: /Access to All Websites/
    assert_select "#overview [data-area=site_access] [data-finding]", text: /Access to Sensitive Sites/
    assert_select "#overview [data-area=site_access] [data-finding]", text: /Optional Access to Local Files/
    assert_select "#overview [data-area=browser] > ul [data-finding]", text: /All Websites Plus Cookies/
    assert_select "#overview [data-area=browser] > ul [data-finding]", text: /Optional Permission: history/
    assert_select "#overview [data-area=code_policy] [data-finding]", text: /WebAssembly Allowed/
    assert_select "#overview [data-area=browser] details[data-routine] summary",
                  text: /3 routine permissions: alarms · storage · contextMenus \(optional\)/
    assert_select "#overview details[data-routine] .bg-severity-low", text: "Routine", count: 3
    # Rated with the current rules: no note about an earlier version.
    assert_select "#older-rules-note", count: 0
    assert_select "#info-popup", text: /Two ratings make up the result/
    assert_select "#info-popup", text: /earlier version of the rules/, count: 0
    assert_select "#security-info-popup", text: /one tier lower/
  end

  test "the overall card shows the rating and its basis" do
    create_new_scan("o" * 32)
    get scan_path("o" * 32), xhr: true

    assert_select ".bg-severity-critical", text: "Full control"
    assert_select "#verdict-access [data-based-on]", text: /Based on the manifest, by fixed rules: \d+ findings\./
  end

  test "the Permissions tab rates from the same table, optional ones one level lower" do
    create_new_scan("t" * 32)
    get scan_path("t" * 32), xhr: true

    required = css_select("#permissions-required-table tbody tr").to_h do |row|
      [row.at_css("th[scope=row] > span.font-mono").text.strip, row.at_css("td:nth-of-type(2) span").text.strip]
    end
    assert_equal({ "storage" => "Routine", "alarms" => "Routine", "tabs" => "Scoped", "cookies" => "Scoped" }, required)
    optional = css_select("#permissions-optional-table tbody tr").to_h do |row|
      [row.at_css("th[scope=row] > span.font-mono").text.strip, row.at_css("td:nth-of-type(2) span").text.strip]
    end
    assert_equal({ "history" => "Scoped", "contextMenus" => "Routine" }, optional)

    # Site patterns carry the engine's level for each pattern.
    assert_select "#permissions li", text: /<all_urls>\s+Broad reach/
    assert_select "#permissions li", text: %r{https://www\.paypal\.com/\*\s+Scoped}
    assert_select "#permissions li", text: %r{file:///\*\s+Routine}
  end

  test "an old scan still shows its stored findings, with a note about the earlier rules" do
    ScanResult.create!(extension_id: "w" * 32, extension_name: "Old", manifest: MANIFEST, extension_details: {},
                       security_findings: [
                         { severity: "Critical", title: "Overall Risk: Critical", description: "Based on 5 total findings, including 4 high-risk findings." },
                         { severity: "High", title: "High-Risk Permission: tabs", description: "Old tabs text." },
                         { severity: "Medium", title: "Medium-Risk Permission: storage", description: "Old storage text." },
                         { severity: "High", title: "Unsafe WebAssembly Execution", description: "Old wasm text." }
                       ])
    get scan_path("w" * 32), xhr: true
    assert_response :success

    assert_select "#older-rules-note"
    assert_select "#info-popup", text: /earlier version of the rules/
    assert_select "#overview [data-area=browser] > ul [data-finding]", text: /Old tabs text\./
    assert_select "#overview details[data-routine] .bg-severity-medium", text: "Scoped", count: 1
    assert_select "#overview [data-area=code_policy] [data-finding]", text: /Old wasm text\./
  end
end
