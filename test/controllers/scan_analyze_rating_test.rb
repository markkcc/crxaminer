require "test_helper"

# What the analyze endpoint returns for a stored scan: the scan plus its
# verdict, for any stored format.
class ScanAnalyzeRatingTest < ActionDispatch::IntegrationTest
  MANIFEST = { manifest_version: 3, permissions: ["proxy"], raw: { "manifest_version" => 3, "permissions" => ["proxy"] } }.freeze
  DETAILS = { users: "39,000,000", rating_count: "44.7K ratings" }.freeze

  test "a stored scan comes back with its verdict" do
    ScanResult.create!(extension_id: "r" * 32, manifest: MANIFEST, extension_details: DETAILS,
                       security_findings: ExtensionSecurityAnalyzer.rated_findings(MANIFEST, extension_details: DETAILS))
    get analyze_scan_index_path(id: "r" * 32)
    assert_response :success
    assert_equal({ "level" => "Medium", "overall" => "Medium", "headline" => "Very powerful, established publisher",
                   "access" => "Full control", "trust" => "Established" }, response.parsed_body["rating"])
  end

  test "an older or junk scan still answers" do
    ScanResult.create!(extension_id: "q" * 32, manifest: MANIFEST, extension_details: DETAILS,
                       security_findings: [{ severity: "High", title: "Overall Risk: High" },
                                           { severity: "Info", title: "AI Context Analysis", description: "Risk Level: Low\nx" }])
    get analyze_scan_index_path(id: "q" * 32)
    assert_equal({ "level" => "Low", "overall" => "Low", "headline" => "Powerful, established publisher",
                   "access" => "Broad reach", "trust" => "Established" }, response.parsed_body["rating"])

    # A row the model can load but that carries junk values. ScanResult itself
    # cannot load a column holding a bare string, so that case is not served here.
    ScanResult.create!(extension_id: "j" * 32, manifest: MANIFEST, extension_details: { users: { a: 1 }, rating_count: [3] },
                       security_findings: [{ title: 5, severity: ["High"] }, { title: "Overall Risk: x", severity: "Severe", rules_version: 4 }])
    get analyze_scan_index_path(id: "j" * 32)
    assert_response :success
    assert_equal({ "level" => nil, "overall" => "Minimal", "headline" => "Minimal access, unproven publisher",
                   "access" => "Minimal", "trust" => "Unproven" }, response.parsed_body["rating"])
  end
end
