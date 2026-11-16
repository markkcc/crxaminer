require "test_helper"

class ExtensionSecurityAnalyzerTest < ActiveSupport::TestCase
  MANIFEST = {
    manifest_version: 3, name: "Demo", version: "1.0", permissions: ["tabs", "cookies"],
    host_permissions: ["<all_urls>"], content_scripts: [{ "matches" => ["<all_urls>"] }],
    content_security_policy: [], embedded_urls: [], raw: { "description" => "Demo extension" }
  }.freeze
  DETAILS = { rating: "4.0", rating_count: "10", size: "1MiB", users: "100" }.freeze

  setup { NoTweetsInTests::POSTED.clear }

  test "adds the AI finding after the rule findings and only records (never posts) the tweet" do
    client = FakeAnthropic::Client.new(FakeAnthropic.json_response)
    findings = ExtensionSecurityAnalyzer.new(MANIFEST, DETAILS, "Demo", "e" * 32, ai_client: client).analyze

    assert_equal 1, client.calls.size
    assert findings.first[:title].start_with?("Overall Risk:")
    assert_equal "AI Context Analysis", findings.last[:title]
    assert_equal 1, NoTweetsInTests::POSTED.size
    assert_includes NoTweetsInTests::POSTED.first, "Risk: High"
  end

  test "a failed AI call leaves the rule-based findings intact" do
    client = FakeAnthropic::Client.new(FakeAnthropic.text_response("oops"))
    findings = nil
    capture_rails_log do
      findings = ExtensionSecurityAnalyzer.new(MANIFEST, DETAILS, "Demo", "e" * 32, ai_client: client).analyze
    end

    assert_nil AiContextAnalysis.find_in(findings)
    assert findings.any? { |f| f[:title].start_with?("Overall Risk:") }
  end

  test "re-scanning unchanged input reuses the stored analysis" do
    first = ExtensionSecurityAnalyzer.new(MANIFEST, DETAILS, "Demo", "e" * 32,
                                          ai_client: FakeAnthropic::Client.new(FakeAnthropic.json_response)).analyze
    stored = ScanResult.new(security_findings: first).security_findings

    client = FakeAnthropic::Client.new
    second = ExtensionSecurityAnalyzer.new(MANIFEST, DETAILS, "Demo", "e" * 32,
                                           previous_findings: stored, ai_client: client).analyze

    assert_empty client.calls
    assert_equal AiContextAnalysis.find_in(first)[:description], AiContextAnalysis.find_in(second)[:description]
  end
end
