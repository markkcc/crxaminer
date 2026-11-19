require "test_helper"

# Part 2: the overall finding is the combined verdict of access and trust,
# built after the AI check, first in the stored list, and rebuildable from
# stored data alone.
class CombinedVerdictTest < ActiveSupport::TestCase
  RAW = { "manifest_version" => 3, "name" => "Tabs", "description" => "Organizes tabs.",
          "permissions" => %w[tabs storage], "host_permissions" => ["<all_urls>"] }.freeze
  MANIFEST = { manifest_version: 3, permissions: RAW["permissions"], host_permissions: RAW["host_permissions"],
               content_scripts: nil, content_security_policy: [], embedded_urls: [], raw: RAW }.freeze
  POPULAR = { users: "39,000,000", rating: "4.5", rating_count: "44.7K ratings", size: "1MiB" }.freeze
  UNKNOWN = { users: "300", rating: "4.0", rating_count: "3", size: "2MiB" }.freeze

  setup { NoTweetsInTests::POSTED.clear }

  def reply(concern, fit = "fits")
    FakeAnthropic.json_response(FakeAnthropic::VALID_RESULT.merge("concern_level" => concern, "purpose_fit" => fit))
  end

  def analyze(details, client)
    ExtensionSecurityAnalyzer.new(MANIFEST, details, "Tabs", "t" * 32, ai_client: client).analyze
  end

  test "the overall finding comes first and carries the combined verdict" do
    client = FakeAnthropic::Client.new(reply("none"))
    findings = analyze(POPULAR, client)

    overall = findings.first
    assert_equal({ severity: "Low", title: "Overall Risk: Low",
                   description: "Access: Broad reach (the highest of 3 rule findings). Trust: Established. " \
                                "Little to worry about from what the manifest and the listing show.",
                   rules_version: 4, access: "High", trust: "established", headline: "Powerful, established publisher" },
                 overall)
    assert_equal "AI Context Analysis", findings.last[:title]
    assert_equal ["Access to All Websites", "Permission: tabs", "Permission: storage"], findings[1...-1].map { |f| f[:title] }
    assert_equal 1, findings.count { |f| ScanPage::FindingGroups.overall?(f) }
  end

  test "the AI check gets the rule findings and the access tier, never the overall line" do
    client = FakeAnthropic::Client.new(reply("none"))
    analyze(POPULAR, client)
    message = client.calls.sole[:messages].first[:content]
    payload = JSON.parse(message[/<extension_data>\n(.*)\n<\/extension_data>/m, 1])

    assert_equal "Broad reach", payload["access_tier"]
    assert_equal ["High: Access to All Websites", "Medium: Permission: tabs", "Low: Permission: storage"], payload["findings"]
    assert_not_includes message, "Overall Risk"
  end

  test "AI concerns lower trust and so raise the overall level, but never change access" do
    { "none" => %w[Low established], "some" => %w[Medium some], "serious" => %w[Critical concerns] }.each do |concern, (level, trust)|
      overall = analyze(POPULAR, FakeAnthropic::Client.new(reply(concern))).first
      assert_equal [level, trust, "High"], overall.values_at(:severity, :trust, :access), concern
    end

    minimal = ExtensionSecurityAnalyzer.new({ manifest_version: 3, raw: { "manifest_version" => 3 } }, POPULAR, "M", "m" * 32,
                                            ai_client: FakeAnthropic::Client.new(reply("serious", "does_not_fit"))).analyze
    assert_equal %w[Minimal concerns Low], minimal.first.values_at(:access, :trust, :severity)
  end

  test "without an AI result the scan is rated from the listing alone" do
    failures = [FakeAnthropic.text_response("not json"), RuntimeError.new("boom"),
                FakeAnthropic::Response.new(stop_reason: :refusal, content: [], model: :m, stop_details: nil, usage: nil)]
    failures.each do |failure|
      findings = nil
      capture_rails_log { findings = analyze(POPULAR, FakeAnthropic::Client.new(failure)) }
      assert_nil AiContextAnalysis.find_in(findings)
      assert_equal %w[Low established High], findings.first.values_at(:severity, :trust, :access)
    end
    findings = nil
    capture_rails_log { findings = analyze(UNKNOWN, :default) } # no API key here
    assert_equal %w[High unproven], findings.first.values_at(:severity, :trust)
  end

  test "stored data rebuilds the same list, with either key style, and never calls the AI" do
    client = FakeAnthropic::Client.new(reply("some", "broader_than_needed"))
    fresh = analyze(UNKNOWN, client)
    ai = AiContextAnalysis.find_in(fresh)

    scan = ScanResult.create!(extension_id: "t" * 32, manifest: MANIFEST, extension_details: UNKNOWN, security_findings: fresh)
    stored_strings = JSON.parse(ScanResult.connection.select_value("SELECT security_findings FROM scan_results WHERE id = #{scan.id}"))
    AiContextAnalysis.stub(:new, ->(**) { raise "must not be called" }) do
      symbols = ExtensionSecurityAnalyzer.rated_findings(scan.manifest, extension_details: scan.extension_details,
                                                         ai_findings: scan.security_findings)
      assert_equal JSON.parse(JSON.generate(fresh)), JSON.parse(JSON.generate(symbols))

      strings = ExtensionSecurityAnalyzer.rated_findings(JSON.parse(JSON.generate(MANIFEST)),
                                                         extension_details: JSON.parse(JSON.generate(UNKNOWN)),
                                                         ai_findings: stored_strings)
      assert_equal symbols.first, strings.first
      assert_equal stored_strings.last, strings.last, "the AI finding is kept exactly as given"
    end
    assert_equal %w[High concerns Critical], fresh.first.values_at(:access, :trust, :severity)
    assert_equal ai, fresh.last
  end

  test "an AI finding stored before this change loads and adds nothing to trust" do
    old_ai = { "severity" => "Info", "title" => "AI Context Analysis", "description" => "Risk Level: Critical\nOld.",
               "ai" => { "risk_level" => "Critical", "summary" => "Old." } }
    findings = ExtensionSecurityAnalyzer.rated_findings(MANIFEST, extension_details: POPULAR, ai_findings: [old_ai])
    assert_equal %w[Low established], findings.first.values_at(:severity, :trust)
    assert_same old_ai, findings.last
    rating = ScanRating.for_scan(security_findings: findings, extension_details: POPULAR)
    assert_nil rating.concern_level
  end

  test "junk listing details, AI findings and manifests never raise" do
    junk_details = [nil, "x", [1], { users: { a: 1 }, rating: [4], rating_count: 3.5, size: nil }, { "users" => "Share" }]
    junk_ai = [nil, "x", [1, 2], [nil, 5, "AI"], [{ title: "AI Context Analysis", severity: "Info", ai: "nope" }],
               [{ "title" => "AI Context Analysis", "severity" => "Info", "ai" => { "concern_level" => "catastrophic", "purpose_fit" => 7 } }]]
    junk_manifests = [MANIFEST, {}, { permissions: "tabs" }, { raw: "x" }, "string", 5]
    junk_manifests.product(junk_details, junk_ai).each do |manifest, details, ai|
      findings = nil
      assert_nothing_raised { findings = ExtensionSecurityAnalyzer.rated_findings(manifest, extension_details: details, ai_findings: ai) }
      assert_includes ExtensionAnalyzerData::OVERALL_LEVELS, findings.first[:severity]
      assert_equal "unproven", findings.first[:trust]
    end

    findings = nil
    capture_rails_log do
      findings = ExtensionSecurityAnalyzer.new(MANIFEST, "junk", 42, "j" * 32,
                                               ai_client: FakeAnthropic::Client.new(reply("some"))).analyze
    end
    assert_equal %w[High concerns Critical], findings.first.values_at(:access, :trust, :severity)
    assert_equal 1, NoTweetsInTests::POSTED.size
  end
end
