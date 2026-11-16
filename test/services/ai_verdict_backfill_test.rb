require "test_helper"

class AiVerdictBackfillTest < ActiveSupport::TestCase
  MANIFEST = { manifest_version: 3, name: "X", version: "1", permissions: ["tabs"], raw: { "description" => "d" } }.freeze
  RULE_FINDINGS = [{ severity: "Medium", title: "Overall Risk: Medium", description: "Based on 1 total findings." }].freeze

  setup do
    NoTweetsInTests::POSTED.clear
    ScanResult.delete_all
    @without_ai = ScanResult.create!(extension_id: "1" * 32, extension_name: "No AI", manifest: MANIFEST,
                                     extension_details: { users: "5" }, security_findings: RULE_FINDINGS)
    @with_ai = ScanResult.create!(extension_id: "2" * 32, manifest: MANIFEST, security_findings: RULE_FINDINGS +
      [{ severity: "Info", title: "AI Context Analysis", description: "Risk Level: Low\nLegacy text" }])
    @no_manifest = ScanResult.create!(extension_id: "3" * 32, manifest: {}, security_findings: RULE_FINDINGS)
    @no_findings = ScanResult.create!(extension_id: "4" * 32, manifest: MANIFEST, security_findings: [])
    @second_without_ai = ScanResult.create!(extension_id: "5" * 32, manifest: MANIFEST, security_findings: RULE_FINDINGS)
  end

  def runner(client, **opts)
    @out = StringIO.new
    @sleeps = []
    AiVerdictBackfill.new(client: client, out: @out, sleeper: ->(s) { @sleeps << s }, **opts)
  end

  test "selects only scans with a manifest and findings but no AI analysis" do
    assert_equal [@without_ai.id, @second_without_ai.id].sort, AiVerdictBackfill.candidates.pluck(:id).sort
  end

  test "dry run only reports the count" do
    client = FakeAnthropic::Client.new
    result = runner(client, dry_run: true, limit: 1).run

    assert_equal 2, result.eligible
    assert_empty client.calls
    assert_match(/Dry run: 2 scan\(s\) have no AI analysis; this run would process up to 1/, @out.string)
  end

  test "stores the analysis without touching updated_at, pauses between calls and never tweets" do
    @without_ai.update_columns(updated_at: 3.days.ago)
    before = @without_ai.reload.updated_at
    client = FakeAnthropic::Client.new(FakeAnthropic.json_response, FakeAnthropic.json_response)

    result = runner(client, pause: 1.5).run

    assert_equal 2, result.updated
    assert_equal [1.5], @sleeps
    @without_ai.reload
    assert_equal before, @without_ai.updated_at
    assert_equal "Risk Level: High", AiContextAnalysis.find_in(@without_ai.security_findings)[:description].lines.first.chomp
    assert_equal RULE_FINDINGS.first[:title], @without_ai.security_findings.first[:title]
    assert_empty AiVerdictBackfill.candidates
    assert_empty NoTweetsInTests::POSTED
  end

  test "respects the limit" do
    client = FakeAnthropic::Client.new(FakeAnthropic.json_response)
    result = runner(client, limit: 1).run

    assert_equal 1, result.attempted
    assert_equal 1, AiVerdictBackfill.candidates.count
  end

  test "stops after the configured number of consecutive failures" do
    client = FakeAnthropic::Client.new(FakeAnthropic.text_response("bad"), FakeAnthropic.text_response("bad"))
    result = nil
    capture_rails_log { result = runner(client, max_consecutive_failures: 1).run }

    assert result.stopped_early
    assert_equal 1, client.calls.size
    assert_match(/Stopping after 1 consecutive failures/, @out.string)
  end

  test "does nothing without an API key" do
    result = runner(:default).run
    assert_equal 0, result.attempted
    assert_match(/ANTHROPIC_API_KEY is not set/, @out.string)
  end
end
