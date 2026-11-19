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

  def api_error(status, klass)
    klass.new(url: URI("https://api.invalid/v1/messages"), status: status, headers: {}, body: nil,
              request: nil, response: nil, message: "x")
  end

  test "selects only scans with a manifest and findings but no AI analysis, optionally after an id" do
    assert_equal [@without_ai.id, @second_without_ai.id].sort, AiVerdictBackfill.candidates.pluck(:id).sort
    assert_equal [@second_without_ai.id], AiVerdictBackfill.candidates(after_id: @without_ai.id).pluck(:id)
  end

  test "dry run only reports the count" do
    client = FakeAnthropic::Client.new
    result = runner(client, dry_run: true, limit: 1).run

    assert_equal 2, result.eligible
    assert_empty client.calls
    assert_match(/Dry run: 2 scan\(s\) have no AI analysis; this run would process up to 1/, @out.string)
  end

  test "a real run needs LIMIT or ALL" do
    client = FakeAnthropic::Client.new
    result = runner(client).run

    assert result.refused
    assert_empty client.calls
    assert_match(/Refusing to run.*Pass LIMIT=n, or ALL=1/, @out.string)
  end

  test "stores the analysis without touching updated_at, pauses, sends the capture date, totals tokens and never tweets" do
    @without_ai.update_columns(updated_at: Time.utc(2026, 9, 1, 12))
    before = @without_ai.reload.updated_at
    client = FakeAnthropic::Client.new(FakeAnthropic.json_response, FakeAnthropic.json_response)

    result = runner(client, all: true, pause: 1.5).run

    assert_equal 2, result.updated
    assert_equal [1.5], @sleeps
    @without_ai.reload
    assert_equal before, @without_ai.updated_at
    ai = AiContextAnalysis.find_in(@without_ai.security_findings)
    assert_equal "some", ai[:ai][:concern_level]
    # The verdict is rebuilt with the new check: Scoped access, and concerns lower trust to the lowest level.
    overall = @without_ai.security_findings.first
    assert_equal ["Overall Risk: High", "High", "Medium", "concerns", ExtensionSecurityAnalyzer::RULES_VERSION],
                 overall.values_at(:title, :severity, :access, :trust, :rules_version)
    assert_equal ai, @without_ai.security_findings.last
    assert_includes client.calls.first[:messages].first[:content], "\"data_captured_on\":\"2026-09-01\""
    assert_empty AiVerdictBackfill.candidates
    assert_empty NoTweetsInTests::POSTED
    assert_equal [1800, 600], [result.input_tokens, result.output_tokens]
    assert_match(/Tokens used: 1800 input, 600 output/, @out.string)
    assert_match(/Last processed id: #{@second_without_ai.id} \(continue with AFTER_ID=#{@second_without_ai.id}\)/, @out.string)
  end

  test "respects the limit and resumes after AFTER_ID" do
    client = FakeAnthropic::Client.new(FakeAnthropic.json_response)
    result = runner(client, limit: 1).run
    assert_equal 1, result.attempted
    assert_equal @without_ai.id, result.last_id

    client = FakeAnthropic::Client.new(FakeAnthropic.json_response)
    result = runner(client, limit: 5, after_id: @without_ai.id).run
    assert_equal 1, result.attempted
    assert_equal @second_without_ai.id, result.last_id
    assert_empty AiVerdictBackfill.candidates
  end

  test "per-scan failures are reported and skipped, never stopping the run" do
    third = ScanResult.create!(extension_id: "8" * 32, manifest: MANIFEST, security_findings: RULE_FINDINGS)
    refusal = FakeAnthropic::Response.new(stop_reason: :refusal, content: [], model: :"claude-opus-5-5",
                                          stop_details: nil, usage: FakeAnthropic.usage)
    client = FakeAnthropic::Client.new(refusal, api_error(400, Anthropic::Errors::BadRequestError),
                                       FakeAnthropic.json_response)
    result = nil
    capture_rails_log { result = runner(client, all: true, max_consecutive_failures: 1).run }

    assert_not result.stopped_early
    assert_equal 3, result.attempted
    assert_equal 2, result.skipped
    assert_equal 1, result.updated
    assert_match(/Skipped #{@without_ai.id} .*: refusal/, @out.string)
    assert_match(/Skipped #{@second_without_ai.id} .*: bad_request/, @out.string)
    assert AiContextAnalysis.find_in(third.reload.security_findings)
  end

  test "stops after consecutive systemic failures" do
    client = FakeAnthropic::Client.new(api_error(429, Anthropic::Errors::RateLimitError),
                                       api_error(503, Anthropic::Errors::ServiceUnavailableError))
    result = nil
    capture_rails_log { result = runner(client, all: true, max_consecutive_failures: 2).run }

    assert result.stopped_early
    assert_equal 2, client.calls.size
    assert_match(/Stopping after 2 consecutive systemic failures \(server_error\)/, @out.string)
  end

  test "a scan replaced by a re-scan meanwhile is not counted as updated" do
    replace = lambda do |_params|
      @without_ai.destroy
      ScanResult.create!(extension_id: "1" * 32, manifest: MANIFEST, security_findings: RULE_FINDINGS)
      FakeAnthropic.json_response
    end
    client = FakeAnthropic::Client.new(replace)
    result = runner(client, limit: 1).run

    assert_equal 0, result.updated
    assert_equal 1, result.write_conflicts
    assert_match(/Not saved #{@without_ai.id}/, @out.string)
  end

  test "does nothing without an API key" do
    result = runner(:default, limit: 1).run
    assert_equal 0, result.attempted
    assert_match(/ANTHROPIC_API_KEY is not set/, @out.string)
  end
end
