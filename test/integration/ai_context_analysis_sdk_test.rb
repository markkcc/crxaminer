require "test_helper"

# Runs the real Anthropic::Client (official SDK) against a stub HTTP server on
# 127.0.0.1, so the request the SDK actually serializes and the response
# objects it actually builds are exercised without a key or network access.
class AiContextAnalysisSdkTest < ActiveSupport::TestCase
  MANIFEST = {
    manifest_version: 3, name: "Demo", version: "1.0", permissions: ["tabs"], host_permissions: [],
    content_scripts: nil, content_security_policy: [],
    raw: { "manifest_version" => 3, "name" => "Demo", "version" => "1.0", "description" => "A demo extension." }
  }.freeze

  def message_body(content, stop_reason: "end_turn")
    {
      id: "msg_test", type: "message", role: "assistant", model: "claude-opus-5-5",
      content: content, stop_reason: stop_reason, stop_sequence: nil, stop_details: nil,
      usage: { input_tokens: 321, output_tokens: 123 }
    }
  end

  def analysis(server)
    client = AiContextAnalysis.build_client(api_key: "test-dummy-key", base_url: server.base_url)
    AiContextAnalysis.new(manifest: MANIFEST, extension_details: { users: "10" }, extension_name: "Demo",
                          findings: [{ severity: "Minimal", title: "Overall Risk: Minimal" }], client: client)
  end

  test "sends the expected request and reads the text block after a thinking block" do
    reply = { risk_level: "Low", summary: "Small and focused.", trust_factors: ["Narrow permissions"],
              concerns: [], recommendations: ["Keep it updated"] }
    server = StubMessagesServer.new([200, message_body([
      { type: "thinking", thinking: "", signature: "sig" },
      { type: "text", text: JSON.generate(reply), citations: nil }
    ])])

    finding = analysis(server).call

    assert_equal 1, server.requests.size
    request = server.requests.first
    body = request.json

    assert_equal "POST /v1/messages HTTP/1.1", request.request_line
    assert_equal "Bearer test-dummy-key", request.headers["authorization"]
    assert_equal "server-side-fallback-2026-07-01", request.headers["anthropic-beta"]
    assert_equal "claude-opus-5-5", body["model"]
    assert_equal AiContextAnalysis.max_tokens, body["max_tokens"]
    assert_equal 4000, body["max_tokens"]
    assert_equal "low", body.dig("output_config", "effort")
    assert_equal "json_schema", body.dig("output_config", "format", "type")
    assert_equal JSON.parse(JSON.generate(AiContextAnalysis::SCHEMA)), body.dig("output_config", "format", "schema")
    assert_equal "default", body["fallbacks"]
    assert_equal AiContextAnalysis::SYSTEM_PROMPT, body["system"]
    assert_equal 1, body["messages"].size
    assert_includes body["messages"].first["content"], "A demo extension."
    %w[temperature top_p top_k thinking tool_choice stream betas].each do |key|
      assert_not body.key?(key), "#{key} must not be in the request body"
    end

    assert_equal "Risk Level: Low", finding[:description].lines.first.chomp
    assert_equal "claude-opus-5-5", finding[:ai][:model]
    assert_equal ["Keep it updated"], finding[:ai][:recommendations]
  ensure
    server&.close
  end

  test "a refusal with empty content is handled without reading content" do
    server = StubMessagesServer.new([200, message_body([], stop_reason: "refusal").merge(
      stop_details: { type: "refusal", category: "cyber", explanation: nil,
                      fallback_credit_token: nil, fallback_has_prefill_claim: nil, recommended_model: nil }
    )])
    log = capture_rails_log { assert_nil analysis(server).call }
    assert_match(/refused .*category=:cyber/, log)
  ensure
    server&.close
  end

  test "max_tokens from the API is a failed analysis" do
    server = StubMessagesServer.new([200, message_body([{ type: "thinking", thinking: "", signature: "s" }],
                                                        stop_reason: "max_tokens")])
    log = capture_rails_log { assert_nil analysis(server).call }
    assert_match(/hit max_tokens/, log)
  ensure
    server&.close
  end

  test "an API error status is logged and does not raise" do
    server = StubMessagesServer.new([400, { type: "error",
                                            error: { type: "invalid_request_error", message: "bad request" } }])
    log = capture_rails_log { assert_nil analysis(server).call }
    assert_match(/API error 400 BadRequestError/, log)
    assert_equal 1, server.requests.size, "4xx errors are not retried"
  ensure
    server&.close
  end
end
