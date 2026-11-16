# In-process stand-ins for the Anthropic client, so unit tests never reach
# the network. The SDK code path itself is covered by
# test/integration/ai_context_analysis_sdk_test.rb against a local stub server.
module FakeAnthropic
  Block = Struct.new(:type, :text, keyword_init: true)
  StopDetails = Struct.new(:category, :explanation, keyword_init: true)
  Response = Struct.new(:stop_reason, :content, :model, :stop_details, keyword_init: true)

  VALID_RESULT = {
    "risk_level" => "High",
    "summary" => "Broad access with an unclear purpose.",
    "trust_factors" => ["Large user base"],
    "concerns" => ["Reads every page", "Unknown publisher"],
    "recommendations" => ["Use a separate Chrome profile"]
  }.freeze

  def self.text_response(text, stop_reason: :end_turn, model: "claude-opus-5-5")
    Response.new(
      stop_reason: stop_reason,
      model: model.to_sym,
      stop_details: nil,
      content: [Block.new(type: :thinking, text: nil), Block.new(type: :text, text: text)]
    )
  end

  def self.json_response(data = VALID_RESULT, **opts)
    text_response(JSON.generate(data), **opts)
  end

  # Records create() params and returns the next queued response, or raises
  # it when it is an exception.
  class Client
    attr_reader :calls

    def initialize(*responses)
      @responses = responses
      @calls = []
    end

    def beta
      self
    end

    def messages
      self
    end

    def create(**params)
      @calls << params
      response = @responses.shift
      raise response if response.is_a?(Exception)
      raise "FakeAnthropic::Client: no response queued" if response.nil?

      response
    end
  end
end
