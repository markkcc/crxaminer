ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "minitest/mock"
require_relative "support/fake_anthropic"
require_relative "support/stub_messages_server"

# Tests never use a real Anthropic key or the real API.
ENV.delete("ANTHROPIC_API_KEY")

# Tests never post to X: record the text instead.
module NoTweetsInTests
  POSTED = []

  def post_tweet(text)
    POSTED << text
    false
  end
end
TwitterClient.prepend(NoTweetsInTests)

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Add more helper methods to be used by all tests here...

    # Captures Rails.logger output during the block and returns it.
    def capture_rails_log
      io = StringIO.new
      original = Rails.logger
      Rails.logger = ActiveSupport::Logger.new(io)
      yield
      io.string
    ensure
      Rails.logger = original
    end
  end
end
