require 'anthropic'

Anthropic.configure do |config|
  config.access_token = ENV.fetch('ANTHROPIC_API_KEY') do |key|
    raise "Missing ANTHROPIC_API_KEY environment variable" unless Rails.env.development?
    Rails.logger.warn "Missing ANTHROPIC_API_KEY environment variable"
    nil
  end
end 