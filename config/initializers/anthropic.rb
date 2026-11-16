require 'anthropic'

# The official Anthropic SDK is configured per client (see AiContextAnalysis),
# which reads ANTHROPIC_API_KEY when it runs. Production still refuses to boot
# without a key; development and test boot and log instead, and the AI step
# is skipped (with an error log) for scans run without a key.
unless ENV.key?('ANTHROPIC_API_KEY')
  raise "Missing ANTHROPIC_API_KEY environment variable" unless Rails.env.development? || Rails.env.test?
  Rails.logger.warn "Missing ANTHROPIC_API_KEY environment variable"
end
