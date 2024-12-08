require 'oauth'

class TwitterClient
  def initialize
    @consumer = OAuth::Consumer.new(
      ENV["TWITTER_CONSUMER_KEY"],
      ENV["TWITTER_CONSUMER_SECRET"],
      site: 'https://api.twitter.com'
    )
    
    @oauth_token = OAuth::AccessToken.new(
      @consumer,
      ENV["TWITTER_ACCESS_TOKEN"],
      ENV["TWITTER_ACCESS_TOKEN_SECRET"]
    )
  rescue => e
    Rails.logger.error "Failed to initialize Twitter client: #{e.message}"
    return nil
  end

  def post_tweet(text)
    return false unless @oauth_token # Skip if initialization failed
    
    truncated_text = text.to_s.slice(0, 280)
    uri = URI("https://api.twitter.com/2/tweets")
    
    response = @oauth_token.post(
      uri.path,
      { text: truncated_text }.to_json,
      'Content-Type' => 'application/json'
    )
    
    result = JSON.parse(response.body)
    
    if ['200', '201'].include?(response.code)
        true
      else
        if response.code == '429'
          reset_time = response['x-rate-limit-reset']
          Rails.logger.error "Twitter Rate Limit Exceeded. Reset at: #{reset_time}"
        else
          Rails.logger.error "Twitter API Error: #{response.code}"
          Rails.logger.error result
        end
        false
      end
  rescue => e
    Rails.logger.error "Failed to post tweet: #{e.message}"
    false
  end
end