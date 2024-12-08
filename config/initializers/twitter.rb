Rails.application.reloader.to_prepare do
    begin
      # Test that we can initialize the client
      TwitterClient.new
    rescue => e
      Rails.logger.error "Failed to initialize Twitter client: #{e.message}"
    end
  end