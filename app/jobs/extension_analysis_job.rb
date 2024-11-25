class ExtensionAnalysisJob < ApplicationJob
  queue_adapter = :async

  def perform(extension_id)
    broadcast_update("Starting analysis...", extension_id)
    
    # Fetch store data
    broadcast_update("Fetching extension details...", extension_id)
    fetch_chrome_store_data(extension_id)
    
    # Download and analyze
    broadcast_update("Downloading extension...", extension_id)
    download_and_analyze_extension(extension_id)
    
    # Complete
    broadcast_complete(extension_id)
  end

  private

  def broadcast_update(message, extension_id)
    Turbo::StreamsChannel.broadcast_update_to(
      "analysis_#{extension_id}",
      target: "analysis_status",
      partial: "scan/loading_status",
      locals: { message: message }
    )
  end

  def broadcast_complete(extension_id)
    Turbo::StreamsChannel.broadcast_update_to(
      "analysis_#{extension_id}",
      target: "analysis_status",
      partial: "scan/complete_status"
    )
  end

  # ... rest of the analysis methods moved from controller ...
end 