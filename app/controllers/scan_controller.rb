class ScanController < ApplicationController
  helper_method :get_display_severity

  # The store-version lookup asks Google, so keep one visitor from making the
  # server do that in a loop. A normal page view makes one request.
  STORE_VERSION_RATE_LIMIT = 30
  rate_limit to: STORE_VERSION_RATE_LIMIT, within: 1.minute, only: :store_version, name: "store-version",
             with: -> { render json: { error: "Too many requests. Please try again in a minute." }, status: :too_many_requests }

  def show
    @extension_id = params[:id]&.downcase
    
    unless valid_extension_id?(@extension_id)
      if request.xhr?
        render json: { error: "Invalid extension ID format" }, status: :unprocessable_entity
      else
        flash[:error] = "Invalid extension ID format"
        redirect_to root_path
      end
      return
    end

    if request.xhr?
      @scan_result = ScanResult.find_by(extension_id: @extension_id)
      if @scan_result
        @manifest = @scan_result.manifest
        @extension_name = @scan_result.extension_name
        @extension_image = @scan_result.extension_image
        @extension_details = @scan_result.extension_details
        @security_findings = @scan_result.security_findings
        @last_scanned = @scan_result.updated_at
        @report = ScanPage::Report.new(manifest: @manifest, security_findings: @security_findings,
                                       cache_key: [@scan_result.id, @scan_result.updated_at.to_f])
        # Cached store version only: the page never waits for Google.
        @freshness = ScanFreshness.new(@scan_result, store: StoreVersionClient.cached(@extension_id))
        render partial: 'results'
      else
        render json: { error: "Analysis results not found" }, status: :not_found
      end
    else
      @scan_result = ScanResult.find_by(extension_id: @extension_id)
      if @scan_result
        @manifest = @scan_result.manifest
        @extension_name = @scan_result.extension_name
        @extension_image = @scan_result.extension_image
        @extension_details = @scan_result.extension_details
        @security_findings = @scan_result.security_findings
        @last_scanned = @scan_result.updated_at
        @report = ScanPage::Report.new(manifest: @manifest, security_findings: @security_findings,
                                       cache_key: [@scan_result.id, @scan_result.updated_at.to_f])
        # Cached store version only: the page never waits for Google.
        @freshness = ScanFreshness.new(@scan_result, store: StoreVersionClient.cached(@extension_id))
      end
      render :show
    end
  end

  def analyze
    @extension_id = params[:id]&.strip

    unless valid_extension_id?(@extension_id)
      render json: { error: "Invalid extension ID format" }, status: :unprocessable_entity
      return
    end

    existing_scan = ScanResult.find_by(extension_id: @extension_id)
    
    # Return the existing scan unless force is true and a re-scan is allowed:
    # the scan is older than 24 hours, or the store now has another version
    # (the server asks the store; nothing from the browser decides this).
    if existing_scan && (params[:force] != 'true' || !rescan_allowed?(existing_scan))
      Rails.logger.debug "Found recent scan for extension #{@extension_id}"
      render json: existing_scan.as_json(except: [:id]).merge(last_scanned: existing_scan.updated_at)
      return
    end

    analyzer = ExtensionAnalyzer.new(@extension_id, previous_findings: existing_scan&.security_findings)
    result = analyzer.perform

    if result.error?
      render json: { error: result.error }, status: :unprocessable_entity
    else
      # Delete existing scan if it exists
      existing_scan&.destroy

      begin
        scan_result = ScanResult.new(
          extension_id: @extension_id,
          extension_name: result.extension_name,
          extension_image: result.extension_image,
          manifest: result.manifest.deep_symbolize_keys,
          extension_details: result.extension_details.deep_symbolize_keys,
          security_findings: result.security_findings.map(&:deep_symbolize_keys)
        )
      rescue => e
        Rails.logger.error "Failed to create scan result: #{e.message}"
        Rails.logger.error "Backtrace: #{e.backtrace.join("\n")}"
        render json: { error: "Failed to process scan results" }, status: :internal_server_error
        return
      end

      if scan_result.save
        Rails.logger.debug "Saved new scan result"
        render json: scan_result.as_json(except: [:id]).merge(last_scanned: scan_result.updated_at)
      else
        render json: { error: scan_result.errors.full_messages.join(", ") }, status: :unprocessable_entity
      end
    end
  end

  # GET /scan/:id/store_version: the version the Chrome Web Store offers now,
  # compared with the stored scan. Called by the scan page after it loads.
  # Only for extensions with a stored scan, so it cannot be used to make the
  # server query Google for arbitrary IDs.
  def store_version
    extension_id = params[:id].to_s.downcase
    unless valid_extension_id?(extension_id)
      render json: { error: "Invalid extension ID format" }, status: :unprocessable_entity
      return
    end

    scan = ScanResult.find_by(extension_id: extension_id)
    unless scan
      render json: { error: "No stored scan for this extension" }, status: :not_found
      return
    end

    store = StoreVersionClient.lookup(extension_id)
    freshness = ScanFreshness.new(scan, store: store)
    render json: {
      extension_id: extension_id,
      status: store.status,
      store_version: freshness.store_version,
      version_differs: freshness.version_differs?,
      old: freshness.old?,
      store_note: freshness.store_note,
      notice: freshness.notice,
      rescan_allowed: freshness.rescan_allowed?
    }
  end

  def stats
    @total_scans = ScanResult.count

    # Filter recent scans by severity if specified
    severity_filter = params[:severity]
    if severity_filter.present?
      @recent_scans = ScanResult.where(
        "EXISTS (
          SELECT 1 FROM jsonb_array_elements(security_findings) AS finding
          WHERE finding->>'title' = 'AI Context Analysis'
          AND finding->>'severity' = 'Info'
          AND finding->>'description' LIKE ?
        )",
        "Risk Level: #{severity_filter}%"
      ).or(
        ScanResult.where(
          "NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(security_findings) AS finding
            WHERE finding->>'title' = 'AI Context Analysis'
            AND finding->>'severity' = 'Info'
          )
          AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(security_findings) AS finding
            WHERE LOWER(finding->>'title') LIKE '%overall risk%'
            AND finding->>'severity' = ?
          )",
          severity_filter
        )
      ).order(created_at: :desc).limit(10)
    else
      @recent_scans = ScanResult.order(created_at: :desc).limit(10)
    end

    # If this is an AJAX request, only render the table partial
    if request.xhr?
      render partial: 'recent_scans_table', locals: { recent_scans: @recent_scans }
      return
    end

    # Load cached stats or trigger refresh if cache is empty
    cache = StatCache.first
    if cache.nil?
      # No cache exists, trigger a job to create it and use defaults
      RefreshStatsJob.perform_later
      # Ordered from most to least severe
      @severity_counts = {
        'Critical' => 0,
        'High' => 0,
        'Medium' => 0,
        'Low' => 0,
        'Minimal' => 0
      }
      @spiciest_extensions = []
      @scans_last_30_days = 0
      @all_urls_count = 0
    else
      # Ensure correct order (most to least severe) when loading from cache
      stored_counts = cache.severity_counts
      @severity_counts = {
        'Critical' => stored_counts['Critical'] || 0,
        'High' => stored_counts['High'] || 0,
        'Medium' => stored_counts['Medium'] || 0,
        'Low' => stored_counts['Low'] || 0,
        'Minimal' => stored_counts['Minimal'] || 0
      }
      # Convert spiciest_extensions from stored hashes back to the format expected by the view
      @spiciest_extensions = cache.spiciest_extensions.map do |ext_data|
        {
          scan: ScanResult.find_by(extension_id: ext_data['extension_id']),
          finding_count: ext_data['finding_count']
        }
      end.compact # Remove any nil scans (in case an extension was deleted)
      @scans_last_30_days = cache.scans_last_30_days || 0
      @all_urls_count = cache.all_urls_count || 0
    end
  end

  private

  def rescan_allowed?(scan)
    return true if scan.updated_at <= ScanFreshness::RESCAN_AFTER.ago

    ScanFreshness.new(scan, store: StoreVersionClient.lookup(scan.extension_id)).rescan_allowed?
  end

  def valid_extension_id?(id)
    id.present? && id.match?(/\A[a-zA-Z0-9]{32}\z/)
  end

  # Get display severity - prefers AI context-aware verdict, falls back to overall risk
  def get_display_severity(scan)
    # First, try to get AI context-aware verdict
    ai_analysis = scan.security_findings&.find { |f| f[:severity] == "Info" && f[:title] == "AI Context Analysis" }
    if ai_analysis && ai_analysis[:description]&.start_with?("Risk Level:")
      risk_level = ai_analysis[:description].split("\n").first.split("Risk Level:").last&.strip
      return risk_level&.capitalize
    end

    # Fall back to overall risk
    overall_risk = scan.security_findings&.find { |f| f[:title]&.downcase&.include?('overall risk') }
    overall_risk[:severity]&.capitalize if overall_risk
  end
end 