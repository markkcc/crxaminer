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
                                       extension_details: @extension_details,
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
                                       extension_details: @extension_details,
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
      render json: existing_scan.as_json(except: [:id]).merge(last_scanned: existing_scan.updated_at,
                                                              rating: rating_json(existing_scan))
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
        render json: scan_result.as_json(except: [:id]).merge(last_scanned: scan_result.updated_at,
                                                              rating: rating_json(scan_result))
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

    # Filter recent scans by the level they show (ScanDisplayLevel)
    severity_filter = params[:severity]
    # Only the columns the table shows: a stored manifest is large and is not one of them.
    recent = ScanResult.select(:id, :extension_id, :extension_name, :extension_image, :security_findings, :created_at)
                       .order(created_at: :desc).limit(10)
    @recent_scans = severity_filter.present? ? ScanDisplayLevel.where_level(recent, severity_filter.to_s) : recent

    # If this is an AJAX request, only render the table partial
    if request.xhr?
      render partial: 'recent_scans_table', locals: { recent_scans: @recent_scans }
      return
    end

    # The saved statistics (ScanStats). They are worked out in the background:
    # ask for that when nothing is saved yet, or when the migration has just
    # made room for the newer statistics and the saved row predates them.
    @stats = ScanStats::Dashboard.load
    request_stats_refresh if @stats.empty? || @stats.awaiting_metrics?
  end

  private

  def rescan_allowed?(scan)
    return true if scan.updated_at <= ScanFreshness::RESCAN_AFTER.ago

    ScanFreshness.new(scan, store: StoreVersionClient.lookup(scan.extension_id)).rescan_allowed?
  end

  # The verdict as the page shows it, for clients of the analyze endpoint.
  def rating_json(scan)
    findings = scan.read_attribute(:security_findings)
    rating = ScanRating.for_scan(security_findings: findings, extension_details: scan.read_attribute(:extension_details))
    { level: ScanDisplayLevel.for(findings), overall: rating.overall, headline: rating.headline,
      access: rating.access.name, trust: rating.trust.name }
  end

  STATS_REFRESH_KEY = "stats/refresh_requested".freeze
  STATS_REFRESH_EVERY = 30.minutes

  # Queues RefreshStatsJob, at most once per STATS_REFRESH_EVERY for each
  # server, however many people open the page meanwhile. A queue that cannot
  # take the job does not stop the page, and the next view tries again.
  def request_stats_refresh
    return if Rails.cache.read(STATS_REFRESH_KEY)

    RefreshStatsJob.perform_later
    Rails.cache.write(STATS_REFRESH_KEY, true, expires_in: STATS_REFRESH_EVERY)
  rescue StandardError => e
    Rails.logger.error("The statistics refresh could not be queued: #{e.class}: #{e.message}")
  end

  def valid_extension_id?(id)
    id.present? && id.match?(/\A[a-zA-Z0-9]{32}\z/)
  end

  # The level shown for a scan in the recent-scans list (ScanDisplayLevel),
  # read from the column as stored so a junk row cannot break the page.
  def get_display_severity(scan)
    ScanDisplayLevel.for(scan.read_attribute(:security_findings))
  end
end
