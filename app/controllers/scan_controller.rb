class ScanController < ApplicationController
  helper_method :get_display_severity

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
    
    # Return existing scan if either:
    # 1. force is not true and scan exists, OR
    # 2. force is true and scan exists and is less than 24 hours old
    if existing_scan && (
         params[:force] != 'true' || 
         existing_scan.updated_at > 24.hours.ago
       )
      Rails.logger.debug "Found recent scan for extension #{@extension_id}"
      render json: existing_scan.as_json(except: [:id]).merge(last_scanned: existing_scan.updated_at)
      return
    end

    analyzer = ExtensionAnalyzer.new(@extension_id)
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

  def stats
    @total_scans = ScanResult.count
    @recent_scans = ScanResult.order(created_at: :desc).limit(10)

    # Calculate severity counts
    @severity_counts = {
      'Critical' => 0,
      'High' => 0,
      'Medium' => 0,
      'Low' => 0,
      'Minimal' => 0
    }

    ScanResult.find_each do |scan|
      severity = get_display_severity(scan)
      @severity_counts[severity] += 1 if severity && @severity_counts.key?(severity)
    end

    # Get top 5 "spiciest" extensions (most findings)
    @spiciest_extensions = ScanResult.all.map do |scan|
      finding_count = scan.security_findings&.count { |f| !f[:title]&.downcase&.include?('overall risk') } || 0
      {
        scan: scan,
        finding_count: finding_count
      }
    end.sort_by { |e| -e[:finding_count] }.take(5)
  end

  private

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