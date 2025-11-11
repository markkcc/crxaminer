class RefreshStatsJob < ApplicationJob
  queue_as :default

  def perform
    # Calculate severity counts (ordered from most to least severe)
    severity_counts = {
      'Critical' => 0,
      'High' => 0,
      'Medium' => 0,
      'Low' => 0,
      'Minimal' => 0
    }

    ScanResult.find_each do |scan|
      severity = get_display_severity(scan)
      severity_counts[severity] += 1 if severity && severity_counts.key?(severity)
    end

    # Get top 5 "spiciest" extensions (most findings)
    spiciest_extensions = ScanResult.all.map do |scan|
      finding_count = scan.security_findings&.count { |f| !f[:title]&.downcase&.include?('overall risk') } || 0
      {
        extension_id: scan.extension_id,
        extension_name: scan.extension_name,
        extension_image: scan.extension_image,
        finding_count: finding_count
      }
    end.sort_by { |e| -e[:finding_count] }.take(5)

    # Calculate scans in last 30 days
    scans_last_30_days = ScanResult.where("created_at >= ?", 30.days.ago).count

    # Calculate extensions with <all_urls> permissions
    # Use PostgreSQL to check if '<all_urls>' exists in either permissions or host_permissions arrays
    all_urls_count = ScanResult.where(
      "EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(manifest->'permissions') AS perm WHERE perm = '<all_urls>'
      ) OR EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(manifest->'host_permissions') AS perm WHERE perm = '<all_urls>'
      )"
    ).count

    # Save to cache (only keep one record)
    StatCache.destroy_all
    StatCache.create!(
      severity_counts: severity_counts,
      spiciest_extensions: spiciest_extensions,
      scans_last_30_days: scans_last_30_days,
      all_urls_count: all_urls_count
    )

    Rails.logger.info "Stats cache refreshed: #{severity_counts.inspect}"
  end

  private

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
