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

    # Top 5 "spiciest" extensions: the most rule findings, not counting the
    # overall rating, the AI verdict or routine permissions (rated Low in
    # ExtensionAnalyzerData::PERMISSIONS), so a long list of harmless
    # permissions does not count as spicy.
    spiciest_extensions = ScanResult.all.map do |scan|
      finding_count = ScanPage::FindingGroups.new(scan.read_attribute(:security_findings)).areas.sum { |area| area.findings.size }
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

  # The level shown for a scan (ScanDisplayLevel), read from the column as
  # stored so a junk row cannot stop the job.
  def get_display_severity(scan)
    ScanDisplayLevel.for(scan.read_attribute(:security_findings))
  end
end
