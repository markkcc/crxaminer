class RefreshStatsJob < ApplicationJob
  ALL_URLS_JSON = '["<all_urls>"]'.freeze

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

    # Extensions with <all_urls> in permissions or host_permissions. A stored
    # manifest can hold anything in those keys (a string, null, an object), and
    # jsonb_array_elements_text raises on anything but a list, which would stop
    # the whole job; the containment operator simply does not match.
    all_urls_count = ScanResult.where(
      "manifest->'permissions' @> ?::jsonb OR manifest->'host_permissions' @> ?::jsonb",
      ALL_URLS_JSON, ALL_URLS_JSON
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
