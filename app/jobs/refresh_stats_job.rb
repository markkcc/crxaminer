# Recomputes the statistics page's numbers (see ScanStats) and saves them as
# the one StatCache row. Scheduled in config/recurring.yml.
class RefreshStatsJob < ApplicationJob
  queue_as :default

  def perform
    # A worker that started before the migration added `metrics` learns of
    # the column here, so the newer statistics need no restart.
    StatCache.reset_column_information

    result = ScanStats::Collector.run
    cache = StatCache.replace!(ScanStats.cache_attributes(result, previous: StatCache.current))

    Rails.logger.info "Stats cache refreshed from #{result.scans} scans: #{cache.severity_counts.inspect}"
    Rails.logger.warn "Statistics kept from the last run: #{result.failed.join(', ')}" if result.failed.any?
  end
end
