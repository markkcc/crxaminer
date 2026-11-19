# The numbers on the statistics page.
#
#   ScanStats::Collector   reads every stored scan once, in batches, and
#                          works out all the numbers (RefreshStatsJob).
#   StatCache              the one row they are saved in.
#   ScanStats::Dashboard   reads that row for the page.
#
# The page never queries the scans for these numbers, so a statistic costs
# nothing per page view. Each statistic is worked out and shown on its own:
# one that fails keeps its last saved value, or is left off the page, and
# the others carry on.
#
# The four oldest statistics have columns of their own on stat_caches. The
# newer ones are saved together in its `metrics` JSON column, each under its
# own key (METRIC_KEYS) and each with its own totals, so a value kept from an
# earlier run still adds up. Until the migration that adds the column has
# run, only the four older statistics are saved and shown.
module ScanStats
  # Extensions by number of users: the first bucket whose `below` is above
  # the count, the last one otherwise.
  USER_BUCKETS = [
    { key: "under_1k", label: "Under 1,000", below: 1_000 },
    { key: "1k_10k", label: "1,000 to 9,999", below: 10_000 },
    { key: "10k_100k", label: "10,000 to 99,999", below: 100_000 },
    { key: "100k_1m", label: "100,000 to 999,999", below: 1_000_000 },
    { key: "1m_plus", label: "1,000,000 or more", below: nil }
  ].freeze

  TOP_PERMISSIONS = 10
  TOP_EXTENSIONS = 5

  # Keys of the statistics kept in StatCache#metrics.
  METRIC_KEYS = %w[all_sites manifest_versions permissions users popular_full_control].freeze

  module_function

  def user_bucket(users)
    USER_BUCKETS.find { |bucket| bucket[:below].nil? || users < bucket[:below] }
  end

  # The columns to save for a finished Collector run. A statistic that
  # failed (its value is nil) keeps what `previous`, the row being replaced,
  # had for it.
  def cache_attributes(result, previous: nil, metrics_column: StatCache.metrics_column?, now: Time.current)
    values = result.values
    attributes = {
      severity_counts: values[:levels] || previous&.severity_counts || ExtensionAnalyzerData::OVERALL_LEVELS.index_with(0),
      spiciest_extensions: values[:spiciest] || previous&.spiciest_extensions || [],
      scans_last_30_days: values[:recent] || previous&.scans_last_30_days || 0,
      all_urls_count: values[:all_urls] || previous&.all_urls_count || 0
    }
    return attributes unless metrics_column

    kept = previous&.stored_metrics || {}
    fresh = METRIC_KEYS.index_with { |key| values[key.to_sym] }.compact
    attributes.merge(metrics: kept.slice(*METRIC_KEYS).merge(fresh).merge(
      "scans" => result.scans, "computed_at" => now.utc.iso8601, "failed" => result.failed.map(&:to_s)
    ))
  end
end
