# The newer statistics (ScanStats::METRIC_KEYS), kept together as JSON so
# that adding one later needs no migration. The page and the job both work
# before this has run; they then keep to the four older statistics.
class AddMetricsToStatCaches < ActiveRecord::Migration[8.1]
  def change
    add_column :stat_caches, :metrics, :jsonb
  end
end
