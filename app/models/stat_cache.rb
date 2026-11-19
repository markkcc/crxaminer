# The statistics page's numbers, saved by RefreshStatsJob: one row, replaced
# on every run (see ScanStats).
class StatCache < ApplicationRecord
  # The row the page shows.
  def self.current
    order(id: :desc).first
  end

  # False until the migration that adds `metrics` has run.
  def self.metrics_column?
    column_names.include?("metrics")
  end

  # Saves a new row and removes the others in one transaction, so a reader
  # always finds exactly one.
  def self.replace!(attributes)
    transaction do
      record = create!(attributes)
      where.not(id: record.id).delete_all
      record
    end
  end

  # The newer statistics as a hash; {} when there are none. A server that
  # started before the column was added has no type for it and reads it as
  # JSON text, so that is parsed here.
  def stored_metrics
    value = has_attribute?(:metrics) ? self[:metrics] : nil
    value = JSON.parse(value) if value.is_a?(String)
    value.is_a?(Hash) ? value : {}
  rescue JSON::ParserError
    {}
  end

  # True when the column exists but this row was saved before it did.
  def awaiting_metrics?
    has_attribute?(:metrics) && self[:metrics].nil?
  end
end
