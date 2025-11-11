class AddNewMetricsToStatCaches < ActiveRecord::Migration[8.0]
  def change
    add_column :stat_caches, :scans_last_30_days, :integer
    add_column :stat_caches, :all_urls_count, :integer
  end
end
