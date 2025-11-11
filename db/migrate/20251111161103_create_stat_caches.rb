class CreateStatCaches < ActiveRecord::Migration[8.0]
  def change
    create_table :stat_caches do |t|
      t.jsonb :severity_counts
      t.jsonb :spiciest_extensions

      t.timestamps
    end
  end
end
