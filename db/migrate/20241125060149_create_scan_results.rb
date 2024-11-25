class CreateScanResults < ActiveRecord::Migration[8.0]
  def change
    create_table :scan_results do |t|
      t.string :extension_id, null: false, index: { unique: true }
      t.string :extension_name
      t.string :extension_image
      t.jsonb :manifest, default: {}
      t.jsonb :extension_details, default: {}
      t.jsonb :security_findings, default: []
      t.timestamps
    end
  end
end 
