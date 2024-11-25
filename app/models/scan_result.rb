class ScanResult < ApplicationRecord
  validates :extension_id, presence: true, uniqueness: true
  validates :extension_id, format: { with: /\A[a-zA-Z0-9]{32}\z/, message: "must be 32 characters of letters and numbers" }

  # Serialize JSONB columns with symbol keys
  def manifest
    super&.deep_symbolize_keys
  end

  def extension_details
    super&.deep_symbolize_keys
  end

  def security_findings
    super&.map(&:deep_symbolize_keys)
  end
end
