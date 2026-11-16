module ScanHelper
  # Background and text classes for a severity level ("high", "High", :high...).
  # Used for the verdict banner, finding chips, stats chips and bars, and the
  # Secure Annex count cards, so every place shows the same colours.
  def severity_classes(severity)
    ExtensionAnalyzerData::SEVERITY_COLORS.fetch(severity.to_s.strip.capitalize) do
      ExtensionAnalyzerData::SEVERITY_FALLBACK_COLOR
    end
  end
end
