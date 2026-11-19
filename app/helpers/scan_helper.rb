module ScanHelper
  # Background and text classes for a severity level ("high", "High", :high...).
  # Used for the verdict banner, finding chips, stats chips and bars, and the
  # Secure Annex count cards, so every place shows the same colours.
  def severity_classes(severity)
    ExtensionAnalyzerData::SEVERITY_COLORS.fetch(severity.to_s.strip.capitalize) do
      ExtensionAnalyzerData::SEVERITY_FALLBACK_COLOR
    end
  end

  # Icon shapes (16 by 16, drawn with the text colour) for the AI check's lists.
  AI_LIST_ICONS = {
    trust_factors: ["M8 1.75 2.75 3.75v3.6c0 3.1 2.2 5.6 5.25 6.9 3.05-1.3 5.25-3.8 5.25-6.9v-3.6z", "m5.7 7.9 1.6 1.6 2.9-3.2"],
    concerns: ["M8 1.9 1.4 13.6h13.2z", "M8 6.4v3.2M8 11.6v.01"],
    recommendations: ["M6 12.5h4M6.5 14.5h3", "M8 1.75a4.25 4.25 0 0 0-2.5 7.7c.4.3.6.7.6 1.2v.35h3.8v-.35c0-.5.2-.9.6-1.2A4.25 4.25 0 0 0 8 1.75z"]
  }.freeze

  # The tone (application.css, ".ai-list") and icon of each AI check list:
  # good for trust factors, caution for concerns, brand for recommendations.
  AI_LIST_TONES = { trust_factors: "good", concerns: "caution", recommendations: "brand" }.freeze

  def ai_list_looks
    AI_LIST_TONES.to_h do |key, tone|
      icon = tag.svg(viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", "stroke-width": 1.6,
                     "stroke-linecap": "round", "stroke-linejoin": "round", focusable: "false") do
        safe_join(AI_LIST_ICONS.fetch(key).map { |d| tag.path(d: d) })
      end
      [key, [tone, icon]]
    end
  end
end
