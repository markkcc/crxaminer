module ScanPage
  # The stored AI finding ("AI Context Analysis") as the scan page shows it,
  # whatever format it was stored in:
  #
  #   :current  an `ai` hash with concern_level and purpose_fit. This is the
  #             AI check that feeds trust (see ScanRating).
  #   :earlier  an `ai` hash with its own risk_level (an older format).
  #   :earliest only a description: "Risk Level: X", then text with
  #             "Trust Factors:", "Concerns:" and "Recommendations:" headings
  #             and "- " items.
  #
  # The two older formats rated the extension themselves; that level is
  # shown as history only and never feeds the page's rating. Every value
  # here comes from stored data of any shape, so everything is read
  # defensively and returned as plain strings for the view to escape.
  class AiCheck
    LISTS = { trust_factors: "Trust factors", concerns: "Concerns", recommendations: "Recommendations" }.freeze
    HEADINGS = LISTS.to_h { |key, name| ["#{name.downcase}:", key] }.freeze
    LEVELS = ExtensionAnalyzerData::OVERALL_LEVELS

    # How the view words purpose_fit and concern_level, with the tone of their badge.
    PURPOSE_FITS = {
      "fits" => [:good, "Fits its stated purpose"],
      "broader_than_needed" => [:caution, "Broader than its purpose needs"],
      "does_not_fit" => [:bad, "Does not fit its stated purpose"]
    }.freeze
    CONCERN_LEVELS = {
      "none" => [:good, "No concerns"],
      "some" => [:caution, "Some concerns"],
      "serious" => [:bad, "Serious concerns"]
    }.freeze

    # The AI finding of a scan, or nil when it has none.
    def self.for(security_findings)
      finding = ScanPage.list(security_findings).find { |f| f.is_a?(Hash) && FindingGroups.ai?(f) }
      finding && new(finding)
    end

    attr_reader :format

    def initialize(finding)
      @finding = finding
      @ai = ScanPage.value(finding, :ai)
      @format =
        if !@ai.is_a?(Hash) then :earliest
        elsif @ai.key?(:risk_level) || @ai.key?("risk_level") then :earlier
        else :current
        end
      parse_description if @format == :earliest
    end

    def current?
      format == :current
    end

    # [tone, label] for the current format's purpose fit and concern level, or nil.
    def purpose_fit
      current? ? PURPOSE_FITS[ScanPage.value(@ai, :purpose_fit)] : nil
    end

    def concern_level
      current? ? CONCERN_LEVELS[ScanPage.value(@ai, :concern_level)] : nil
    end

    # The level an older format gave the extension ("Low"), or nil when it
    # is missing or not a known level.
    def earlier_level
      return nil if current?

      raw = @format == :earlier ? ScanPage.value(@ai, :risk_level) : @earliest_level
      level = raw.is_a?(String) ? raw.strip.capitalize : nil
      LEVELS.include?(level) ? level : nil
    end

    # Paragraphs of summary text.
    def summary
      return @earliest_summary if @format == :earliest

      text = ScanPage.value(@ai, :summary)
      text.is_a?(String) && text.strip.present? ? [text.strip] : []
    end

    # { trust_factors: [...], concerns: [...], recommendations: [...] }, empty lists left out.
    def lists
      @lists ||= begin
        all = if @format == :earliest
          @earliest_lists
        else
          LISTS.keys.to_h { |key| [key, ScanPage.strings(ScanPage.value(@ai, key)).map(&:strip).reject(&:empty?)] }
        end
        all.reject { |_, items| items.empty? }
      end
    end

    def model
      value = ScanPage.value(@ai, :model)
      value.is_a?(String) && value.strip.present? ? value.strip : nil
    end

    def analyzed_at
      value = ScanPage.value(@ai, :analyzed_at)
      value.is_a?(String) ? Time.zone.parse(value) : nil
    rescue ArgumentError, RangeError
      nil
    end

    # True when the earliest format has a model line to show (it has none).
    def byline?
      @format != :earliest
    end

    private

    def parse_description
      @earliest_summary = []
      @earliest_lists = LISTS.keys.to_h { |key| [key, []] }
      current = nil
      ScanPage.text(ScanPage.value(@finding, :description) || "").split("\n").each_with_index do |raw, index|
        line = raw.strip
        next if line.empty?

        if index.zero? && line.start_with?("Risk Level:")
          @earliest_level = line.delete_prefix("Risk Level:").strip
        elsif (key = HEADINGS[line.downcase])
          current = key
        elsif line.start_with?("- ") && current
          @earliest_lists[current] << line.delete_prefix("- ").strip
        else
          @earliest_summary << line
        end
      end
    end
  end
end
