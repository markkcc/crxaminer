module ScanPage
  # Which manifest lines each rule finding points at, and the notes the
  # Manifest tab shows under those lines.
  #
  # A finding written with evidence (manifest paths, see
  # FindingGroups::Finding) points at the line of each path, or at its
  # nearest existing parent when a path no longer resolves. A finding without
  # evidence (every scan stored by the older rule engine) is placed from its
  # title by ManifestDocument#legacy_lines_for. Nothing here raises on junk.
  class ManifestNotes
    # Severity keys in display order; anything else is "unrated".
    SEVERITIES = ExtensionAnalyzerData::SEVERITY_ORDER.sort_by(&:last).map(&:first).freeze

    # One finding as shown in a note. ref is its position in the findings
    # list, shared with the Overview's "Show line" button.
    Note = Struct.new(:finding, :ref, :severity, :label, keyword_init: true)

    def initialize(document, findings)
      @document = document
      @findings = Array(findings)
    end

    # Line numbers for one finding, ascending and without repeats.
    def lines_for(finding)
      lines_by_finding.fetch(finding, [])
    end

    # Position of a finding in the list, as used by data-manifest-finding.
    def ref_for(finding)
      refs[finding]
    end

    # Line number => notes for that line, most severe first.
    def by_line
      @by_line ||= begin
        map = Hash.new { |h, k| h[k] = [] }
        @findings.each_with_index do |finding, ref|
          note = Note.new(finding: finding, ref: ref, severity: self.class.severity_key(finding.severity),
                          label: self.class.severity_label(finding.severity))
          lines_for(finding).each { |line| map[line] << note }
        end
        map.transform_values { |notes| notes.sort_by.with_index { |n, i| [SEVERITIES.index(n.severity) || SEVERITIES.size, i] } }
           .sort.to_h
      end
    end

    def notes_for(line)
      by_line.fetch(line, [])
    end

    # The most severe severity key on a line, or nil when it has no notes.
    def severity_of(line)
      notes_for(line).first&.severity
    end

    def lines
      by_line.keys
    end

    def any?
      by_line.any?
    end

    def findings?
      @findings.any?
    end

    # Findings that point at no line at all.
    def unplaced_count
      @findings.count { |f| lines_for(f).empty? }
    end

    # Annotated lines counted by their most severe note, in severity order:
    # [["high", 2], ["medium", 4]].
    def line_counts
      counts = by_line.values.map { |notes| notes.first.severity }.tally
      (SEVERITIES + ["unrated"]).filter_map { |key| [key, counts[key]] if counts[key] }
    end

    def self.severity_key(severity)
      key = severity.to_s.strip.downcase
      SEVERITIES.include?(key) ? key : "unrated"
    end

    LABEL_MAX = 20

    # Known severities read as "High"; anything else is shown as stored
    # (escaped by the view, cut to LABEL_MAX characters), or "Unrated" when
    # blank.
    def self.severity_label(severity)
      text = ScanPage.text(severity).strip
      return "Unrated" if text.empty? || severity.nil?
      return text.capitalize if SEVERITIES.include?(text.downcase)

      text.length > LABEL_MAX ? "#{text[0, LABEL_MAX - 1]}…" : text
    end

    private

    def refs
      @refs ||= @findings.each_with_index.with_object({}.compare_by_identity) { |(f, i), map| map[f] ||= i }
    end

    def lines_by_finding
      @lines_by_finding ||= @findings.each_with_object({}.compare_by_identity) do |finding, map|
        map[finding] = place(finding)
      end
    end

    def place(finding)
      return [] if @document.empty?

      evidence = Array(finding.evidence)
      lines = evidence.filter_map { |path| @document.resolve(path) }
      lines = @document.legacy_lines_for(finding.title) if lines.empty?
      lines.uniq.sort
    rescue StandardError
      []
    end
  end
end
