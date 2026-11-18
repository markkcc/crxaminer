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

    # Severities shown as a slim row that opens to the description, so that
    # routine findings (the rule engine rates every routine permission Low)
    # do not drown the ones that matter.
    QUIET = %w[low minimal info].freeze

    # One finding as shown in the note on one line. ref is its position in
    # the findings list, shared with the Overview's "Show line" button;
    # first_line is the lowest line the finding points at, where its full
    # note is shown.
    Note = Struct.new(:finding, :ref, :severity, :label, :line, :first_line, keyword_init: true) do
      def quiet?
        QUIET.include?(severity)
      end

      # The same finding on a later line: shown slim, pointing at first_line.
      def repeat?
        line != first_line
      end

      # Shown as a slim row that opens to the description.
      def slim?
        quiet? || repeat?
      end
    end

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
          lines = lines_for(finding)
          severity = self.class.severity_key(finding.severity)
          label = self.class.severity_label(finding.severity)
          lines.each do |line|
            map[line] << Note.new(finding: finding, ref: ref, severity: severity, label: label,
                                  line: line, first_line: lines.first)
          end
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

    # True when every note on the line is slim (quiet or a repeat), so the
    # line gets a slim note instead of a card.
    def slim?(line)
      notes = notes_for(line)
      notes.any? && notes.all?(&:slim?)
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
