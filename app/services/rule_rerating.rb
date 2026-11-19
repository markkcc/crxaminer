# Rebuilds the verdict of stored scans from stored data, for when the rules
# change (ExtensionSecurityAnalyzer::RULES_VERSION). Used by
# `bin/rails rules:rerate`.
#
# For each scan it recomputes every rule finding from the stored manifest,
# and the overall finding from the access level, the stored listing details
# and the stored AI finding, which is kept exactly as stored (old-format AI
# findings included; they add nothing to trust). It needs
# no network and no API key, never calls the AI and never posts to X. It
# writes without touching updated_at, which the page shows as "last scanned"
# and which drives the 24-hour re-scan cache; a scan re-scanned while the
# task runs (updated_at changed) is left alone.
#
# Scans whose overall finding already carries the current rules version are
# not selected, so a run can be stopped and started again at any time.
class RuleRerating
  BATCH_SIZE = 200

  # Scans with a stored manifest whose overall finding does not carry the
  # current rules version.
  def self.candidates(after_id: nil, version: ExtensionSecurityAnalyzer::RULES_VERSION)
    scope = ScanResult
      .where("jsonb_typeof(manifest) = 'object' AND manifest <> '{}'::jsonb")
      .where(<<~SQL.squish, version.to_s)
        NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(security_findings) = 'array' THEN security_findings ELSE '[]'::jsonb END
          ) AS finding
          WHERE jsonb_typeof(finding) = 'object'
            AND lower(finding->>'title') LIKE '%overall risk%'
            AND finding->>'rules_version' = ?
        )
      SQL
    after_id ? scope.where("scan_results.id > ?", after_id) : scope
  end

  # changes: [overall level before, after] => count (the overall finding's severity).
  # display_changes: the same for the level shown in statistics (ScanDisplayLevel).
  Result = Struct.new(:eligible, :processed, :updated, :unchanged, :write_conflicts, :failed, :refused,
                      :last_id, :changes, :display_changes, keyword_init: true)

  # dry_run: compute and report, write nothing.
  # limit / all: a real run needs one of them, as a guard against a surprise
  #   rewrite of every stored scan.
  # after_id: resume after this scan id.
  def initialize(limit: nil, all: false, after_id: nil, dry_run: false, out: $stdout)
    @limit = limit
    @all = all
    @after_id = after_id
    @dry_run = dry_run
    @out = out
  end

  def run
    scope = self.class.candidates(after_id: @after_id)
    eligible = scope.count
    result = Result.new(eligible: eligible, processed: 0, updated: 0, unchanged: 0, write_conflicts: 0, failed: 0,
                        refused: false, last_id: nil, changes: Hash.new(0), display_changes: Hash.new(0))
    after = @after_id ? " after id #{@after_id}" : ""
    version = ExtensionSecurityAnalyzer::RULES_VERSION

    unless @dry_run || @limit || @all
      result.refused = true
      @out.puts "#{eligible} scan(s)#{after} are not rated with rules version #{version}. " \
                "Pass DRY_RUN=1 to preview, or LIMIT=n or ALL=1 to re-rate them."
      return result
    end

    @out.puts "#{@dry_run ? 'Dry run: ' : ''}#{eligible} scan(s)#{after} to re-rate with rules version #{version}" \
              "#{@limit ? "; this run processes up to #{@limit}" : ''}."

    scope.find_each(batch_size: BATCH_SIZE) do |scan|
      break if @limit && result.processed >= @limit

      result.processed += 1
      result.last_id = scan.id
      status, from, to, shown_from, shown_to = rerate(scan)
      result.changes[[from, to]] += 1 if from || to
      result.display_changes[[shown_from, shown_to]] += 1 if from || to
      case status
      when :updated then result.updated += 1
      when :unchanged then result.unchanged += 1
      when :write_conflict
        result.write_conflicts += 1
        @out.puts "Not saved #{scan.id} #{scan.extension_id}: the scan was re-scanned or removed meanwhile"
      else
        result.failed += 1
        @out.puts "Failed #{scan.id} #{scan.extension_id} (see log)"
      end
    end

    report(result)
    result
  end

  # The findings a scan would have after re-rating: the overall finding, the
  # current rule findings, then its stored AI finding(s), unchanged.
  def self.rerated_findings(manifest, stored_findings, extension_details = nil)
    ai = Array(stored_findings).select { |f| f.is_a?(Hash) && AiContextAnalysis.find_in([f]) }
    ExtensionSecurityAnalyzer.rated_findings(manifest, extension_details: extension_details, ai_findings: ai)
  end

  def self.display_level(findings)
    ScanDisplayLevel.for(findings) || "(none)"
  end

  def self.overall_level(findings)
    overall = Array(findings).find { |f| f.is_a?(Hash) && ScanPage::FindingGroups.overall?(f) }
    level = ScanPage.value(overall, :severity)
    level.is_a?(String) && !level.empty? ? level : "(none)"
  end

  private

  # Returns [status, old overall level, new overall level, old shown level, new shown level].
  def rerate(scan)
    # The columns as stored (string keys), so the AI finding is written back
    # exactly as it was and a junk row cannot break the run.
    stored = stored_json(scan, :security_findings)
    findings = self.class.rerated_findings(stored_json(scan, :manifest), stored, stored_json(scan, :extension_details))
    levels = [self.class.overall_level(stored), self.class.overall_level(findings),
              self.class.display_level(stored), self.class.display_level(findings)]
    return [:unchanged, *levels] if @dry_run

    saved = ScanResult.where(id: scan.id, updated_at: scan.updated_at)
                      .update_all(["security_findings = ?::jsonb", JSON.generate(findings)])
    [saved == 1 ? :updated : :write_conflict, *levels]
  rescue StandardError => e
    Rails.logger.error "Re-rating failed for #{scan.extension_id}: #{e.class}: #{e.message}"
    [:failed, nil, nil, nil, nil]
  end

  def stored_json(scan, column)
    value = scan.read_attribute_before_type_cast(column)
    value.is_a?(String) ? JSON.parse(value) : value
  end

  def report(result)
    print_changes("Overall level (the overall finding), before -> after:", result.changes)
    print_changes("Level shown in statistics and lists, before -> after:", result.display_changes)

    if @dry_run
      @out.puts "Dry run: #{result.processed} scan(s) computed, nothing was written."
    else
      @out.puts "Done: #{result.updated} re-rated, #{result.write_conflicts} not saved, #{result.failed} failed."
    end
    @out.puts "Last processed id: #{result.last_id} (continue with AFTER_ID=#{result.last_id})" if result.last_id
  end

  def print_changes(heading, changes)
    return if changes.empty?

    @out.puts
    @out.puts heading
    levels = ExtensionAnalyzerData::OVERALL_LEVELS
    order = ->(level) { levels.index(level) || levels.size }
    changes.sort_by { |(from, to), _| [order.call(from), order.call(to)] }.each do |(from, to), count|
      @out.puts format("  %-9s -> %-9s %6d", from, to, count)
    end
    @out.puts
  end
end
