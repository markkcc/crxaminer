# Re-runs the AI context analysis for stored scans that have none.
# Used by `bin/rails ai_verdict:backfill`. Never posts to X, and writes with
# update_columns so updated_at ("last scanned") is left unchanged.
#
# The AI check is given the rule findings and access tier of the current
# rules, as on a fresh scan, and the scan's whole verdict is then rebuilt
# from stored data with the new AI finding (ExtensionSecurityAnalyzer.rated_findings),
# so its overall finding reflects the check and the current rules version.
#
# Failures specific to one scan (refusal, max_tokens, invalid output, a 400
# for that input) are reported and skipped. Systemic failures (missing key,
# 401/403, 404, 429, 5xx, connection errors and timeouts) stop the run after
# max_consecutive_failures in a row.
class AiVerdictBackfill
  DEFAULT_PAUSE_SECONDS = 2.0
  DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
  BATCH_SIZE = 25

  # Scans with a manifest and findings but no "AI Context Analysis" finding.
  def self.candidates(after_id: nil)
    scope = ScanResult
      .where("CASE WHEN jsonb_typeof(security_findings) = 'array' THEN jsonb_array_length(security_findings) > 0 ELSE false END")
      .where("jsonb_typeof(manifest) = 'object' AND manifest <> '{}'::jsonb")
      .where(<<~SQL.squish, AiContextAnalysis::TITLE, AiContextAnalysis::SEVERITY)
        NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(security_findings) = 'array' THEN security_findings ELSE '[]'::jsonb END
          ) AS finding
          WHERE finding->>'title' = ? AND finding->>'severity' = ?
        )
      SQL
    after_id ? scope.where("scan_results.id > ?", after_id) : scope
  end

  Result = Struct.new(:eligible, :attempted, :updated, :skipped, :write_conflicts, :stopped_early, :refused,
                      :last_id, :input_tokens, :output_tokens, keyword_init: true)

  def initialize(limit: nil, all: false, after_id: nil, pause: DEFAULT_PAUSE_SECONDS,
                 max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
                 dry_run: false, client: :default, out: $stdout, sleeper: ->(seconds) { sleep(seconds) })
    @limit = limit
    @all = all
    @after_id = after_id
    @pause = pause.to_f
    @max_consecutive_failures = [max_consecutive_failures.to_i, 1].max
    @dry_run = dry_run
    @client = client
    @out = out
    @sleeper = sleeper
  end

  def run
    scope = self.class.candidates(after_id: @after_id)
    eligible = scope.count
    result = Result.new(eligible: eligible, attempted: 0, updated: 0, skipped: 0, write_conflicts: 0,
                        stopped_early: false, refused: false, last_id: nil, input_tokens: 0, output_tokens: 0)
    after = @after_id ? " after id #{@after_id}" : ""

    if @dry_run
      @out.puts "Dry run: #{eligible} scan(s)#{after} have no AI analysis#{@limit ? "; this run would process up to #{@limit}" : ''}."
      return result
    end

    unless @limit || @all
      result.refused = true
      @out.puts "Refusing to run: this calls the paid API for up to #{eligible} scan(s). Pass LIMIT=n, or ALL=1 to process all of them."
      return result
    end

    if @client == :default && !AiContextAnalysis.configured?
      @out.puts "ANTHROPIC_API_KEY is not set; nothing was done."
      return result
    end

    consecutive_systemic = 0
    processed = 0
    scope.find_each(batch_size: BATCH_SIZE) do |scan|
      break if @limit && processed >= @limit

      @sleeper.call(@pause) if processed.positive? && @pause.positive?
      processed += 1
      result.attempted += 1
      result.last_id = scan.id

      analysis, status = backfill(scan)
      if analysis&.usage
        result.input_tokens += analysis.usage[:input_tokens].to_i
        result.output_tokens += analysis.usage[:output_tokens].to_i
      end

      case status
      when :updated
        result.updated += 1
        consecutive_systemic = 0
        @out.puts "Updated #{scan.id} #{scan.extension_id}"
      when :write_conflict
        result.write_conflicts += 1
        consecutive_systemic = 0
        @out.puts "Not saved #{scan.id} #{scan.extension_id}: the scan was replaced or removed meanwhile"
      when :systemic
        result.skipped += 1
        consecutive_systemic += 1
        @out.puts "Failed #{scan.id} #{scan.extension_id}: #{analysis&.outcome} (see log)"
        if consecutive_systemic >= @max_consecutive_failures
          result.stopped_early = true
          @out.puts "Stopping after #{consecutive_systemic} consecutive systemic failures (#{analysis&.outcome})."
          break
        end
      else
        result.skipped += 1
        consecutive_systemic = 0
        @out.puts "Skipped #{scan.id} #{scan.extension_id}: #{analysis&.outcome || 'error'} (see log)"
      end
    end

    @out.puts "Done: #{result.updated} updated, #{result.skipped} skipped or failed, #{result.write_conflicts} not saved. " \
              "Tokens used: #{result.input_tokens} input, #{result.output_tokens} output."
    if result.last_id
      @out.puts "Last processed id: #{result.last_id} (continue with AFTER_ID=#{result.last_id})"
    end
    result
  end

  private

  # Returns [analysis, :updated | :write_conflict | :systemic | :skipped].
  def backfill(scan)
    rules = ExtensionSecurityAnalyzer.new(scan.manifest)
    analysis = AiContextAnalysis.new(
      manifest: scan.manifest,
      extension_details: scan.extension_details,
      extension_name: scan.extension_name,
      findings: rules.rule_findings.drop(1),
      access: ScanRating.access_tier(rules.access_level).name,
      client: @client,
      data_captured_at: scan.updated_at
    )
    finding = analysis.call
    return [analysis, analysis.failed_systemically? ? :systemic : :skipped] unless finding

    findings = ExtensionSecurityAnalyzer.rated_findings(scan.manifest, extension_details: scan.extension_details,
                                                        ai_findings: [finding])
    saved = scan.update_columns(security_findings: findings)
    [analysis, saved ? :updated : :write_conflict]
  rescue ActiveRecord::ActiveRecordError => e
    Rails.logger.error "AI backfill could not save #{scan.extension_id}: #{e.class}: #{e.message}"
    [analysis, :write_conflict]
  rescue StandardError => e
    Rails.logger.error "AI backfill failed for #{scan.extension_id}: #{e.class}: #{e.message}"
    [analysis, :skipped]
  end
end
