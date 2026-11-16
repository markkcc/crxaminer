# Re-runs the AI context analysis for stored scans that have none.
# Used by `bin/rails ai_verdict:backfill`. Never posts to X, and writes with
# update_columns so updated_at ("last scanned") is left unchanged.
class AiVerdictBackfill
  DEFAULT_PAUSE_SECONDS = 2.0
  DEFAULT_MAX_CONSECUTIVE_FAILURES = 3

  # Scans with a manifest and findings but no "AI Context Analysis" finding.
  def self.candidates
    ScanResult
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
  end

  Result = Struct.new(:eligible, :attempted, :updated, :failed, :stopped_early, keyword_init: true)

  def initialize(limit: nil, pause: DEFAULT_PAUSE_SECONDS, max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
                 dry_run: false, client: :default, out: $stdout, sleeper: ->(seconds) { sleep(seconds) })
    @limit = limit
    @pause = pause.to_f
    @max_consecutive_failures = [max_consecutive_failures.to_i, 1].max
    @dry_run = dry_run
    @client = client
    @out = out
    @sleeper = sleeper
  end

  def run
    scope = self.class.candidates
    eligible = scope.count
    scope = scope.limit(@limit) if @limit
    result = Result.new(eligible: eligible, attempted: 0, updated: 0, failed: 0, stopped_early: false)

    if @dry_run
      @out.puts "Dry run: #{eligible} scan(s) have no AI analysis#{@limit ? "; this run would process up to #{@limit}" : ''}."
      return result
    end

    if @client == :default && !AiContextAnalysis.configured?
      @out.puts "ANTHROPIC_API_KEY is not set; nothing was done."
      return result
    end

    consecutive_failures = 0
    scope.find_each.with_index do |scan, index|
      @sleeper.call(@pause) if index.positive? && @pause.positive?
      result.attempted += 1

      if backfill(scan)
        result.updated += 1
        consecutive_failures = 0
        @out.puts "Updated #{scan.extension_id}"
      else
        result.failed += 1
        consecutive_failures += 1
        @out.puts "Failed #{scan.extension_id} (see log)"
        if consecutive_failures >= @max_consecutive_failures
          result.stopped_early = true
          @out.puts "Stopping after #{consecutive_failures} consecutive failures."
          break
        end
      end
    end

    @out.puts "Done: #{result.updated} updated, #{result.failed} failed, #{eligible - result.updated} still without AI analysis."
    result
  end

  private

  def backfill(scan)
    findings = scan.security_findings || []
    finding = AiContextAnalysis.new(
      manifest: scan.manifest,
      extension_details: scan.extension_details,
      extension_name: scan.extension_name,
      findings: findings,
      client: @client
    ).call
    return false unless finding

    scan.update_columns(security_findings: findings + [finding])
    true
  rescue StandardError => e
    Rails.logger.error "AI backfill failed for #{scan.extension_id}: #{e.class}: #{e.message}"
    false
  end
end
