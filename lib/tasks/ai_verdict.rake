namespace :ai_verdict do
  desc "Re-run the AI context analysis for stored scans that have none (uses paid API tokens). " \
       "ENV: DRY_RUN=1 (only count), LIMIT=n or ALL=1 (required for a real run), AFTER_ID=id (resume), " \
       "PAUSE=seconds (default 2), MAX_FAILURES=n (consecutive systemic failures before stopping, default 3)."
  task backfill: :environment do
    limit = ENV["LIMIT"].presence&.to_i
    abort "LIMIT must be a positive integer" if limit && limit <= 0
    after_id = ENV["AFTER_ID"].presence&.to_i
    abort "AFTER_ID must be a positive integer" if after_id && after_id <= 0

    result = AiVerdictBackfill.new(
      dry_run: %w[1 true yes].include?(ENV["DRY_RUN"].to_s.downcase),
      all: %w[1 true yes].include?(ENV["ALL"].to_s.downcase),
      limit: limit,
      after_id: after_id,
      pause: (ENV["PAUSE"].presence || AiVerdictBackfill::DEFAULT_PAUSE_SECONDS).to_f,
      max_consecutive_failures: (ENV["MAX_FAILURES"].presence || AiVerdictBackfill::DEFAULT_MAX_CONSECUTIVE_FAILURES).to_i
    ).run

    puts "Run `RefreshStatsJob.perform_now` to refresh the stats page counts." if result.updated.positive?
    exit 1 if result.stopped_early || result.refused
  end
end
