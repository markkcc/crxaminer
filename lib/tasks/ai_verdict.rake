namespace :ai_verdict do
  desc "Re-run the AI context analysis for stored scans that have none. " \
       "ENV: DRY_RUN=1 (only count), LIMIT=n, PAUSE=seconds (default 2), MAX_FAILURES=n (default 3). Uses API tokens."
  task backfill: :environment do
    limit = ENV["LIMIT"].presence&.to_i
    abort "LIMIT must be a positive integer" if limit && limit <= 0

    result = AiVerdictBackfill.new(
      dry_run: %w[1 true yes].include?(ENV["DRY_RUN"].to_s.downcase),
      limit: limit,
      pause: (ENV["PAUSE"].presence || AiVerdictBackfill::DEFAULT_PAUSE_SECONDS).to_f,
      max_consecutive_failures: (ENV["MAX_FAILURES"].presence || AiVerdictBackfill::DEFAULT_MAX_CONSECUTIVE_FAILURES).to_i
    ).run

    puts "Run `RefreshStatsJob.perform_now` to refresh the stats page counts." if result.updated.positive?
    exit 1 if result.stopped_early
  end
end
