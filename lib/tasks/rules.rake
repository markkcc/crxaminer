namespace :rules do
  desc "Re-rate stored scans with the current rules: rule findings from the stored manifest, and the overall " \
       "verdict from them, the stored listing details and the stored AI finding (kept as it is). " \
       "No network, no API calls, no tweets; updated_at is kept. " \
       "ENV: DRY_RUN=1 (compute and show how overall and shown levels would change, write nothing), " \
       "LIMIT=n or ALL=1 (required for a real run), AFTER_ID=id (resume after this scan id)."
  task rerate: :environment do
    limit = ENV["LIMIT"].presence&.to_i
    abort "LIMIT must be a positive integer" if limit && limit <= 0
    after_id = ENV["AFTER_ID"].presence&.to_i
    abort "AFTER_ID must be a positive integer" if after_id && after_id <= 0

    result = RuleRerating.new(
      dry_run: %w[1 true yes].include?(ENV["DRY_RUN"].to_s.downcase),
      all: %w[1 true yes].include?(ENV["ALL"].to_s.downcase),
      limit: limit,
      after_id: after_id
    ).run

    puts "Run `RefreshStatsJob.perform_now` to refresh the stats page counts." if result.updated.positive?
    exit 1 if result.refused || result.failed.positive?
  end
end
