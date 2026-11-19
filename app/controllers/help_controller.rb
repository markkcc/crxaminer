# The "how it works" page linked from the main navigation.
class HelpController < ApplicationController
  WRITE_UP_URL = "https://astarte.security/docs/tools/crxaminer".freeze

  # One access tier and what puts an extension in it: the rules and the
  # permissions at its finding level.
  Tier = Struct.new(:tier, :rules, :permissions, keyword_init: true) do
    def level
      tier.level
    end
  end

  # One trust level and the listing evidence that leads to it.
  Trust = Struct.new(:level, :evidence, keyword_init: true)

  # Everything is built from the rule engine's data and ScanRating, so the
  # page always matches what they do. Optional items are explained in one
  # sentence on the page instead of being listed again.
  def show
    data = ExtensionAnalyzerData
    permissions = data.permissions_by_level
    @tiers = ScanRating::ACCESS_TIERS.map do |tier|
      rules = data.rules.select { |rule| rule.severity == tier.level && !rule.id.start_with?("optional.") }
      Tier.new(tier: tier, rules: rules, permissions: permissions.fetch(tier.level, []))
    end
    @trust_levels = ScanRating::TRUST_LEVELS.map { |level| Trust.new(level: level, evidence: trust_evidence(level.key)) }
    # Rows are access tiers, columns trust levels: [[tier, [overall, ...]], ...].
    @grid = ScanRating::ACCESS_TIERS.map { |tier| [tier, ScanRating::OVERALL.fetch(tier.key)] }
  end

  private

  # What in the listing (or the AI check) leads to each trust level, with
  # the thresholds ScanRating uses.
  def trust_evidence(key)
    r = ScanRating
    n = ->(number) { ActiveSupport::NumberHelper.number_to_delimited(number) }
    case key
    when "established"
      "The store's Established publisher badge and #{n[r::BADGE_USERS]} users or more, " \
        "or #{n[r::ESTABLISHED_USERS]} users and #{n[r::ESTABLISHED_RATINGS]} ratings or more."
    when "some"
      "The Established publisher or Featured badge, or #{n[r::TRACK_RECORD_USERS]} users and #{n[r::TRACK_RECORD_RATINGS]} ratings or more."
    when "unproven"
      "Less than that, or no listing data."
    when "concerns"
      "The AI check found serious warning signs, or raised concerns about an extension that was already unproven."
    end
  end
end
