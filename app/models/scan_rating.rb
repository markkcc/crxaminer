# The two ratings of a scan and the headline that combines them.
#
#   Access: what the extension could do if it turned malicious. It comes from
#           the manifest by fixed rules (ExtensionSecurityAnalyzer). Nothing
#           in the store listing and no AI reply can change it.
#   Trust:  evidence about who publishes it and how it is received: the store
#           listing's badges, users, ratings and update date. The AI check can
#           lower it (never raise it), so listing text cannot talk it up.
#   Overall: the two combined (OVERALL), with a short headline.
#
# Everything here is a pure function of stored scan data, so it can be shown
# for any scan and recomputed when the rules change. Listing data comes from
# untrusted pages and old scans lack most of it: any field can be missing or
# the wrong type, and nothing here raises on that.
class ScanRating
  AccessTier = Struct.new(:key, :level, :number, :name, :summary, keyword_init: true)
  TrustLevel = Struct.new(:key, :name, :summary, keyword_init: true)
  # tone: :good, :neutral, :caution or :bad (the colour of its badge).
  Signal = Struct.new(:key, :tone, :label, keyword_init: true)

  # Access tiers, most access first. `level` is the finding level that puts
  # an extension in the tier (ExtensionAnalyzerData::LEVELS), which is also
  # what findings store as `severity`.
  ACCESS_TIERS = [
    { key: "full_control", level: "Critical", number: 4, name: "Full control",
      summary: "It could take over accounts, traffic or other parts of the browser or computer." },
    { key: "broad_reach", level: "High", number: 3, name: "Broad reach",
      summary: "It could see or change a great deal of what you do in the browser." },
    { key: "scoped", level: "Medium", number: 2, name: "Scoped",
      summary: "It could reach particular data or sites, not everything." },
    { key: "routine", level: "Low", number: 1, name: "Routine",
      summary: "It only asks for things most extensions need." },
    { key: "minimal", level: "Minimal", number: 0, name: "Minimal",
      summary: "The rules found nothing to flag." }
  ].map { |attrs| AccessTier.new(**attrs).freeze }.freeze

  # Trust levels, most trust first.
  TRUST_LEVELS = [
    { key: "established", name: "Established",
      summary: "A recognised publisher or a large, long-standing user base." },
    { key: "some", name: "Some track record",
      summary: "Enough users and ratings, or a store badge, to show it is in real use." },
    { key: "unproven", name: "Unproven",
      summary: "Few users or ratings, or no listing data, so there is little to go on." },
    { key: "concerns", name: "Warning signs",
      summary: "Something about the listing or its stated purpose does not add up." }
  ].map { |attrs| TrustLevel.new(**attrs).freeze }.freeze

  # Overall level by access tier (rows) and trust level (columns, in the
  # order of TRUST_LEVELS). The levels reuse the five familiar names and
  # colours. More access or less trust never lowers the result.
  OVERALL = {
    "full_control" => %w[Medium High Critical Critical],
    "broad_reach"  => %w[Low Medium High Critical],
    "scoped"       => %w[Low Low Medium High],
    "routine"      => %w[Minimal Minimal Low Medium],
    "minimal"      => %w[Minimal Minimal Minimal Low]
  }.freeze

  ACCESS_WORDS = {
    "full_control" => "Very powerful", "broad_reach" => "Powerful", "scoped" => "Limited access",
    "routine" => "Routine access", "minimal" => "Minimal access"
  }.freeze
  TRUST_WORDS = {
    "established" => "established publisher", "some" => "some track record",
    "unproven" => "unproven publisher", "concerns" => "warning signs"
  }.freeze
  ADVICE = {
    "Critical" => "Avoid it unless you know exactly who publishes it and why it needs this much access.",
    "High" => "Install it only if you know and trust the publisher.",
    "Medium" => "Think about whether you need it and trust who makes it.",
    "Low" => "Little to worry about from what the manifest and the listing show.",
    "Minimal" => "Low stakes: it asks for very little."
  }.freeze

  # Thresholds for the listing signals.
  ESTABLISHED_USERS = 1_000_000
  ESTABLISHED_RATINGS = 1_000
  BADGE_USERS = 100_000
  TRACK_RECORD_USERS = 10_000
  TRACK_RECORD_RATINGS = 50
  FEW_USERS = 1_000
  STALE_AFTER_YEARS = 2

  # What the AI check may report (AiContextAnalysis). "some" lowers trust one
  # level; "serious" sets it to the lowest. Anything else changes nothing.
  CONCERN_LEVELS = %w[none some serious].freeze
  PURPOSE_FITS = %w[fits broader_than_needed does_not_fit].freeze

  attr_reader :access, :trust, :signals, :overall, :headline, :advice

  def self.access_tier(level)
    ACCESS_TIERS.find { |tier| tier.level == level.to_s.strip.capitalize } || ACCESS_TIERS.last
  end

  def self.trust_level(key)
    TRUST_LEVELS.find { |level| level.key == key.to_s }
  end

  # The rating for a stored scan: its access level is the one the rules
  # stored (the overall finding's :access, or its severity for scans rated
  # before the two ratings existed); trust is worked out from the stored
  # listing details and AI check.
  def self.for_scan(security_findings:, extension_details:, as_of: Time.current)
    findings = ScanPage.list(security_findings).select { |f| f.is_a?(Hash) }
    ai = findings.find { |f| ScanPage::FindingGroups.ai?(f) }
    new(access_level: stored_access_level(findings), extension_details: extension_details,
        ai: ScanPage.value(ai, :ai), as_of: as_of)
  end

  # The access level a stored scan carries (see .for_scan), as stored: pass
  # it to .access_tier for the tier. nil when the scan has no overall finding.
  def self.stored_access_level(security_findings)
    overall = ScanPage.list(security_findings).find { |f| f.is_a?(Hash) && ScanPage::FindingGroups.overall?(f) }
    ScanPage.value(overall, :access) || ScanPage.value(overall, :severity)
  end

  # access_level: a finding level ("High") or nil. ai: the stored AI check
  # (a hash that may carry :concern_level and :purpose_fit) or nil.
  def initialize(access_level:, extension_details:, ai: nil, as_of: Time.current)
    @details = extension_details.is_a?(Hash) ? extension_details : {}
    @ai = ai.is_a?(Hash) ? ai : {}
    @as_of = as_of
    @access = self.class.access_tier(access_level)
    @signals = listing_signals + ai_signals
    @trust = TRUST_LEVELS[trust_index]
    @overall = OVERALL.fetch(@access.key)[trust_index]
    @headline = "#{ACCESS_WORDS.fetch(@access.key)}, #{TRUST_WORDS.fetch(@trust.key)}"
    @advice = ADVICE.fetch(@overall)
  end

  # What gets stored on the overall finding, next to :severity (the overall level).
  def to_stored
    { access: access.level, trust: trust.key, headline: headline }
  end

  def users
    @users ||= self.class.count(ScanPage.value(@details, :users))
  end

  def rating_count
    @rating_count ||= self.class.count(ScanPage.value(@details, :rating_count))
  end

  def rating
    value = ScanPage.value(@details, :rating)
    number = Float(value.to_s.strip, exception: false) if value.is_a?(String) || value.is_a?(Numeric)
    number if number && number.between?(0, 5)
  end

  def last_updated
    value = ScanPage.value(@details, :last_updated)
    return nil unless value.is_a?(String) && value.match?(/\d{4}/)

    Date.parse(value)
  rescue ArgumentError, RangeError
    nil
  end

  def established_publisher?
    ScanPage.value(@details, :established_publisher) == true
  end

  def featured?
    ScanPage.value(@details, :featured) == true
  end

  def concern_level
    value = ScanPage.value(@ai, :concern_level)
    CONCERN_LEVELS.include?(value) ? value : nil
  end

  def purpose_fit
    value = ScanPage.value(@ai, :purpose_fit)
    PURPOSE_FITS.include?(value) ? value : nil
  end

  # "39,000,000", "10,000+", "44.7K ratings", "1.2M" -> an integer; anything
  # else (nil, "Share", junk) -> nil.
  def self.count(value)
    return value if value.is_a?(Integer) && value >= 0
    return nil unless value.is_a?(String)

    match = value.strip.match(/\A(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s*([KMB])?\b/i)
    return nil unless match

    number = match[1].delete(",").to_f
    number *= { "K" => 1_000, "M" => 1_000_000, "B" => 1_000_000_000 }.fetch(match[2].to_s.upcase, 1)
    number.round
  end

  private

  # 0 (established) to 3 (warning signs): the listing sets the starting
  # point and the AI check can only move it down.
  def trust_index
    @trust_index ||= begin
      base = listing_index
      case concern_level
      when "serious" then TRUST_LEVELS.size - 1
      when "some" then [base + 1, TRUST_LEVELS.size - 1].min
      else base
      end
    end
  end

  def listing_index
    u = users.to_i
    r = rating_count.to_i
    if (established_publisher? && u >= BADGE_USERS) || (u >= ESTABLISHED_USERS && r >= ESTABLISHED_RATINGS)
      0
    elsif established_publisher? || featured? || (u >= TRACK_RECORD_USERS && r >= TRACK_RECORD_RATINGS)
      1
    else
      2
    end
  end

  def listing_signals
    signals = []
    signals << signal(:established_publisher, :good, "Established publisher badge") if established_publisher?
    signals << signal(:featured, :good, "Featured by the Chrome Web Store") if featured?
    signals << users_signal
    signals << ratings_signal
    signals << rating_signal
    signals << updated_signal
    signals.compact!
    signals << signal(:no_listing, :caution, "No store listing data") if signals.empty?
    signals
  end

  def users_signal
    return nil unless users

    label = "#{ActiveSupport::NumberHelper.number_to_delimited(users)} users"
    if users >= BADGE_USERS then signal(:users, :good, label)
    elsif users >= FEW_USERS then signal(:users, :neutral, label)
    else signal(:users, :caution, "Fewer than #{ActiveSupport::NumberHelper.number_to_delimited(FEW_USERS)} users")
    end
  end

  def ratings_signal
    return nil unless rating_count

    label = "#{ActiveSupport::NumberHelper.number_to_delimited(rating_count)} #{rating_count == 1 ? 'rating' : 'ratings'}"
    if rating_count >= ESTABLISHED_RATINGS then signal(:rating_count, :good, label)
    elsif rating_count >= TRACK_RECORD_RATINGS then signal(:rating_count, :neutral, label)
    else signal(:rating_count, :caution, "Only #{label}")
    end
  end

  # A low rating says people dislike the extension, not that its publisher
  # is untrustworthy, so it is shown as a caution and does not change the level.
  def rating_signal
    return nil unless rating && rating_count.to_i >= TRACK_RECORD_RATINGS

    signal(:rating, rating < 3 ? :caution : :neutral, "Rated #{format('%.1f', rating)} of 5")
  end

  def updated_signal
    date = last_updated
    return nil unless date

    if date < @as_of.to_date.prev_year(STALE_AFTER_YEARS)
      signal(:last_updated, :caution, "Not updated since #{date.strftime('%B %Y')}")
    else
      signal(:last_updated, :neutral, "Updated #{date.strftime('%B %-d, %Y')}")
    end
  end

  def ai_signals
    signals = []
    case purpose_fit
    when "fits" then signals << signal(:purpose_fit, :good, "Permissions fit its stated purpose (AI check)")
    when "broader_than_needed" then signals << signal(:purpose_fit, :caution, "Asks for more than its stated purpose needs (AI check)")
    when "does_not_fit" then signals << signal(:purpose_fit, :bad, "Permissions do not fit its stated purpose (AI check)")
    end
    case concern_level
    when "some" then signals << signal(:concern_level, :caution, "The AI check raised concerns")
    when "serious" then signals << signal(:concern_level, :bad, "The AI check found serious warning signs")
    end
    signals
  end

  def signal(key, tone, label)
    Signal.new(key: key, tone: tone, label: label)
  end
end
