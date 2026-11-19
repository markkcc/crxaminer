# The badges that show a scan's ratings, defined once and used on every page:
#
#   overall_badge("High")          the bottom line, in the severity colours
#   access_badge("High")           an access tier ("Broad reach") with a
#                                  four-step meter, in its level's colour
#   finding_badge(finding.severity) the same for one finding; unknown levels
#                                  get a neutral badge with the stored text
#   trust_badge(rating.trust)      a trust level, in its own tinted palette
#   signal_chip(signal)            one piece of trust evidence, by tone
#   tone_chip(:caution, "text")    the same chip for any tone and text
#
# Every badge carries its meaning as text; icons and the meter are
# decoration (aria-hidden). Text is always escaped: stored levels and labels
# can be anything. The look lives in application.css (".badge").
module RatingBadgesHelper
  SIZES = %i[sm md lg].freeze
  TONES = %i[good neutral caution bad].freeze

  # Icon shapes on a 16 by 16 grid, drawn with the text colour.
  SHIELD = "M8 1.75 2.75 3.75v3.6c0 3.1 2.2 5.6 5.25 6.9 3.05-1.3 5.25-3.8 5.25-6.9v-3.6z".freeze
  CIRCLE = [:circle, { cx: 8, cy: 8, r: 6.25 }].freeze
  ICONS = {
    alert_triangle: [[:path, { d: "M8 1.9 1.4 13.6h13.2z" }], [:path, { d: "M8 6.4v3.2M8 11.6v.01" }]],
    alert_circle: [CIRCLE, [:path, { d: "M8 4.9v3.6M8 11v.01" }]],
    check_circle: [CIRCLE, [:path, { d: "m5.4 8.2 1.8 1.8 3.4-3.8" }]],
    shield_check: [[:path, { d: SHIELD }], [:path, { d: "m5.7 7.9 1.6 1.6 2.9-3.2" }]],
    shield_half: [[:path, { d: SHIELD }], [:path, { d: "M8 1.75v12.25c3.05-1.3 5.25-3.8 5.25-6.9v-3.6z", fill: "currentColor" }]],
    question: [CIRCLE, [:path, { d: "M6.2 6.3a1.85 1.85 0 1 1 2.6 1.7c-.55.25-.8.6-.8 1.2v.3M8 11.3v.01" }]],
    check: [[:path, { d: "m3.5 8.5 3 3 6-7" }]],
    dot: [[:circle, { cx: 8, cy: 8, r: 2.25, fill: "currentColor" }]],
    exclamation: [CIRCLE, [:path, { d: "M8 4.9v3.6M8 11v.01" }]],
    cross: [CIRCLE, [:path, { d: "m5.9 5.9 4.2 4.2m0-4.2-4.2 4.2" }]]
  }.freeze

  OVERALL_ICONS = { "Critical" => :alert_triangle, "High" => :alert_triangle, "Medium" => :alert_circle,
                    "Low" => :check_circle, "Minimal" => :check_circle }.freeze
  TRUST_ICONS = { "established" => :shield_check, "some" => :shield_half, "unproven" => :question,
                  "concerns" => :alert_triangle }.freeze
  TONE_ICONS = { good: :check, neutral: :dot, caution: :exclamation, bad: :cross }.freeze

  # The overall level ("High") as "High risk", in the severity colours.
  # Anything else reads "Not rated" in neutral grey.
  def overall_badge(level, size: :md)
    name = ScanPage.text(level).strip.capitalize
    known = ExtensionAnalyzerData::OVERALL_LEVELS.include?(name)
    rating_badge(kind: "overall", size: size, level: known ? name.downcase : "unrated",
                 classes: severity_classes(known ? name : nil),
                 icon: rating_icon(OVERALL_ICONS.fetch(name, :question)),
                 text: known ? "#{name} risk" : "Not rated")
  end

  # An access tier (a ScanRating::AccessTier, or the finding level that puts
  # an extension in it: "High" is Broad reach). label: :sr (default) says
  # "Access:" to screen readers only, :visible shows it, nil leaves it out.
  # An unknown level reads as stored, in neutral grey (see finding_badge).
  def access_badge(tier_or_level, size: :md, label: :sr)
    tier = tier_or_level.is_a?(ScanRating::AccessTier) ? tier_or_level : known_tier(tier_or_level)
    return finding_badge(tier_or_level, size: size) unless tier

    rating_badge(kind: "access", size: size, level: tier.level.downcase, label: label && ["Access", label],
                 classes: severity_classes(tier.level), icon: meter(tier.number), text: tier.name)
  end

  # A finding's level as its access tier ("Broad reach" for High). Info and
  # Minimal keep their names; anything else is shown as stored (escaped and
  # cut short, as on the Manifest tab) in neutral grey, or "Unrated".
  def finding_badge(severity, size: :sm)
    tier = known_tier(severity)
    return access_badge(tier, size: size, label: nil) if tier

    key = ScanPage::ManifestNotes.severity_key(severity)
    rating_badge(kind: "finding", size: size, level: key, classes: severity_classes(key == "unrated" ? nil : key),
                 text: ScanPage::ManifestNotes.severity_label(severity))
  end

  # A trust level (a ScanRating::TrustLevel or its key), in the trust
  # palette. label works as for access_badge.
  def trust_badge(level_or_key, size: :md, label: :sr)
    level = level_or_key.is_a?(ScanRating::TrustLevel) ? level_or_key : ScanRating.trust_level(level_or_key)
    key = level&.key || "unknown"
    rating_badge(kind: "trust", size: size, level: key, label: label && ["Trust", label],
                 icon: rating_icon(TRUST_ICONS.fetch(key, :question)), text: level&.name || "Not rated")
  end

  # One trust signal (a ScanRating::Signal).
  def signal_chip(signal, size: :sm)
    tone_chip(signal.tone, signal.label, size: size, key: signal.key)
  end

  # A chip of the given tone (:good, :neutral, :caution, :bad) with any text.
  # An unknown tone is shown as neutral.
  def tone_chip(tone, text, size: :sm, key: nil)
    tone = TONES.include?(tone.to_s.to_sym) ? tone.to_s.to_sym : :neutral
    rating_badge(kind: "signal", size: size, level: tone.to_s, icon: rating_icon(TONE_ICONS.fetch(tone)),
                 text: ScanPage.text(text), data: { signal: key })
  end

  private

  def known_tier(level)
    name = level.is_a?(String) || level.is_a?(Symbol) ? level.to_s.strip.capitalize : nil
    ScanRating::ACCESS_TIERS.find { |tier| tier.level == name }
  end

  def rating_badge(kind:, size:, level:, text:, classes: nil, icon: nil, label: nil, data: {})
    size = SIZES.include?(size) ? size : :md
    prefix = if label
      word, how = label
      tag.span("#{word}: ", class: how == :visible ? "badge-label" : "sr-only")
    end
    tag.span(class: ["badge", classes].compact.join(" "),
             data: { badge: kind, level: level, size: size }.merge(data.compact)) do
      safe_join([icon, prefix, tag.span(text, class: "badge-text")].compact)
    end
  end

  def rating_icon(name)
    tag.svg(class: "badge-icon", viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", "stroke-width": 1.6,
            "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false") do
      safe_join(ICONS.fetch(name).map { |shape, attrs| tag.public_send(shape, **attrs) })
    end
  end

  # Four rising bars, the first `filled` of them solid.
  def meter(filled)
    tag.svg(class: "badge-meter", viewBox: "0 0 19 12", "aria-hidden": "true", focusable: "false") do
      safe_join(4.times.map do |i|
        height = 4.5 + (i * 2.5)
        tag.rect(x: i * 5, y: 12 - height, width: 3.5, height: height, rx: 1, fill: "currentColor",
                 "fill-opacity": i < filled ? 1 : 0.3)
      end)
    end
  end
end
