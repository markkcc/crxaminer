# The "Extension Details" section of a scan page's header card, built from
# the store listing as stored with the scan (@extension_details). Old scans
# have few of these fields and any of them can be junk, so every value is
# read defensively: only non-blank strings and numbers count, and the view
# escapes them like any other text. Nothing here is ever made into a link.
module ExtensionDetailsHelper
  # One short fact: a label, its value and an optional smaller note.
  Fact = Struct.new(:key, :label, :value, :note, keyword_init: true)

  # The store badges, in the order shown, with their labels.
  STORE_BADGES = { featured: "Featured", established_publisher: "Established publisher" }.freeze

  # A rating as the store writes it ("4.6"), shown with a star.
  STAR_RATING = /\A[0-5](?:\.\d)?\z/

  # A part of developer_info such as "Email: hello@example.com".
  LABELLED_PART = /\A(\p{L}[\p{L} .-]{0,23}):\s*(\S.*)\z/m

  # The short facts, in display order: developer, users, rating, last
  # updated, size. Missing or junk values are left out.
  def extension_facts(details)
    value = ->(key) { detail_text(details, key) }
    rating = value[:rating]
    count = value[:rating_count]
    count = "#{count} ratings" if count&.match?(/\A[\d,.]+[KkMm]?\z/)

    [
      Fact.new(key: :author, label: "Developer", value: value[:author]),
      Fact.new(key: :users, label: "Users", value: value[:users]),
      (if rating
         Fact.new(key: :rating, label: "Rating", value: rating, note: count)
       elsif count
         Fact.new(key: :rating, label: "Ratings", value: count)
       end),
      Fact.new(key: :last_updated, label: "Last updated", value: value[:last_updated]),
      Fact.new(key: :size, label: "Size", value: value[:size])
    ].compact.select(&:value)
  end

  # The store badges this listing had (only a stored true counts).
  def extension_store_badges(details)
    STORE_BADGES.filter_map { |key, label| label if ScanPage.value(details, key) == true }
  end

  # The developer's contact details, split into parts where the text has
  # the store's usual "name and address; Website: x; Email: y" form:
  # [[nil, "name and address"], ["Website", "x"], ...]. Text without that
  # form comes back as one unlabelled part. nil when there is nothing.
  def developer_info_parts(details)
    text = detail_text(details, :developer_info)
    return nil unless text

    text.split(/\s*;\s+/).filter_map do |part|
      part = part.strip
      next if part.empty?

      (match = LABELLED_PART.match(part)) ? [match[1].strip, match[2].strip] : [nil, part]
    end.presence
  end

  def star_rating?(value)
    value.match?(STAR_RATING)
  end

  private

  def detail_text(details, key)
    value = ScanPage.value(details, key)
    text = case value
           when String then value
           when Numeric then value.to_s
           end
    text&.squish.presence
  end
end
