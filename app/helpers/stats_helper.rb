# The statistics page is built from cards (ScanStats::Dashboard supplies
# their numbers). Each card is built on its own, so one that cannot be shown
# is left out and the rest of the page still appears.
module StatsHelper
  CARD = "bg-brand-50 dark:bg-gray-700 rounded-lg p-6 border border-brand-200 dark:border-gray-600".freeze
  CARD_TITLE = "text-sm font-medium text-gray-600 dark:text-gray-400".freeze

  # The HTML of one card, or nil when the block has nothing to show or
  # raises (the error is logged with the card's name).
  def stat_card(name, &block)
    capture(&block).presence
  rescue StandardError => e
    Rails.logger.error("Statistics card #{name} could not be shown: #{e.class}: #{e.message}")
    nil
  end

  # The headline numbers, side by side. Missing ones (nil) leave no gap.
  def stat_tiles(*tiles)
    tiles = tiles.compact_blank
    return if tiles.empty?

    columns = { 1 => nil, 2 => "sm:grid-cols-2", 3 => "md:grid-cols-3" }.fetch(tiles.size, "sm:grid-cols-2 lg:grid-cols-4")
    tag.div(safe_join(tiles), class: ["grid grid-cols-1 gap-6 mb-6", columns], data: { stat_row: "tiles" })
  end

  # Cards side by side on large screens. A card on its own takes the full width.
  def stat_row(*cards)
    cards = cards.compact_blank
    return if cards.empty?

    tag.div(safe_join(cards), class: ["grid grid-cols-1 gap-6 mb-6", ("lg:grid-cols-2" if cards.size > 1)])
  end

  # "45%"; "<1%" for a share too small to round to 1; "0%" for none.
  def stat_percent(count, total)
    return "0%" unless total.to_i.positive? && count.to_i.positive?

    percent = count * 100.0 / total
    percent < 0.5 ? "<1%" : "#{[percent.round, 100].min}%"
  end

  # The width of a bar for `count` out of `total`, as a CSS percentage. A
  # count that is not zero always shows at least a sliver.
  def stat_bar_width(count, total)
    return "0%" unless total.to_i.positive? && count.to_i.positive?

    "#{(count * 100.0 / total).clamp(1, 100).round(1)}%"
  end
end
