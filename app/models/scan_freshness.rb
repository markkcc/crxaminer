# How current a stored scan is: its age, and whether the Chrome Web Store
# now offers a different version than the one scanned. Decides the notice
# on the scan page and whether a forced re-scan is allowed.
#
#   ScanFreshness.new(scan, store: StoreVersionClient.cached(id))
#
# store is a StoreVersionClient::Result or nil (not known yet). Pure: no
# network and no database access.
class ScanFreshness
  include ActionView::Helpers::DateHelper

  # Older than this, the page says so even without a store version.
  OLD_AFTER = 30.days
  # Older than this, anyone may ask for a re-scan.
  RESCAN_AFTER = 24.hours
  # Long or hostile version strings are cut in sentences.
  VERSION_DISPLAY_LIMIT = 40

  attr_reader :scanned_at, :store

  def initialize(scan, store: nil, now: Time.current)
    @scanned_at = scan.updated_at
    manifest = scan.manifest
    @scanned_version = manifest.is_a?(Hash) ? (manifest[:version] || manifest["version"]) : nil
    @store = store
    @now = now
  end

  # The scanned version as text, or nil when the manifest has none (or a
  # value that is not a string or number).
  def scanned_version
    value = @scanned_version
    value = value.to_s if value.is_a?(Numeric)
    value.is_a?(String) && !value.strip.empty? ? value.strip : nil
  end

  def store_version
    store&.ok? ? store.version : nil
  end

  def old?
    scanned_at.present? && scanned_at <= @now - OLD_AFTER
  end

  # True only when the store reported a version and it is not the scanned
  # one. "1.2" and "1.2.0" are the same version to Chrome.
  def version_differs?
    return false unless store_version

    normalized(scanned_version) != normalized(store_version)
  end

  def same_version?
    store_version.present? && !version_differs?
  end

  def notice?
    old? || version_differs?
  end

  def rescan_allowed?
    scanned_at.nil? || scanned_at <= @now - RESCAN_AFTER || version_differs?
  end

  # "11 months", "about 1 year"
  def age_in_words
    distance_of_time_in_words(scanned_at, @now)
  end

  # Plain sentences for the notice, or nil when there is nothing to say.
  def notice
    return nil unless notice?

    covers = scanned_version ? "covers version #{short(scanned_version)}" : nil
    first = if old?
      ["This scan is #{age_in_words} old", covers].compact.join(" and ") + "."
    elsif covers
      "This scan #{covers}."
    end
    sentences = [first]
    sentences << "The Chrome Web Store now has version #{short(store_version)}." if version_differs?
    sentences << "The extension may have changed since then." if old? && !version_differs?
    sentences << "The results below may not match the extension you would install today."
    sentences.compact.join(" ")
  end

  # What the page shows beside the scanned version once the store answered.
  def store_note
    return nil unless store

    if version_differs?
      "in the store now: #{short(store_version)}"
    elsif same_version?
      "the latest in the store"
    else
      "store version not available"
    end
  end

  private

  def short(text)
    text.to_s.truncate(VERSION_DISPLAY_LIMIT)
  end

  def normalized(version)
    return version unless StoreVersionClient.valid_version?(version)

    parts = version.split(".").map(&:to_i)
    parts += [0] * (4 - parts.length)
    parts
  end
end
