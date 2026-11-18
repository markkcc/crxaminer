require "test_helper"

class ScanFreshnessTest < ActiveSupport::TestCase
  NOW = Time.utc(2026, 11, 18, 12)
  Scan = Struct.new(:updated_at, :manifest, keyword_init: true)

  def freshness(age:, version: "1.68.0", store: nil)
    ScanFreshness.new(Scan.new(updated_at: NOW - age, manifest: { version: version }), store: store, now: NOW)
  end

  def known(version) = StoreVersionClient::Result.new(status: :ok, version: version)
  def unavailable = StoreVersionClient::Result.new(status: :unavailable, reason: "noupdate")
  def failed = StoreVersionClient::Result.new(status: :error, reason: "HTTP 500")

  test "a fresh scan of the store's version has no notice" do
    f = freshness(age: 2.days, store: known("1.68.0"))

    assert_not f.notice?
    assert_nil f.notice
    assert f.same_version?
    assert_equal "the latest in the store", f.store_note
  end

  test "a fresh scan with no store answer yet has no notice and no note" do
    f = freshness(age: 2.days)

    assert_not f.notice?
    assert_nil f.store_note
  end

  test "an old scan gets the age notice" do
    f = freshness(age: 11.months)

    assert f.old?
    assert_equal "This scan is 11 months old and covers version 1.68.0. The extension may have changed since then. " \
                 "The results below may not match the extension you would install today.", f.notice
  end

  test "thirty days is old, twenty-nine is not" do
    assert freshness(age: 30.days).old?
    assert_not freshness(age: 29.days).old?
  end

  test "a different store version gets the version notice" do
    f = freshness(age: 3.days, store: known("1.70.2"))

    assert f.version_differs?
    assert_not f.old?
    assert_equal "This scan covers version 1.68.0. The Chrome Web Store now has version 1.70.2. " \
                 "The results below may not match the extension you would install today.", f.notice
    assert_equal "in the store now: 1.70.2", f.store_note
  end

  test "an old scan of an older version gets one notice that says both" do
    f = freshness(age: 11.months, store: known("1.70.2"))

    assert_equal "This scan is 11 months old and covers version 1.68.0. The Chrome Web Store now has version 1.70.2. " \
                 "The results below may not match the extension you would install today.", f.notice
  end

  test "no version or a failed lookup makes no claim about the store" do
    [unavailable, failed].each do |store|
      fresh = freshness(age: 2.days, store: store)
      assert_not fresh.notice?
      assert_not fresh.version_differs?
      assert_equal "store version not available", fresh.store_note

      old = freshness(age: 11.months, store: store)
      assert old.notice?
      assert_no_match(/removed|Chrome Web Store now/, old.notice)
    end
  end

  test "versions that Chrome treats as equal are the same" do
    assert_not freshness(age: 2.days, version: "1.2", store: known("1.2.0.0")).version_differs?
    assert freshness(age: 2.days, version: "1.2", store: known("1.2.1")).version_differs?
  end

  test "re-scan is allowed after 24 hours or when the store version differs" do
    assert freshness(age: 25.hours).rescan_allowed?
    assert freshness(age: 2.hours, store: known("1.70.2")).rescan_allowed?
    assert_not freshness(age: 2.hours).rescan_allowed?
    assert_not freshness(age: 2.hours, store: known("1.68.0")).rescan_allowed?
    assert_not freshness(age: 2.hours, store: unavailable).rescan_allowed?
    assert_not freshness(age: 2.hours, store: failed).rescan_allowed?
  end

  test "odd stored versions do not break the notice" do
    hostile = "<script>alert(1)</script>" * 5
    f = freshness(age: 11.months, version: hostile, store: known("1.0"))
    assert f.version_differs?
    assert_includes f.notice, "covers version #{hostile.truncate(ScanFreshness::VERSION_DISPLAY_LIMIT)}."

    [nil, "", { "x" => 1 }, ["1.0"]].each do |version|
      notice = freshness(age: 11.months, version: version).notice
      assert notice.start_with?("This scan is 11 months old."), notice
    end
    assert_equal "This scan is 11 months old and covers version 3.", freshness(age: 11.months, version: 3).notice[/\A[^.]+\./]

    no_manifest = ScanFreshness.new(Scan.new(updated_at: NOW - 40.days, manifest: nil), now: NOW)
    assert no_manifest.notice?
  end
end
