require "test_helper"

class ScanRatingTest < ActiveSupport::TestCase
  AS_OF = Time.utc(2026, 11, 19)

  def rating(access = "High", details = {}, ai: nil)
    ScanRating.new(access_level: access, extension_details: details, ai: ai, as_of: AS_OF)
  end

  test "access tiers follow the finding levels" do
    assert_equal %w[Critical High Medium Low Minimal], ScanRating::ACCESS_TIERS.map(&:level)
    assert_equal ["Full control", "Broad reach", "Scoped", "Routine", "Minimal"], ScanRating::ACCESS_TIERS.map(&:name)
    assert_equal "Broad reach", rating("High").access.name
    assert_equal "Broad reach", rating("high").access.name
    assert_equal "Minimal", rating(nil).access.name
    assert_equal "Minimal", rating("nonsense").access.name
  end

  test "the listing decides the trust level" do
    assert_equal "established", rating("High", { users: "39,000,000", rating_count: "44.7K ratings" }).trust.key
    assert_equal "established", rating("High", { users: "100,000", established_publisher: true }).trust.key
    assert_equal "some", rating("High", { users: "5,000", established_publisher: true }).trust.key
    assert_equal "some", rating("High", { users: "300", featured: true }).trust.key
    assert_equal "some", rating("High", { users: "10,000", rating_count: "75 ratings" }).trust.key
    assert_equal "some", rating("High", { users: "2,000,000", rating_count: "739 ratings" }).trust.key
    assert_equal "unproven", rating("High", { users: "10,000", rating_count: "26 ratings" }).trust.key
    assert_equal "unproven", rating("High", { users: "Share", rating: "4.4" }).trust.key
    assert_equal "unproven", rating("High", {}).trust.key
    assert_equal "unproven", rating("High", nil).trust.key
  end

  test "a low rating is shown as a caution but does not lower trust" do
    r = rating("High", { users: "4,000,000", rating: "1.2", rating_count: "5.5K ratings" })
    assert_equal "established", r.trust.key
    assert_equal [:caution, "Rated 1.2 of 5"], r.signals.find { |s| s.key == :rating }.then { |s| [s.tone, s.label] }
  end

  test "the AI check can lower trust and never raise it" do
    strong = { users: "39,000,000", rating_count: "44.7K ratings" }
    assert_equal "established", rating("High", strong, ai: { concern_level: "none", purpose_fit: "fits" }).trust.key
    assert_equal "some", rating("High", strong, ai: { concern_level: "some" }).trust.key
    assert_equal "concerns", rating("High", strong, ai: { concern_level: "serious" }).trust.key
    assert_equal "concerns", rating("High", {}, ai: { concern_level: "some" }).trust.key
    assert_equal "unproven", rating("High", {}, ai: { concern_level: "none", purpose_fit: "fits", trust_level: "established" }).trust.key
    assert_equal "unproven", rating("High", {}, ai: { "concern_level" => "excellent" }).trust.key
    assert_equal "some", rating("High", strong, ai: { "concern_level" => "some" }).trust.key, "string keys work too"
  end

  test "the overall level combines the two and never falls with more access or less trust" do
    assert_equal "Low", rating("High", { users: "39,000,000", rating_count: "44.7K ratings" }).overall
    assert_equal "High", rating("High", {}).overall
    assert_equal "Critical", rating("Critical", {}).overall
    assert_equal "Medium", rating("Critical", { users: "100,000", established_publisher: true }).overall
    assert_equal "Minimal", rating("Minimal", {}).overall

    order = %w[Minimal Low Medium High Critical]
    table = ScanRating::OVERALL
    assert_equal ScanRating::ACCESS_TIERS.map(&:key), table.keys
    table.each_value do |row|
      assert_equal ScanRating::TRUST_LEVELS.size, row.size
      assert_equal row.map { |l| order.index(l) }.sort, row.map { |l| order.index(l) }, "less trust never lowers the level"
    end
    table.values.transpose.each do |column|
      ranks = column.map { |l| order.index(l) }
      assert_equal ranks.sort.reverse, ranks, "more access never lowers the level"
    end
  end

  test "the headline and advice read as a sentence" do
    r = rating("High", { users: "39,000,000", rating_count: "44.7K ratings" })
    assert_equal "Powerful, established publisher", r.headline
    assert_equal ScanRating::ADVICE.fetch("Low"), r.advice
    assert_equal "Very powerful, unproven publisher", rating("Critical", {}).headline
    assert_equal({ access: "High", trust: "established", headline: "Powerful, established publisher" }, r.to_stored)
  end

  test "signals describe the listing, with a tone each" do
    r = rating("High", { users: "7,000,000", rating: "4.3", rating_count: "13.3K ratings", last_updated: "November 6, 2026",
                         featured: true, established_publisher: true },
               ai: { purpose_fit: "broader_than_needed", concern_level: "some" })
    assert_equal %i[established_publisher featured users rating_count rating last_updated purpose_fit concern_level], r.signals.map(&:key)
    assert_equal %i[good good good good neutral neutral caution caution], r.signals.map(&:tone)
    assert_includes r.signals.map(&:label), "7,000,000 users"
    assert_includes r.signals.map(&:label), "13,300 ratings"
    assert_includes r.signals.map(&:label), "Updated November 6, 2026"

    old = rating("High", { users: "600", rating_count: "9 ratings", last_updated: "March 3, 2023" })
    assert_equal ["Fewer than 1,000 users", "Only 9 ratings", "Not updated since March 2023"], old.signals.map(&:label)
    assert_equal [:caution], old.signals.map(&:tone).uniq

    assert_equal [[:no_listing, :caution, "No store listing data"]], rating("High", {}).signals.map { |s| [s.key, s.tone, s.label] }
  end

  test "counts are read from the forms the store uses" do
    { "39,000,000" => 39_000_000, "10,000+" => 10_000, "44.7K ratings" => 44_700, "275 ratings" => 275, "1.2M" => 1_200_000,
      "7" => 7, 12 => 12, "Share" => nil, "" => nil, nil => nil, -3 => nil, ["1"] => nil, "ratings 5" => nil }.each do |value, expected|
      expected.nil? ? assert_nil(ScanRating.count(value), value.inspect) : assert_equal(expected, ScanRating.count(value), value.inspect)
    end
  end

  test "junk listing data never raises" do
    junk = { users: { a: 1 }, rating: ["4"], rating_count: 3.5, last_updated: "<script>", featured: "true", established_publisher: 1 }
    r = rating("High", junk, ai: "nope")
    assert_equal "unproven", r.trust.key
    assert_equal [:no_listing], r.signals.map(&:key)
    assert_nothing_raised { rating("High", "x").signals }
    assert_nil rating("High", { last_updated: "99 99, 9999" }).last_updated
    assert_nil rating("High", { rating: "11" }).rating
  end

  test "a stored scan is rated from its overall finding, listing details and AI check" do
    details = { users: "39,000,000", rating_count: "44.7K ratings" }
    newer = [{ title: "Overall Risk: Low", severity: "Low", access: "High", trust: "established", rules_version: 4 },
             { title: "AI Context Analysis", severity: "Info", ai: { concern_level: "some" } }]
    r = ScanRating.for_scan(security_findings: newer, extension_details: details, as_of: AS_OF)
    assert_equal ["Broad reach", "some", "Medium"], [r.access.name, r.trust.key, r.overall]

    older = [{ "title" => "Overall Risk: Critical", "severity" => "Critical" },
             { "title" => "AI Context Analysis", "severity" => "Info", "ai" => { "risk_level" => "Low" } }]
    r = ScanRating.for_scan(security_findings: older, extension_details: details, as_of: AS_OF)
    assert_equal ["Full control", "established", "Medium"], [r.access.name, r.trust.key, r.overall]

    r = ScanRating.for_scan(security_findings: nil, extension_details: nil)
    assert_equal ["Minimal", "unproven", "Minimal"], [r.access.name, r.trust.key, r.overall]
    assert_nothing_raised { ScanRating.for_scan(security_findings: ["x", 3, nil], extension_details: [1]) }
  end
end
