require "test_helper"

# Part 4: the text posted to X shows the overall level with the headline,
# then access and trust, and stays within X's limit.
class TweetTextTest < ActiveSupport::TestCase
  DETAILS = { rating: "4.5", rating_count: "44.7K", size: "1.2MiB", users: "39,000,000" }.freeze

  def rating(access = "High", details = DETAILS)
    ScanRating.new(access_level: access, extension_details: details)
  end

  def text(name, details: DETAILS, rating: rating())
    ExtensionSecurityAnalyzer.tweet_text(name: name, extension_id: "a" * 32, extension_details: details, rating: rating)
  end

  test "name, store line, overall level with headline, access and trust, link" do
    assert_equal <<~TEXT.chomp, text("Tab Helper", rating: rating("High", { users: "39,000,000", rating_count: "44.7K ratings" }))
      Tab Helper
      4.5 ★ (44.7K), 1.2MiB
      Overall: Low (Powerful, established publisher)
      Access: Broad reach. Trust: Established
      https://crxaminer.tech/scan/#{'a' * 32}
    TEXT
  end

  test "missing or junk store fields read as unknown" do
    lines = text(nil, details: nil, rating: rating("Critical", nil)).lines.map(&:chomp)
    assert_equal ["Unknown Extension", "? ★, ?KiB", "Overall: Critical (Very powerful, unproven publisher)",
                  "Access: Full control. Trust: Unproven"], lines.first(4)
    junk = text("X", details: { rating: ["5"], rating_count: { a: 1 }, size: "9" * 500 }, rating: rating("Low", "x"))
    assert_equal "? ★, #{'9' * 19}…", junk.lines[1].chomp
  end

  test "long names are shortened so the post stays within 280 as X counts it" do
    ["A" * 1000, "名" * 400, "😀" * 300, "word " * 200, "x"].each do |name|
      post = text(name)
      assert_operator ExtensionSecurityAnalyzer.tweet_length(post), :<=, 280, name[0, 10]
      assert post.end_with?("https://crxaminer.tech/scan/#{'a' * 32}")
      assert_equal 5, post.lines.size
    end
    assert_equal "x", text("x").lines.first.chomp
    assert text("A" * 1000).lines.first.chomp.end_with?("A…")
    assert_equal 280, ExtensionSecurityAnalyzer.tweet_length(text("A" * 1000))
  end

  test "a scan posts once, with the new text, and never for real in tests" do
    NoTweetsInTests::POSTED.clear
    manifest = { manifest_version: 3, permissions: ["proxy"], raw: { "manifest_version" => 3, "permissions" => ["proxy"] } }
    ExtensionSecurityAnalyzer.new(manifest, DETAILS, "Proxy Switcher", "p" * 32, ai_client: :default).analyze
    post = NoTweetsInTests::POSTED.sole
    assert_includes post, "Overall: Medium (Very powerful, established publisher)"
    assert_includes post, "Access: Full control. Trust: Established"
    assert_not_includes post, "Risk:"
  end
end
