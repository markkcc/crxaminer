require "test_helper"

class RatingBadgesHelperTest < ActionView::TestCase
  include ScanHelper

  HOSTILE = %(<img src=x onerror="alert(1)">).freeze

  def badge(html)
    Nokogiri::HTML5.fragment(html.to_s).at_css(".badge")
  end

  def visible_text(node)
    node.dup.tap { |n| n.css(".sr-only").each(&:remove) }.text.strip
  end

  test "the overall badge reads '<Level> risk' in the severity colours, with a decorative icon" do
    ExtensionAnalyzerData::OVERALL_LEVELS.each do |level|
      node = badge(overall_badge(level))
      assert_equal "#{level} risk", node.text.strip
      assert_equal %w[overall md], [node["data-badge"], node["data-size"]]
      assert_equal level.downcase, node["data-level"]
      assert_includes node["class"], severity_classes(level)
      assert_equal "true", node.at_css("svg")["aria-hidden"]
    end
    assert_equal "High risk", badge(overall_badge(" high ")).text.strip
    assert_equal "lg", badge(overall_badge("Low", size: :lg))["data-size"]
    assert_equal "md", badge(overall_badge("Low", size: :huge))["data-size"], "unknown sizes fall back to md"
  end

  test "an unknown overall level reads Not rated in neutral grey" do
    [nil, "", "Severe", HOSTILE, { a: 1 }, 7].each do |value|
      node = badge(overall_badge(value))
      assert_equal "Not rated", node.text.strip, value.inspect
      assert_equal "unrated", node["data-level"]
      assert_includes node["class"], ExtensionAnalyzerData::SEVERITY_FALLBACK_COLOR
    end
  end

  test "the access badge names the tier, fills its meter by the tier number, in its level's colour" do
    ScanRating::ACCESS_TIERS.each do |tier|
      [tier, tier.level, tier.level.downcase].each do |input|
        node = badge(access_badge(input))
        assert_equal tier.name, visible_text(node)
        assert_equal "Access:", node.at_css(".sr-only").text.strip, "the context is there for screen readers"
        assert_equal "access", node["data-badge"]
        assert_includes node["class"], severity_classes(tier.level)
        bars = node.css("svg.badge-meter rect")
        assert_equal 4, bars.size
        assert_equal tier.number, bars.count { |bar| bar["fill-opacity"] == "1" }
        assert_equal "true", node.at_css("svg.badge-meter")["aria-hidden"]
      end
    end
    assert_equal "Access:", badge(access_badge("High", label: :visible)).at_css(".badge-label").text.strip
    assert_nil badge(access_badge("High", label: nil)).at_css(".sr-only, .badge-label")
  end

  test "finding badges show the tier name for finding levels and keep Info and unknown levels" do
    { "Critical" => "Full control", "High" => "Broad reach", "medium" => "Scoped", "LOW" => "Routine", "Minimal" => "Minimal" }.each do |level, name|
      node = badge(finding_badge(level))
      assert_equal name, node.text.strip
      assert_equal "sm", node["data-size"]
      assert_includes node["class"], severity_classes(level)
    end

    info = badge(finding_badge("Info"))
    assert_equal ["Info", "finding", "info"], [info.text.strip, info["data-badge"], info["data-level"]]
    assert_includes info["class"], severity_classes("Info")

    junk = badge(finding_badge(HOSTILE))
    assert_equal "unrated", junk["data-level"]
    assert_includes junk["class"], ExtensionAnalyzerData::SEVERITY_FALLBACK_COLOR
    assert_equal "#{HOSTILE[0, 19]}…", junk.text.strip, "shown as stored, cut short"
    assert_not_includes finding_badge(HOSTILE), "<img"
    assert_equal "Unrated", badge(finding_badge(nil)).text.strip
    assert_equal "Unrated", badge(finding_badge("  ")).text.strip
  end

  test "the trust badge has its own palette and an icon per level" do
    icons = ScanRating::TRUST_LEVELS.map do |level|
      [level, level.key].each do |input|
        node = badge(trust_badge(input))
        assert_equal level.name, visible_text(node)
        assert_equal ["trust", level.key], [node["data-badge"], node["data-level"]]
        assert_equal "Trust:", node.at_css(".sr-only").text.strip
        assert_no_match(/bg-severity|text-severity/, node["class"], "never the severity colours")
        assert_equal "true", node.at_css("svg")["aria-hidden"]
      end
      badge(trust_badge(level)).at_css("svg").inner_html
    end
    assert_equal icons.size, icons.uniq.size, "each level has its own icon"

    unknown = badge(trust_badge(HOSTILE))
    assert_equal ["Not rated", "unknown"], [visible_text(unknown), unknown["data-level"]]
    assert_equal "Not rated", visible_text(badge(trust_badge(nil)))
  end

  test "trust levels and signal tones each have both themes' colours in the stylesheet" do
    css = Rails.root.join("app/assets/tailwind/application.css").read
    blocks = css.split("@media (prefers-color-scheme: dark)")
    dark = blocks.drop(1).map { |b| b[/\A.*?\n\}\n/m].to_s }.find { |b| b.include?("--trust-") }
    (ScanRating::TRUST_LEVELS.map { |l| "trust-#{l.key}" } + RatingBadgesHelper::TONES.map { |t| "tone-#{t}" }).each do |name|
      %w[bg fg line].each do |part|
        assert_equal 2, css.scan("--#{name}-#{part}:").size, "#{name} has a light and a dark #{part}"
        assert_includes dark, "--#{name}-#{part}:", "#{name} has a dark #{part}"
      end
      kind = name.start_with?("trust") ? "trust" : "signal"
      assert_includes css, %(.badge[data-badge="#{kind}"][data-level="#{name.split('-', 2).last}"])
    end
  end

  test "signal chips are coloured by tone and escape their text" do
    RatingBadgesHelper::TONES.each do |tone|
      node = badge(signal_chip(ScanRating::Signal.new(key: :users, tone: tone, label: "7,000 users")))
      assert_equal ["signal", tone.to_s, "users"], [node["data-badge"], node["data-level"], node["data-signal"]]
      assert_equal "7,000 users", node.text.strip
      assert_equal "true", node.at_css("svg")["aria-hidden"]
    end
    icons = RatingBadgesHelper::TONES.map { |tone| badge(tone_chip(tone, "x")).at_css("svg").inner_html }
    assert_equal 4, icons.uniq.size

    odd = badge(tone_chip("dangerous", HOSTILE))
    assert_equal "neutral", odd["data-level"]
    assert_equal HOSTILE, odd.text.strip
    assert_not_includes tone_chip(:bad, HOSTILE), "<img"
    assert_equal "good", badge(tone_chip("good", "x"))["data-level"], "a tone given as a string works"
  end
end
