require "test_helper"

class ScanHelperTest < ActionView::TestCase
  LEVELS = %w[Critical High Medium Low Minimal Info].freeze

  test "every level has exactly one mapping, whatever its case" do
    assert_equal LEVELS, ExtensionAnalyzerData::SEVERITY_COLORS.keys

    LEVELS.each do |level|
      expected = ExtensionAnalyzerData::SEVERITY_COLORS.fetch(level)
      assert_equal expected, severity_classes(level)
      assert_equal expected, severity_classes(level.downcase)
      assert_equal expected, severity_classes(level.upcase)
      assert_equal expected, severity_classes(level.downcase.to_sym)
    end
  end

  test "each level has its own background and a matching foreground token" do
    backgrounds = LEVELS.map { |level| severity_classes(level)[/\bbg-\S+/] }
    assert_equal LEVELS.size, backgrounds.uniq.size

    LEVELS.each do |level|
      token = "severity-#{level.downcase}"
      assert_equal "bg-#{token} text-#{token}-fg", severity_classes(level)
    end
  end

  test "the tokens carry the original palette, with text that reaches 4.5:1" do
    css = Rails.root.join("app/assets/tailwind/application.css").read
    original = { "critical" => "violet-600", "high" => "red-600", "medium" => "orange-500",
                 "low" => "yellow-500", "minimal" => "green-500", "info" => "blue-500" }
    # White where it reaches 4.5:1 on the colour, a dark ink of the same hue where it does not.
    text = { "critical" => "#ffffff", "high" => "#ffffff", "medium" => "#431407",
             "low" => "#422006", "minimal" => "#052e16", "info" => "#020617" }

    original.each do |level, colour|
      assert_includes css, "--color-severity-#{level}: var(--color-#{colour});"
      assert_includes css, "--color-severity-#{level}-fg: #{text.fetch(level)};"
    end
  end

  test "unknown or missing levels fall back to a neutral style" do
    assert_equal ExtensionAnalyzerData::SEVERITY_FALLBACK_COLOR, severity_classes(nil)
    assert_equal ExtensionAnalyzerData::SEVERITY_FALLBACK_COLOR, severity_classes("Unknown")
  end
end
