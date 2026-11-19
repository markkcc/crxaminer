require "test_helper"

# Part 4: one display level per scan, the same in Ruby (statistics, the
# recent-scans list) and in the stats SQL filter, for every stored format.
class ScanDisplayLevelTest < ActionDispatch::IntegrationTest
  NEW_AI = { severity: "Info", title: "AI Context Analysis", description: "Fine.\nNo warning signs found.",
             ai: { concern_level: "none", purpose_fit: "fits" } }.freeze

  def old_ai(level)
    { severity: "Info", title: "AI Context Analysis", description: "Risk Level: #{level}\nOld text", ai: { risk_level: level } }
  end

  def overall(level, **extra)
    { severity: level, title: "Overall Risk: #{level}", description: "x", **extra }
  end

  # name => [stored findings, expected display level]
  ROWS = {
    "v4 with a new AI finding" => -> (t) { [[t.overall("High", rules_version: 4, access: "Critical", trust: "established"), NEW_AI], "High"] },
    "v4 keeping an old AI finding" => -> (t) { [[t.overall("Low", rules_version: 4, access: "High"), t.old_ai("Critical")], "Low"] },
    "v5 string keys" => -> (t) { [[{ "title" => "Overall Risk: Medium", "severity" => "Medium", "rules_version" => 5 }], "Medium"] },
    "v3 with an old AI finding" => -> (t) { [[t.overall("Medium", rules_version: 3), t.old_ai("High")], "High"] },
    "v2 without AI" => -> (t) { [[t.overall("Critical", rules_version: 2)], "Critical"] },
    "no version with a new AI finding" => -> (t) { [[t.overall("Low"), NEW_AI], "Low"] },
    "no version with an old AI finding" => -> (t) { [[t.overall("High"), t.old_ai("Minimal")], "Minimal"] },
    "version as a string is not version 4" => -> (t) { [[t.overall("Minimal", rules_version: "4"), t.old_ai("Medium")], "Medium"] },
    "v4 with a junk severity" => -> (t) { [[t.overall("<b>High</b>", rules_version: 4), t.old_ai("High")], nil] },
    "junk string" => -> (_) { ["junk", nil] },
    "junk list" => -> (_) { [[nil, 5, "x", [1], { title: 5 }], nil] },
    "nothing stored" => -> (_) { [nil, nil] }
  }.freeze

  setup do
    ScanResult.delete_all
    @expected = {}
    ROWS.each_with_index do |(name, row), i|
      findings, level = row.call(self)
      scan = ScanResult.create!(extension_id: format("%032d", i), extension_name: name, manifest: {}, security_findings: findings)
      @expected[scan.id] = level
    end
  end

  test "Ruby gives each stored format its level" do
    ScanResult.find_each do |scan|
      level = ScanDisplayLevel.for(scan.read_attribute(:security_findings))
      @expected[scan.id].nil? ? assert_nil(level, scan.extension_name) : assert_equal(@expected[scan.id], level, scan.extension_name)
    end
    assert_equal "High", ScanDisplayLevel.for([overall("High", rules_version: 4)].map(&:deep_stringify_keys))
  end

  test "the SQL filter selects exactly the scans Ruby shows at that level" do
    ScanDisplayLevel::LEVELS.each do |level|
      expected = @expected.select { |_, l| l == level }.keys.sort
      assert_equal expected, ScanDisplayLevel.where_level(ScanResult.all, level).pluck(:id).sort, level
    end
    assert_empty ScanDisplayLevel.where_level(ScanResult.all, "High%")
    assert_empty ScanDisplayLevel.where_level(ScanResult.all, "Info")
  end

  # The partial is a list of table rows; parse it inside a table.
  def rows
    Nokogiri::HTML5("<table><tbody>#{response.body}</tbody></table>").css("tr.scan-row")
  end

  test "the stats page filters by the shown level and lists it" do
    get stats_scan_index_path(severity: "High"), xhr: true
    assert_response :success
    names = rows.map { |row| row.text.squish }
    assert_equal 2, names.size
    assert names.any? { |n| n.include?("v4 with a new AI finding") }
    assert names.any? { |n| n.include?("v3 with an old AI finding") }
    assert_equal %w[High High], rows.map { |row| row["data-severity"] }

    get stats_scan_index_path(severity: "'; DROP TABLE scan_results; --"), xhr: true
    assert_response :success
    assert_empty rows

    get stats_scan_index_path, xhr: true
    assert_equal ROWS.size.clamp(0, 10), rows.size, "junk rows render too"
  end

  test "the statistics count the shown level of every scan" do
    RefreshStatsJob.perform_now
    counts = StatCache.first.severity_counts
    assert_equal({ "Critical" => 1, "High" => 2, "Medium" => 2, "Low" => 2, "Minimal" => 1 }, counts)
  end
end
