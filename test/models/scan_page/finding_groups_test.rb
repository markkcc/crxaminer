require "test_helper"

class ScanPage::FindingGroupsTest < ActiveSupport::TestCase
  def finding(severity, title, description = "d")
    { severity: severity, title: title, description: description }
  end

  def area(groups, key)
    groups.areas.find { |a| a.key == key }
  end

  test "every title the rule engine writes lands in its area" do
    groups = ScanPage::FindingGroups.new([
      finding("High", "Overall Risk: High"),
      finding("High", "High-Risk Permission: tabs"),
      finding("High", "High-Risk Permission: <all_urls>"),
      finding("High", "Dangerous Permission Combination: webRequest + webRequestBlocking"),
      finding("High", "Broad Host Permissions"),
      finding("Medium", "Access to Sensitive Domains"),
      finding("High", "Broad Content Script Injection"),
      finding("Medium", "Older Manifest Version"),
      finding("High", "Unsafe WebAssembly Execution"),
      finding("High", "Unsafe JavaScript Evaluation"),
      finding("Medium", "Medium-Risk Permission: geolocation"),
      { severity: "Info", title: "AI Context Analysis", description: "Risk Level: Low" }
    ])

    assert_equal %i[site_access browser code_policy network], groups.areas.map(&:key)
    assert_equal ["Access to Sensitive Domains", "Broad Content Script Injection", "Broad Host Permissions", "High-Risk Permission: <all_urls>"].sort,
                 area(groups, :site_access).findings.map(&:title).sort
    assert_equal ["Dangerous Permission Combination: webRequest + webRequestBlocking", "High-Risk Permission: tabs", "Medium-Risk Permission: geolocation"],
                 area(groups, :browser).findings.map(&:title)
    assert_equal ["Unsafe JavaScript Evaluation", "Unsafe WebAssembly Execution", "Older Manifest Version"],
                 area(groups, :code_policy).findings.map(&:title)
    assert area(groups, :network).empty?
    assert_equal 10, groups.findings.size
  end

  test "routine permissions are collapsed but keep their stored severity and text" do
    groups = ScanPage::FindingGroups.new([
      finding("Medium", "Medium-Risk Permission: storage", "Stored text"),
      finding("Medium", "Medium-Risk Permission: notifications"),
      finding("Medium", "Medium-Risk Permission: activeTab"),
      finding("High", "Medium-Risk Permission: contextMenus"), # odd stored severity stays as it is
      finding("Medium", "Medium-Risk Permission: unlimitedStorage"),
      finding("Medium", "Medium-Risk Permission: geolocation")
    ])
    browser = area(groups, :browser)

    assert_equal ["Medium-Risk Permission: geolocation"], browser.findings.map(&:title)
    assert_equal %w[contextMenus activeTab notifications storage unlimitedStorage], browser.routine.map(&:permission)
    assert_equal "5 routine permissions: contextMenus · activeTab · notifications · storage · unlimitedStorage", browser.routine_label
    assert_equal "High", browser.routine.first.severity
    assert_equal "Stored text", browser.routine.find { |f| f.permission == "storage" }.description
  end

  test "one routine permission reads in the singular" do
    groups = ScanPage::FindingGroups.new([finding("Medium", "Medium-Risk Permission: storage")])
    assert_equal "1 routine permission: storage", area(groups, :browser).routine_label
  end

  test "unknown titles go to Other, which only appears when used" do
    assert_nil area(ScanPage::FindingGroups.new([]), :other)

    groups = ScanPage::FindingGroups.new([finding("Low", "Something from an older engine")])
    assert_equal ["Something from an older engine"], area(groups, :other).findings.map(&:title)
  end

  test "junk findings never raise and nothing is dropped" do
    groups = ScanPage::FindingGroups.new([
      "not a hash", nil, 5,
      { severity: nil, title: nil, description: nil },
      { "severity" => "High", "title" => "High-Risk Permission: tabs", "description" => "string keys" },
      { severity: 3, title: ["array"], description: { a: 1 } }
    ])

    assert_equal 3, groups.findings.size
    assert_equal 1, area(groups, :browser).findings.size
    assert_equal 2, area(groups, :other).findings.size
    assert_includes area(groups, :other).findings.map(&:title), '["array"]'
    assert_equal [], ScanPage::FindingGroups.new(nil).findings
    assert_equal [], ScanPage::FindingGroups.new("garbage").findings
  end
end
