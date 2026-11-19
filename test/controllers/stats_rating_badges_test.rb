require "test_helper"

# The statistics page shows overall levels with the same badges as the scan page.
class StatsRatingBadgesTest < ActionDispatch::IntegrationTest
  def store(id, findings, name: "Ext")
    ScanResult.create!(extension_id: id, extension_name: name, manifest: { name: "X" }, extension_details: {},
                       security_findings: findings)
  end

  test "the level filters and the recent scans use the overall badge" do
    store("s1" * 16, [{ title: "Overall Risk: High", severity: "High" }])
    store("s2" * 16, [{ title: "Something else", severity: "Low" }], name: %(<img src=x onerror="alert(1)">))
    get stats_scan_index_path
    assert_response :success

    assert_select "h2", text: "Overall ratings"
    buttons = css_select("[role=group] button.severity-filter-btn")
    assert_equal ExtensionAnalyzerData::OVERALL_LEVELS, buttons.map { |b| b["data-severity"] }
    assert_equal ExtensionAnalyzerData::OVERALL_LEVELS.map { |l| "#{l} risk" },
                 buttons.map { |b| b.at_css("[data-badge=overall]").text.strip }
    buttons.each do |button|
      assert_includes button.at_css("[data-badge=overall]")["class"], "bg-severity-#{button['data-severity'].downcase}"
    end

    assert_select "thead th", text: "Rating"
    rows = css_select("#recent-scans-tbody tr").to_h { |r| [r.css("td")[0].text[/ID: (\w+)/, 1], r.at_css("[data-badge=overall]")] }
    assert_equal "High risk", rows.fetch("s1" * 16).text.strip
    assert_includes rows.fetch("s1" * 16)["class"], "bg-severity-high"
    assert_equal "Not rated", rows.fetch("s2" * 16).text.strip, "a scan with no level gets a neutral badge"
    assert_not_includes response.body, %(<img src=x onerror)
  end

  test "the filtered list returns the same badges" do
    store("s3" * 16, [{ title: "Overall Risk: Medium", severity: "Medium" }])
    get stats_scan_index_path(severity: "Medium"), xhr: true

    assert_response :success
    # The response is table rows only; read them inside a table.
    rows = Nokogiri::HTML5("<table><tbody>#{response.body}</tbody></table>").css("tr[data-severity=Medium]")
    assert_equal ["Medium risk"], rows.map { |r| r.at_css("[data-badge=overall][data-level=medium]").text.strip }
  end
end
