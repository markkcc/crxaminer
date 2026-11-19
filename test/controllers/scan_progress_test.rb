require "test_helper"

# The scan's progress card (scan/_loading_status): shown while a new scan or a
# forced re-scan runs, with an indeterminate bar, approximate steps and one
# polite live line; and its finished state (scan/_complete_status).
class ScanProgressTest < ActionDispatch::IntegrationTest
  MANIFEST = { manifest_version: 3, name: "X", version: "1.0", permissions: [], raw: { "name" => "X" } }.freeze
  OVERALL = { severity: "Low", title: "Overall Risk: Low", description: "Based on 1 total findings." }.freeze
  STEPS = ["Store listing", "Package", "Rules", "AI check"].freeze

  def steps
    css_select("#scan-progress ol.scan-steps > li.scan-step").map { |li| [li.text.squish, li["data-step"]] }
  end

  test "a new scan shows the running card: indeterminate bar, approximate steps and one polite live line" do
    id = "pa" * 16
    get scan_path(id)
    assert_response :success

    assert_select "#analysis_status #scan-progress[data-state=running][aria-busy=true]", count: 1
    assert_select "#scan-progress-title", text: "Scanning this extension"
    assert_select "#scan-progress", text: /Extension ID\s+#{id}/
    assert_select "#scan-progress-hint", text: "This usually takes a few seconds."
    assert_select "#scan-progress-hint[data-slow-text]", count: 1

    # Indeterminate: a progressbar with no value, so nothing claims a percentage.
    assert_select "#scan-progress [role=progressbar][aria-labelledby=scan-progress-title][aria-valuetext=Working]", count: 1
    assert_select "#scan-progress [role=progressbar][aria-valuenow]", count: 0
    assert_no_match(/\d+\s*%/, css_select("#scan-progress").first.text)

    assert_select "#scan-progress ol[aria-label='Scan steps (approximate)']", count: 1
    assert_equal STEPS.zip(%w[active todo todo todo]), steps
    assert_select "#scan-progress .scan-step-dot[aria-hidden=true]", count: 4

    # One live region, polite, for the step changes.
    assert_select "#scan-progress [aria-live]", count: 1
    assert_select "#progress-message[aria-live=polite]", text: "Reading the Chrome Web Store listing."

    # The script still asks for the same analysis, and fills the finished state.
    assert_includes response.body, "fetch('/scan/analyze?id=#{id}&force=', {"
    assert_includes response.body, "panel.dataset.state = 'done';"
    assert_includes response.body, "sessionStorage.setItem('justCompleted', 'true');"
    assert_includes response.body, "url.searchParams.delete('force');"
  end

  test "a forced re-scan names the extension, escaped, above the stored results" do
    ScanResult.create!(extension_id: "pb" * 16, extension_name: "<b>Named</b>", manifest: MANIFEST,
                       extension_details: {}, security_findings: [OVERALL])
    get scan_path("pb" * 16, force: true)
    assert_response :success

    assert_select "#scan-progress-title", text: "Scanning <b>Named</b>"
    assert_select "#scan-progress-title[data-running-text='Scanning <b>Named</b>'][data-done-text='Scan complete']", count: 1
    assert_not_includes response.body, "Scanning <b>Named</b>"
    assert_includes response.body, "fetch('/scan/analyze?id=#{'pb' * 16}&force=true', {"
    assert_select "#analysis_results #extension-details", count: 1
  end

  test "a stored scan without force shows no progress card" do
    ScanResult.create!(extension_id: "pc" * 16, extension_name: "Stored", manifest: MANIFEST,
                       extension_details: {}, security_findings: [OVERALL])
    get scan_path("pc" * 16)
    assert_select "#scan-progress", count: 0
  end

  test "the finished card has every step done, a full bar and no busy flag" do
    html = ApplicationController.render(partial: "scan/complete_status")
    doc = Nokogiri::HTML5.fragment(html)

    card = doc.at_css("#scan-progress")
    assert_equal "done", card["data-state"]
    assert_equal "false", card["aria-busy"]
    assert_equal "Scan complete", doc.at_css("#scan-progress-title").text.strip
    assert_equal "Complete", doc.at_css("[role=progressbar]")["aria-valuetext"]
    assert_equal STEPS.zip(%w[done done done done]), doc.css("li.scan-step").map { |li| [li.text.squish, li["data-step"]] }
    assert_equal "Scan complete. Loading the results.", doc.at_css("#progress-message[aria-live=polite]").text
  end

  test "a status message passed in becomes the first live line" do
    html = ApplicationController.render(partial: "scan/loading_status", locals: { message: "Fetching extension details..." })
    doc = Nokogiri::HTML5.fragment(html)
    assert_equal "running", doc.at_css("#scan-progress")["data-state"]
    assert_equal "Fetching extension details...", doc.at_css("#progress-message").text
    assert_equal "Scanning this extension", doc.at_css("#scan-progress-title").text.strip
  end
end
