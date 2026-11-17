require "test_helper"

class ScanStoreBadgesTest < ActionDispatch::IntegrationTest
  MANIFEST = { manifest_version: 3, name: "X", version: "1.0", permissions: [], raw: { "name" => "X" } }.freeze
  OVERALL = { severity: "Low", title: "Overall Risk: Low", description: "Based on 1 total findings." }.freeze

  def show(id, details)
    ScanResult.create!(extension_id: id, extension_name: "Badged", manifest: MANIFEST,
                       extension_details: details, security_findings: [OVERALL])
    get scan_path(id), xhr: true
    assert_response :success
    css_select("[data-store-badges]").map { |node| node.text.squish }
  end

  test "both badges show as one line in the header card" do
    assert_equal ["Chrome Web Store badges: Featured · Established publisher"],
                 show("b1" * 16, { author: "Acme", featured: true, established_publisher: true })
  end

  test "a single badge shows alone" do
    assert_equal ["Chrome Web Store badges: Established publisher"], show("b2" * 16, { established_publisher: true })
    assert_equal ["Chrome Web Store badges: Featured"], show("b3" * 16, { featured: true })
  end

  test "scans without badge keys, including older ones, show no badge line" do
    assert_empty show("b4" * 16, { author: "Acme", rating: "4.0", users: "10" })
    assert_empty show("b5" * 16, {})
    assert_not_includes response.body, "Chrome Web Store badges"
  end

  test "only a stored true counts as a badge" do
    assert_empty show("b6" * 16, { featured: "true", established_publisher: "<b>yes</b>" })
    assert_not_includes response.body, "<b>yes</b>"
  end
end
