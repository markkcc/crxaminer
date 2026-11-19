require "test_helper"

# "Extension Details" in a scan page's header card: short facts as tiles, the
# store badges as the last tile, the developer's contact details in their own
# panel, one quiet line when nothing was saved, and every value escaped.
#
# Set RENDER_DIR to keep each rendered page there (for screenshots).
class ScanExtensionDetailsTest < ActionDispatch::IntegrationTest
  MANIFEST = { manifest_version: 3, name: "X", version: "1.0", permissions: [], raw: { "name" => "X" } }.freeze
  OVERALL = { severity: "Low", title: "Overall Risk: Low", description: "Based on 1 total findings." }.freeze
  HOSTILE = %("><img src=x onerror=alert(1)><script>alert(1)</script>).freeze
  BITWARDEN = {
    author: "Bitwarden Inc.", rating: "2.8", rating_count: "8.2K ratings", users: "7,000,000", size: "24.84MiB",
    last_updated: "November 2, 2026", featured: true, established_publisher: true,
    developer_info: "Bitwarden Inc., 1 N Calle Cesar Chavez Suite 102, Santa Barbara, CA 93103-5619, US; " \
                    "Website: bitwarden.com; Email: hello@bitwarden.com; Phone: +1 904-664-9194"
  }.freeze

  def show(id, details)
    ScanResult.create!(extension_id: id, extension_name: "Details", manifest: MANIFEST,
                       extension_details: details, security_findings: [OVERALL])
    get scan_path(id)
    assert_response :success
    if (dir = ENV["RENDER_DIR"]).present?
      html = response.body.sub("<head>", %(<head><base href="http://localhost:3122/">))
      File.write(File.join(dir, "#{name}.html"), html)
    end
  end

  def facts
    css_select("#extension-facts > [data-fact]").map do |tile|
      [tile["data-fact"], tile.at_css("dt").text.squish, tile.css("dd").map { |dd| dd.text.squish }]
    end
  end

  test "every field: five fact tiles, the badges tile and the contact panel split into its parts" do
    show("da" * 16, BITWARDEN)

    assert_select "#extension-details h2", text: "Extension Details"
    assert_equal [
      ["author", "Developer", ["Bitwarden Inc."]],
      ["users", "Users", ["7,000,000"]],
      ["rating", "Rating", ["2.8 out of 5", "8.2K ratings"]],
      ["last_updated", "Last updated", ["November 2, 2026"]],
      ["size", "Size", ["24.84MiB"]],
      ["badges", "Store badges", ["Featured", "Established publisher"]]
    ], facts
    assert_select "[data-fact=rating] svg[aria-hidden=true]", count: 1

    assert_select "#developer-info [data-contact-text]", count: 1,
                  text: "Bitwarden Inc., 1 N Calle Cesar Chavez Suite 102, Santa Barbara, CA 93103-5619, US"
    parts = css_select("#developer-info [data-contact-part]").map { |p| [p.at_css("dt").text, p.at_css("dd").text] }
    assert_equal [["Website", "bitwarden.com"], ["Email", "hello@bitwarden.com"], ["Phone", "+1 904-664-9194"]], parts
    # Untrusted text is never made into a link.
    assert_select "#extension-details a", count: 0
    assert_select "[data-details-empty]", count: 0
  end

  test "some fields: only those tiles, and no contact panel" do
    show("db" * 16, { users: "20,000", rating: "4.2", rating_count: "188 ratings", author: "", developer_info: "", size: nil })

    assert_equal [["users", "Users", ["20,000"]], ["rating", "Rating", ["4.2 out of 5", "188 ratings"]]], facts
    assert_select "#developer-info", count: 0
    assert_select "[data-store-badges]", count: 0
  end

  test "a rating count without a rating, and a bare count, read as ratings" do
    show("dc" * 16, { rating_count: "1,234" })
    assert_equal [["rating", "Ratings", ["1,234 ratings"]]], facts
  end

  test "developer information without the usual form is shown as plain text" do
    show("dd" * 16, { developer_info: "Contact us through our website" })

    assert_select "#extension-facts", count: 0
    assert_select "#developer-info [data-contact-text]", count: 1, text: "Contact us through our website"
    assert_select "#developer-info [data-contact-part]", count: 0
  end

  test "developer information with one labelled part has no address line" do
    show("de" * 16, { author: "Muhammed", developer_info: "Email: someone@example.com" })

    assert_select "#developer-info [data-contact-text]", count: 0
    assert_equal ["Email someone@example.com"], css_select("#developer-info [data-contact-part]").map { |p| p.text.squish }
  end

  test "no fields: one quiet line instead of an empty section" do
    [{}, nil, { author: "", users: nil, store_description: "Only a description" }].each_with_index do |details, index|
      show("d#{index}" * 16, details)
      assert_select "#extension-details [data-details-empty]", count: 1, text: "No listing details were saved with this scan."
      assert_select "#extension-facts, #developer-info", count: 0
    end
  end

  test "hostile values are escaped and never links" do
    show("df" * 16, { author: HOSTILE, users: HOSTILE, rating: HOSTILE, rating_count: HOSTILE, size: HOSTILE,
                      last_updated: HOSTILE, featured: "true", established_publisher: HOSTILE,
                      developer_info: "#{HOSTILE}; Website: javascript:alert(1); Email: #{HOSTILE}" })

    assert_equal %w[author users rating last_updated size], facts.map(&:first)
    facts.each { |_, _, values| assert_equal HOSTILE, values.first }
    # A rating that is not a number gets no star and no "out of 5".
    assert_select "[data-fact=rating] svg", count: 0
    assert_select "[data-fact=rating]", text: /out of 5/, count: 0
    assert_select "[data-store-badges]", count: 0
    assert_select "#developer-info [data-contact-text]", text: HOSTILE
    assert_equal [["Website", "javascript:alert(1)"], ["Email", HOSTILE]],
                 css_select("#developer-info [data-contact-part]").map { |p| [p.at_css("dt").text, p.at_css("dd").text] }
    assert_select "#extension-details a, #extension-details img, #extension-details script", count: 0
    assert_not_includes response.body, "<img src=x onerror=alert(1)>"
    assert_includes response.body, "&lt;img src=x onerror=alert(1)&gt;"
  end

  test "values that are not text or numbers are left out" do
    show("dg" * 16, { author: { "nested" => HOSTILE }, users: ["1"], rating: 4.5, size: true })
    assert_equal [["rating", "Rating", ["4.5 out of 5"]]], facts
  end
end
