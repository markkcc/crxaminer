require "test_helper"

# The rating card at the top of the Overview, the AI check and the rating
# badges in the header and the findings, for every stored format: scans rated
# with the access and trust rules, older scans with the earlier AI formats,
# and scans with no AI finding at all.
#
# Set RENDER_DIR to keep each rendered page there (for screenshots).
class ScanRatingCardTest < ActionDispatch::IntegrationTest
  HOSTILE = %("><img src=x onerror="window.__x=1"><script>window.__x=1</script>).freeze
  MANIFEST = {
    manifest_version: 3, name: "X", version: "2.1",
    permissions: %w[tabs storage cookies], host_permissions: ["<all_urls>"],
    raw: { "manifest_version" => 3, "name" => "X", "version" => "2.1",
           "permissions" => %w[tabs storage cookies], "host_permissions" => ["<all_urls>"] }
  }.freeze
  LISTING = { author: "Acme", users: "3,000,000", rating: "4.6", rating_count: "12.5K ratings",
              last_updated: "October 2, 2026", established_publisher: true }.freeze

  # Findings as the new rules store them: the overall level with access,
  # trust and headline, titles without risk words, and the new AI format.
  def new_findings(ai: true, summary: "It blocks ads <b>well</b>.")
    [
      { title: "Overall Risk: Medium", severity: "Medium", access: "Critical", trust: "established",
        headline: "Very powerful, established publisher", rules_version: 4,
        description: "Full control, established publisher." },
      { title: "All Websites Plus Cookies", severity: "Critical", description: "It can read your cookies.",
        rule: "combination.all_sites_cookies", evidence: [["permissions", 2], ["host_permissions", 0]] },
      { title: "Access to All Websites", severity: "High", description: "Every site.", rule: "host.all_sites",
        evidence: [["host_permissions", 0]] },
      { title: "Permission: tabs", severity: "Medium", description: "Tab addresses.", rule: "permission.tabs",
        evidence: [["permissions", 0]] },
      { title: "Permission: storage", severity: "Low", description: "Storage.", rule: "permission.storage",
        evidence: [["permissions", 1]] },
      (if ai
         { title: "AI Context Analysis", severity: "Info", description: "",
           ai: { concern_level: "none", purpose_fit: "fits", summary: summary,
                 trust_factors: ["Known publisher"], concerns: ["Reads every page"], recommendations: ["Keep it updated"],
                 model: "model-x", analyzed_at: "2026-11-16T12:00:00Z" } }
       end)
    ].compact
  end

  def store(id, findings, details: LISTING, name: "Demo Ext")
    ScanResult.create!(extension_id: id, extension_name: name, manifest: MANIFEST,
                       extension_details: details, security_findings: findings)
  end

  def show(id)
    get scan_path(id)
    assert_response :success
    if (dir = ENV["RENDER_DIR"]).present?
      html = response.body.sub("<head>", %(<head><base href="http://localhost:3122/">))
      File.write(File.join(dir, "#{name}.html"), html)
    end
  end

  def badge_text(selector)
    css_select(selector).map { |b| b.text.squish }
  end

  test "a scan rated with the new rules shows the verdict, both ratings, their evidence and the AI check" do
    store("ra" * 16, new_findings)
    show("ra" * 16)

    assert_select "#verdict[data-overall=Medium]" do
      assert_select "[data-badge=overall][data-level=medium]", text: "Medium risk"
      assert_select "#verdict-headline", text: "Very powerful, established publisher"
      assert_select "#verdict-advice", text: ScanRating::ADVICE.fetch("Medium")
    end
    assert_select "#verdict-access [data-badge=access][data-level=critical]", text: "Full control"
    assert_select "#verdict-access", text: /#{Regexp.escape(ScanRating::ACCESS_TIERS.first.summary)}/
    assert_select "#verdict-access [data-based-on]", text: "Based on the manifest, by fixed rules: 4 findings."
    assert_select "#verdict-trust [data-badge=trust][data-level=established]", text: "Established"
    assert_select "#verdict-trust [data-based-on]", text: "Based on the store listing and the AI check."
    assert_equal ["Established publisher badge", "3,000,000 users", "12,500 ratings", "Rated 4.6 of 5",
                  "Updated October 2, 2026", "Permissions fit its stated purpose (AI check)"],
                 badge_text("#verdict-signals [data-badge=signal]")
    assert_equal %w[good good good neutral neutral good], css_select("#verdict-signals [data-badge=signal]").map { |b| b["data-level"] }

    # The notable capabilities, by tier, each a link to its finding; the routine one is counted.
    assert_equal %w[critical high medium], css_select("#verdict-capabilities [data-tier]").map { |r| r["data-tier"] }
    assert_equal ["Full control", "Broad reach", "Scoped"], badge_text("#verdict-capabilities [data-badge=access]")
    links = css_select("#verdict-capabilities a[data-capability]")
    assert_equal ["All Websites Plus Cookies", "Access to All Websites", "Permission: tabs"], links.map { |a| a.text.strip }
    links.each do |link|
      target = css_select(link["href"]).first
      assert target, "#{link['href']} exists"
      assert_equal "", target["data-finding"]
      assert_includes target.text, link.text.strip
    end
    assert_select "[data-capability-more]", text: /Also 1 routine or minor finding\./

    # The AI check feeds trust: its two verdicts as chips, its text, its byline.
    assert_select "#ai-check[data-format=current]" do
      assert_select "h2", text: "AI check"
      assert_equal ["Fits its stated purpose", "No concerns"], badge_text("#ai-check [data-badge=signal]")
      assert_select "p", text: /It can lower trust, never raise it, and it never changes access\./
      assert_select "p", text: "It blocks ads <b>well</b>."
      assert_select "[data-ai-list=trust_factors] li", text: "Known publisher"
      assert_select "[data-ai-list=concerns] li", text: "Reads every page"
      assert_select "[data-ai-list=recommendations] li", text: "Keep it updated"
      assert_select "#ai-byline", text: "AI analysis by model-x on 2026-11-16 12:00 UTC"
      assert_select "#ai-earlier-note, details", count: 0
    end
    assert_select "#older-rules-note", count: 0
  end

  test "the header shows the overall level and both ratings, so they are on every tab" do
    store("rb" * 16, new_findings)
    show("rb" * 16)

    assert_select "#header-rating", count: 1
    assert_equal ["Medium risk", "Access: Full control", "Trust: Established"], badge_text("#header-rating .badge")
    assert_select "#header-rating .badge-label", count: 2, message: "Access and Trust are named on screen"
    assert css_select("#header-rating").first.ancestors("#tab-content").empty?, "outside the tab panels"
  end

  test "findings show their tier instead of the level word, and keep Show line" do
    store("rc" * 16, new_findings)
    show("rc" * 16)

    cookies = css_select("#overview [data-finding]").find { |f| f.text.include?("All Websites Plus Cookies") }
    assert_equal "Full control", cookies.at_css("[data-badge=access]").text.strip
    assert_includes cookies.at_css("[data-badge=access]")["class"], "bg-severity-critical"
    assert_select "#overview [data-finding] .bg-severity-high", text: "Broad reach"
    assert_select "#overview [data-finding] .bg-severity-low", text: "Routine"
    assert_no_match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/, css_select("#overview").text)
    assert_select "#overview [data-finding] button[data-manifest-lines]", minimum: 3
  end

  test "an earlier AI analysis is kept for reference and its level is said not to count" do
    findings = [{ title: "Overall Risk: Critical", severity: "Critical", rules_version: 2, description: "Old." },
                { title: "High-Risk Permission: tabs", severity: "High", description: "Old tabs." },
                { title: "AI Context Analysis", severity: "Info", description: "Risk Level: Low\nOld text.",
                  ai: { risk_level: "Low", summary: "Looks fine #{HOSTILE}", trust_factors: ["Popular"], concerns: [],
                        recommendations: ["Keep it updated"], model: "model-old", analyzed_at: "2025-05-01T09:30:00Z" } }]
    store("rd" * 16, findings)
    show("rd" * 16)

    # The page's rating comes from the stored level and the listing, never the AI's own level.
    assert_select "#verdict[data-overall=Medium] [data-badge=overall]", text: "Medium risk"
    assert_select "#verdict-access [data-badge=access]", text: "Full control"
    assert_select "#verdict-access [data-based-on]", text: /by an earlier version of the rules/
    assert_select "#verdict-trust [data-based-on]", text: /AI analysis is in an earlier format and does not count/
    assert_select "#verdict-signals [data-signal=purpose_fit], #verdict-signals [data-signal=concern_level]", count: 0

    assert_select "#ai-check[data-format=earlier]" do
      assert_select "h2", text: "Earlier AI analysis"
      assert_select "#ai-earlier-note", text: /It rated this extension Low, but the rating above no longer uses that\./
      assert_select "[data-badge]", count: 0, message: "no badge for a level that does not count"
      assert_select "details#ai-earlier-text:not([open]) summary", text: /Show the earlier analysis/
      assert_select "details p", text: "Looks fine #{HOSTILE}"
      assert_select "details [data-ai-list=recommendations] li", text: "Keep it updated"
      assert_select "details #ai-byline", text: "AI analysis by model-old on 2025-05-01 09:30 UTC"
    end
    assert_select "#older-rules-note"
    assert_select "#info-popup", text: /earlier version of the rules/
    assert_not_includes response.body, HOSTILE
  end

  test "the earliest text-only AI analysis is parsed the same way" do
    findings = [{ title: "Overall Risk: High", severity: "High", description: "Old." },
                { title: "AI Context Analysis", severity: "Info",
                  description: "Risk Level: High\nSummary text.\nTrust Factors:\n- Popular\nConcerns:\n- #{HOSTILE}" }]
    store("re" * 16, findings, details: {})
    show("re" * 16)

    assert_select "#verdict-access [data-badge=access]", text: "Broad reach"
    assert_select "#verdict-trust [data-badge=trust]", text: "Unproven"
    assert_equal ["No store listing data"], badge_text("#verdict-signals [data-badge=signal]")
    assert_select "#ai-check[data-format=earliest]" do
      assert_select "#ai-earlier-note", text: /It rated this extension High/
      assert_select "[data-ai-list=trust_factors] li", text: "Popular"
      assert_select "[data-ai-list=concerns] li", text: HOSTILE
      assert_select "#ai-byline", count: 0
    end
    assert_not_includes response.body, HOSTILE
  end

  test "without an AI finding, trust rests on the listing alone" do
    store("rf" * 16, new_findings(ai: false))
    show("rf" * 16)

    assert_select "#ai-check", count: 0
    assert_select "#verdict-trust [data-based-on]", text: "Based on the store listing alone: this scan has no AI check."
    assert_select "#verdict-trust [data-badge=trust]", text: "Established"
  end

  test "the AI check can lower trust, and the page says why" do
    findings = new_findings
    findings.last[:ai] = findings.last[:ai].merge(concern_level: "serious", purpose_fit: "does_not_fit")
    store("rg" * 16, findings)
    show("rg" * 16)

    assert_select "#verdict-trust [data-badge=trust][data-level=concerns]", text: "Warning signs"
    assert_select "#verdict [data-badge=overall]", text: "Critical risk"
    assert_select "#verdict-signals [data-signal=purpose_fit][data-level=bad]", text: /do not fit/
    assert_select "#verdict-signals [data-signal=concern_level][data-level=bad]", text: /serious warning signs/
    assert_equal ["Does not fit its stated purpose", "Serious concerns"], badge_text("#ai-check h2 ~ [data-badge=signal]")
  end

  test "a scan with nothing flagged says so in the access column" do
    store("rh" * 16, [{ title: "Overall Risk: Minimal", severity: "Minimal", access: "Minimal", trust: "unproven", rules_version: 4 }],
          details: {})
    show("rh" * 16)

    assert_select "#verdict-access [data-badge=access][data-level=minimal]", text: "Minimal"
    assert_select "#verdict-access [data-based-on]", text: /nothing was flagged\./
    assert_select "#verdict-capabilities, [data-capability-more]", count: 0
    assert_select "#verdict [data-badge=overall]", text: "Minimal risk"
  end

  test "hostile names, titles, levels and AI text are escaped everywhere on the card" do
    findings = [{ title: "Overall Risk: #{HOSTILE}", severity: HOSTILE, access: HOSTILE, headline: HOSTILE },
                { title: HOSTILE, severity: "High", description: HOSTILE },
                { title: "Odd", severity: HOSTILE, description: "x" },
                { title: "AI Context Analysis", severity: "Info",
                  ai: { concern_level: HOSTILE, purpose_fit: "fits", summary: HOSTILE, concerns: [HOSTILE, { a: 1 }], model: HOSTILE } }]
    store("ri" * 16, findings, details: { users: HOSTILE, rating: HOSTILE, last_updated: HOSTILE }, name: HOSTILE)
    show("ri" * 16)

    assert_not_includes response.body, HOSTILE
    assert_not_includes response.body, "<img src=x"
    assert_select "#verdict-access [data-badge=access]", text: "Minimal", message: "an unknown stored level is no access tier"
    assert_select "#verdict-headline", text: "Minimal access, unproven publisher"
    assert_select "#verdict-capabilities a", text: HOSTILE
    assert_select "#overview [data-finding] [data-badge][data-level=unrated]", text: /\A"><img src=x onerro…\z/
    assert_select "#ai-check [data-ai-list=concerns] li", count: 1, text: HOSTILE
    assert_select "#ai-byline", text: "AI analysis by #{HOSTILE}"
    assert_select "h1", text: HOSTILE
  end
end
