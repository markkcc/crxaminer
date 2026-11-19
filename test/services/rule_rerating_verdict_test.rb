require "test_helper"

# Part 5: re-rating rebuilds the whole verdict of scans rated with rules
# version none, 2 and 3 from stored data alone.
class RuleReratingVerdictTest < ActiveSupport::TestCase
  RAW = { "manifest_version" => 3, "permissions" => %w[storage proxy], "host_permissions" => ["<all_urls>"] }.freeze
  MANIFEST = { manifest_version: 3, permissions: RAW["permissions"], host_permissions: RAW["host_permissions"], raw: RAW }.freeze
  POPULAR = { users: "39,000,000", rating_count: "44.7K ratings", rating: "4.5" }.freeze
  OLD_AI = { "severity" => "Info", "title" => "AI Context Analysis", "description" => "Risk Level: Low\nOld text.",
             "ai" => { "risk_level" => "Low", "summary" => "Old text.", "input_digest" => "d1" } }.freeze
  NEW_AI = { "severity" => "Info", "title" => "AI Context Analysis", "description" => "Odd.\nSome concerns.",
             "ai" => { "concern_level" => "some", "purpose_fit" => "broader_than_needed", "summary" => "Odd.",
                       "trust_factors" => [], "concerns" => ["x"], "recommendations" => [], "input_digest" => "d2" } }.freeze

  setup do
    ScanResult.delete_all
    stamp = Time.utc(2026, 3, 4, 5, 6, 7)
    @none = create("1", [{ "severity" => "High", "title" => "Overall Risk: High", "description" => "Based on 3 findings." },
                         { "severity" => "High", "title" => "High-Risk Permission: proxy", "description" => "old" }, OLD_AI], POPULAR)
    @v2 = create("2", [{ "severity" => "High", "title" => "Overall Risk: High", "description" => "x", "rules_version" => 2 }], POPULAR)
    @v3 = create("3", [{ "severity" => "High", "title" => "Overall Risk: High", "description" => "x", "rules_version" => 3 }, NEW_AI],
                 { "users" => "300" })
    @v4 = create("4", ExtensionSecurityAnalyzer.rated_findings(MANIFEST, extension_details: POPULAR), POPULAR)
    [@none, @v2, @v3, @v4].each { |scan| scan.update_columns(updated_at: stamp) }
  end

  def create(digit, findings, details)
    ScanResult.create!(extension_id: digit * 32, extension_name: "Scan #{digit}", manifest: MANIFEST,
                       extension_details: details, security_findings: findings)
  end

  def stored(scan)
    JSON.parse(ScanResult.connection.select_value("SELECT security_findings FROM scan_results WHERE id = #{scan.id}"))
  end

  test "only scans below rules version 4 are selected" do
    assert_equal [@none.id, @v2.id, @v3.id].sort, RuleRerating.candidates.pluck(:id).sort
  end

  test "the dry run reports how the overall and the shown levels would change, and writes nothing" do
    before = ScanResult.order(:id).pluck(:security_findings, :updated_at)
    out = StringIO.new
    result = RuleRerating.new(dry_run: true, out: out).run

    # Full control (proxy): established publisher -> Medium; the v3 scan's
    # unproven listing and AI concerns -> Critical.
    assert_equal({ %w[High Medium] => 2, %w[High Critical] => 1 }, result.changes)
    # The none-version scan showed its old AI level (Low).
    assert_equal({ %w[Low Medium] => 1, %w[High Medium] => 1, %w[High Critical] => 1 }, result.display_changes)
    assert_match(/Overall level \(the overall finding\), before -> after:\n  High\s+-> Critical\s+1\n  High\s+-> Medium\s+2/, out.string)
    assert_match(/Level shown in statistics and lists, before -> after:/, out.string)
    assert_match(/Low\s+-> Medium\s+1/, out.string)
    assert_equal before, ScanResult.order(:id).pluck(:security_findings, :updated_at)
  end

  test "a real run rebuilds the verdict from stored data, keeps AI findings and updated_at, and calls nothing" do
    stamps = ScanResult.order(:id).pluck(:id, :updated_at)
    NoTweetsInTests::POSTED.clear
    AiContextAnalysis.stub(:new, ->(**) { raise "must not be called" }) do
      assert_equal 3, RuleRerating.new(all: true, out: StringIO.new).run.updated
    end
    assert_equal stamps, ScanResult.order(:id).pluck(:id, :updated_at)
    assert_empty NoTweetsInTests::POSTED

    none = stored(@none)
    assert_equal({ "severity" => "Medium", "title" => "Overall Risk: Medium", "rules_version" => 4, "access" => "Critical",
                   "trust" => "established", "headline" => "Very powerful, established publisher" }, none.first.except("description"))
    assert_equal ["Permission: proxy", "Access to All Websites", "Permission: storage"], none[1...-1].map { |f| f["title"] }
    assert_equal OLD_AI, none.last, "the old AI finding stays exactly as stored and adds nothing to trust"

    v3 = stored(@v3)
    assert_equal %w[Critical concerns Critical], v3.first.values_at("severity", "trust", "access")
    assert_equal NEW_AI, v3.last
    assert_equal %w[Medium established], stored(@v2).first.values_at("severity", "trust")
    assert_equal 4, stored(@v2).size, "no AI finding is added"

    assert_equal %w[Medium Medium Critical Medium],
                 [@none, @v2, @v3, @v4].map { |scan| ScanDisplayLevel.for(stored(scan)) }
    assert_empty RuleRerating.candidates
  end

  test "junk stored details and findings do not stop the run" do
    junk = ScanResult.create!(extension_id: "9" * 32, manifest: MANIFEST, extension_details: nil,
                              security_findings: ["x", 5, nil, { "title" => "AI Context Analysis", "severity" => "Info", "ai" => "?" }])
    ScanResult.where(id: junk.id).update_all("extension_details = '\"junk\"'::jsonb")
    result = RuleRerating.new(all: true, out: StringIO.new).run
    assert_equal 0, result.failed
    findings = stored(junk)
    assert_equal %w[Critical unproven], findings.first.values_at("severity", "trust")
    assert_equal({ "title" => "AI Context Analysis", "severity" => "Info", "ai" => "?" }, findings.last)
  end
end
