require "test_helper"

class RuleReratingTest < ActiveSupport::TestCase
  RAW = { "manifest_version" => 3, "permissions" => %w[storage cookies], "host_permissions" => ["<all_urls>"] }.freeze
  MANIFEST = { manifest_version: 3, permissions: %w[storage cookies], host_permissions: ["<all_urls>"], raw: RAW }.freeze
  OLD_FINDINGS = [
    { severity: "Medium", title: "Overall Risk: Medium", description: "Based on 3 total findings, including 1 high-risk finding." },
    { severity: "Medium", title: "Medium-Risk Permission: storage", description: "old" },
    { severity: "High", title: "High-Risk Permission: cookies", description: "old" },
    { severity: "High", title: "Broad Host Permissions", description: "old" }
  ].freeze
  AI = { "severity" => "Info", "title" => "AI Context Analysis", "description" => "Risk Level: Low\nKept as is.",
         "ai" => { "risk_level" => "Low", "input_digest" => "abc", "model" => "m", "z_last" => [1, { "b" => 2, "a" => 1 }] } }.freeze

  setup do
    NoTweetsInTests::POSTED.clear
    ScanResult.delete_all
    @old = ScanResult.create!(extension_id: "1" * 32, manifest: MANIFEST, security_findings: OLD_FINDINGS + [AI])
    @old.update_columns(updated_at: Time.utc(2026, 1, 2, 3, 4, 5))
    @no_ai = ScanResult.create!(extension_id: "2" * 32, manifest: { manifest_version: 2, raw: { "manifest_version" => 2 } },
                                security_findings: [{ severity: "Minimal", title: "Overall Risk: Minimal", description: "x" }])
    @current = ScanResult.create!(extension_id: "3" * 32, manifest: MANIFEST,
                                  security_findings: ExtensionSecurityAnalyzer.rule_findings(MANIFEST))
    @no_manifest = ScanResult.create!(extension_id: "4" * 32, manifest: {}, security_findings: OLD_FINDINGS)
    @junk = ScanResult.create!(extension_id: "5" * 32, manifest: { permissions: "tabs", raw: "x", content_scripts: [5] },
                               security_findings: ["junk", 5, nil])
  end

  def runner(**opts)
    @out = StringIO.new
    RuleRerating.new(out: @out, **opts)
  end

  test "selects scans with a manifest whose overall finding lacks the current rules version" do
    assert_equal [@old.id, @no_ai.id, @junk.id].sort, RuleRerating.candidates.pluck(:id).sort
    assert_equal [@no_ai.id, @junk.id], RuleRerating.candidates(after_id: @old.id).order(:id).pluck(:id)
  end

  test "a real run needs LIMIT or ALL" do
    result = runner.run
    assert result.refused
    assert_match(/Pass DRY_RUN=1 to preview, or LIMIT=n or ALL=1/, @out.string)
    assert_equal OLD_FINDINGS.size + 1, @old.reload.security_findings.size
  end

  test "a dry run reports how overall ratings would change and writes nothing" do
    before = ScanResult.order(:id).pluck(:security_findings, :updated_at)
    result = runner(dry_run: true).run

    assert_equal 3, result.processed
    assert_equal({ %w[Medium Critical] => 1, %w[Minimal Low] => 1, ["(none)", "Minimal"] => 1 }, result.changes)
    assert_match(/Medium\s+-> Critical\s+1/, @out.string)
    assert_match(/Minimal\s+-> Low\s+1/, @out.string)
    assert_match(/nothing was written/, @out.string)
    assert_equal before, ScanResult.order(:id).pluck(:security_findings, :updated_at)
  end

  test "re-rates from the stored manifest, keeps the AI finding exactly and updated_at unchanged, never calls out" do
    before = @old.reload.updated_at
    client_calls = 0
    AiContextAnalysis.stub(:new, ->(**) { client_calls += 1; raise "must not be called" }) do
      result = runner(all: true).run
      assert_equal 3, result.updated
    end

    @old.reload
    findings = @old.security_findings
    assert_equal before, @old.updated_at
    assert_equal 0, client_calls
    assert_empty NoTweetsInTests::POSTED

    assert_equal "Overall Risk: Critical", findings.first[:title]
    assert_equal ExtensionSecurityAnalyzer::RULES_VERSION, findings.first[:rules_version]
    assert_equal ExtensionSecurityAnalyzer.rule_findings(@old.manifest), findings[0...-1]
    assert_not findings.any? { |f| f[:title] == "Broad Host Permissions" }
    # The AI finding is the last one and identical to what was stored (jsonb does not keep key order).
    stored = JSON.parse(ScanResult.connection.select_value("SELECT security_findings FROM scan_results WHERE id = #{@old.id}"))
    assert_equal AI, stored.last

    # Junk findings are replaced by the current rule findings.
    assert_equal "Overall Risk: Minimal", @junk.reload.security_findings.first[:title]
    # The scan without a manifest is left alone.
    assert_equal OLD_FINDINGS.map { |f| f[:title] }, @no_manifest.reload.security_findings.map { |f| f[:title] }
  end

  test "is idempotent and resumable" do
    first = runner(limit: 1).run
    assert_equal 1, first.updated
    assert_equal @old.id, first.last_id
    assert_match(/continue with AFTER_ID=#{@old.id}/, @out.string)

    second = runner(all: true).run
    assert_equal 2, second.eligible
    assert_equal 2, second.updated

    third = runner(all: true).run
    assert_equal 0, third.eligible
    assert_equal 0, third.processed
  end

  test "a scan re-scanned while the task runs is not overwritten" do
    rerating = runner(all: true)
    @old.reload
    # Simulates a re-scan between loading the scan and writing it.
    ScanResult.where(id: @old.id).update_all(updated_at: Time.utc(2026, 5, 5))
    status, = rerating.send(:rerate, @old)
    assert_equal :write_conflict, status
    assert_equal "Overall Risk: Medium", @old.reload.security_findings.first[:title]
  end

  test "the rake task is defined with the documented options" do
    require "rake"
    Rake::TaskManager.record_task_metadata = true
    Rails.application.load_tasks unless Rake::Task.task_defined?("rules:rerate")
    task = Rake::Task["rules:rerate"]
    %w[DRY_RUN LIMIT ALL AFTER_ID].each { |option| assert_includes task.full_comment, option }
  end
end
