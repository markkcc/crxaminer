require "test_helper"

# The single pass that works out every statistic (RefreshStatsJob).
class ScanStatsCollectorTest < ActiveSupport::TestCase
  setup { ScanResult.delete_all }

  def scan(number, manifest: {}, details: {}, findings: [], **attributes)
    ScanResult.create!({ extension_id: format("%032d", number), extension_name: "Ext #{number}", manifest: manifest,
                         extension_details: details, security_findings: findings }.merge(attributes))
  end

  def collect
    ScanStats::Collector.run
  end

  def overall(level, **extra)
    [{ title: "Overall Risk: #{level}", severity: level }.merge(extra)]
  end

  test "counts extensions that can run on every site as the rules see them" do
    scan(1, manifest: { manifest_version: 3, host_permissions: ["*://*/*"] })
    scan(2, manifest: { manifest_version: 2, permissions: ["tabs", "http://*/*"] })
    scan(3, manifest: { manifest_version: 3, content_scripts: [{ matches: ["<all_urls>"] }] })
    scan(4, manifest: { manifest_version: 3, host_permissions: ["https://*/*"], content_scripts: [{ matches: ["*://*.com/*"] }] })
    scan(5, manifest: { manifest_version: 3, host_permissions: ["https://*.example.com/*"],
                        content_scripts: [{ matches: ["https://example.org/*"] }] })
    scan(6, manifest: { manifest_version: 3, optional_host_permissions: ["<all_urls>"] })
    # Chrome ignores a match pattern in a Manifest V3 "permissions" list.
    scan(7, manifest: { manifest_version: 3, permissions: ["<all_urls>"] })
    # The manifest as written wins over the extracted copy.
    scan(8, manifest: { host_permissions: [], raw: { manifest_version: 3, host_permissions: ["<all_urls>"] } })

    values = collect.values
    assert_equal({ "scans" => 8, "any" => 5, "host_access" => 4, "content_scripts" => 2 }, values[:all_sites])
    assert_equal 1, values[:all_urls], "the older count is the literal string in the stored lists, as before"
  end

  test "splits scans by manifest version" do
    [3, 2, "2", 2.0, nil, "three", 4, "<b>2</b>"].each_with_index { |version, i| scan(i, manifest: { manifest_version: version }) }

    assert_equal({ "2" => 3, "3" => 1, "other" => 4 }, collect.values[:manifest_versions])
  end

  test "ranks the permissions asked for at install, once per extension, leaving out patterns and junk" do
    scan(1, manifest: { manifest_version: 3, permissions: %w[storage tabs storage] })
    scan(2, manifest: { manifest_version: 2, permissions: ["tabs", "https://*/*", "<all_urls>"] })
    scan(3, manifest: { manifest_version: 3, permissions: ["tabs", "weird name!", "<script>", 7, nil, "x" * 80, "https://a.example/*"],
                        optional_permissions: ["cookies"] })
    scan(4, manifest: { permissions: "tabs" })

    assert_equal({ "scans" => 4, "top" => [{ "name" => "tabs", "count" => 3 }, { "name" => "storage", "count" => 1 }] },
                 collect.values[:permissions])
  end

  test "keeps only the ten most requested permissions, by count then name" do
    names = ("a".."l").map { |letter| "perm#{letter.upcase}" }
    names.each_with_index do |_, i|
      scan(i, manifest: { manifest_version: 3, permissions: names.first(i + 1) })
    end

    top = collect.values[:permissions]["top"]
    assert_equal names.first(10), top.map { |entry| entry["name"] }
    assert_equal [12, 11, 10, 9, 8, 7, 6, 5, 4, 3], top.map { |entry| entry["count"] }
  end

  test "groups extensions by the users their listing shows" do
    ["500", "1,000", "10,000+", "999,999", "5,000,000", 2_000_000, nil, "Share"].each_with_index do |users, i|
      scan(i, details: { users: users })
    end
    scan(20, details: "junk")

    assert_equal({ "buckets" => { "under_1k" => 1, "1k_10k" => 1, "10k_100k" => 1, "100k_1m" => 1, "1m_plus" => 2 },
                   "unknown" => 3 }, collect.values[:users])
  end

  test "lists the most installed extensions in the Full control tier" do
    # Rated with the two ratings: the tier is the stored access level, whatever the overall level.
    scan(1, details: { users: "9,000,000" }, findings: overall("Medium", access: "Critical", trust: "established", rules_version: 4),
            extension_image: "https://img.example/1.png")
    scan(2, details: { users: "50,000,000" }, findings: overall("Critical", access: "High", trust: "concerns", rules_version: 4))
    # Rated before the two ratings: the overall level was the access level.
    scan(3, details: { users: "2,000,000" }, findings: overall("Critical"))
    scan(4, details: { users: "70,000,000" }, findings: overall("High"))
    scan(5, details: {}, findings: overall("Critical"))
    scan(6, details: { users: "3,000" }, findings: overall("Critical"), extension_image: "javascript:alert(1)")
    scan(7, details: { users: "2,000,000" }, findings: overall("Critical"))
    scan(8, details: { users: "100" }, findings: overall("Critical"))
    scan(9, details: { users: "10" }, findings: overall("Critical"))

    popular = collect.values[:popular_full_control]
    assert_equal [1, 3, 7, 6, 8].map { |n| format("%032d", n) }, popular.map { |e| e["extension_id"] },
                 "by users, earlier scan first on a tie, five at most"
    assert_equal [9_000_000, 2_000_000, 2_000_000, 3_000, 100], popular.map { |e| e["users"] }
    assert_equal({ "extension_id" => format("%032d", 1), "extension_name" => "Ext 1",
                   "extension_image" => "https://img.example/1.png", "users" => 9_000_000 }, popular.first)
    assert_nil popular[3]["extension_image"], "only https images are kept"
  end

  test "works out the older statistics in the same pass" do
    scan(1, findings: overall("High"), created_at: 40.days.ago)
    scan(2, findings: ExtensionSecurityAnalyzer.rule_findings(permissions: %w[debugger history]))
    scan(3, findings: overall("High"))

    values = collect.values
    assert_equal({ "Critical" => 1, "High" => 2, "Medium" => 0, "Low" => 0, "Minimal" => 0 }, values[:levels])
    assert_equal 2, values[:recent]
    assert_equal [[format("%032d", 2), 2], [format("%032d", 1), 0], [format("%032d", 3), 0]],
                 values[:spiciest].map { |e| [e["extension_id"], e["finding_count"]] }
  end

  def scan_queries
    queries = []
    callback = ->(*, payload) { queries << payload[:sql] if payload[:sql].include?("scan_results") && payload[:name] != "SCHEMA" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
    queries
  end

  test "reads the scans in one query per batch and never fetches the embedded URLs" do
    5.times { |i| scan(i, manifest: { manifest_version: 3, permissions: ["tabs"], embedded_urls: ["https://a.example/"] * 50 }) }

    result = nil
    queries = scan_queries { result = collect }
    assert_equal 1, queries.size, queries.inspect
    assert_includes queries.first, "manifest - 'embedded_urls'"
    assert_no_match(/"scan_results"\.\*|@>|COUNT/i, queries.first)
    assert_equal 5, result.scans

    stub_const(ScanStats::Collector, :BATCH_SIZE, 2) do
      queries = scan_queries { result = collect }
    end
    assert_equal 3, queries.size, "5 scans in batches of 2"
    assert_equal 5, result.scans
    assert_equal 5, result.values[:permissions]["top"].first["count"]
  end

  test "the manifest it reads has everything the rules read except the embedded URLs" do
    scan(1, manifest: { manifest_version: 3, permissions: ["tabs"], embedded_urls: ["https://a.example/"], raw: { name: "x" } })
    record = ScanResult.select(ScanStats::Collector::COLUMNS).first

    assert_equal({ "manifest_version" => 3, "permissions" => ["tabs"], "raw" => { "name" => "x" } }, record[:slim_manifest])
  end

  test "stored junk of any shape is counted without an error" do
    scan(1, manifest: { permissions: { a: 1 }, host_permissions: 7, content_scripts: "x", manifest_version: [] },
            details: { users: { a: 1 } }, findings: [1, "x", nil, { title: 5, severity: [] }])
    scan(2)
    scan(3)
    scan(4)
    connection = ScanResult.connection
    connection.execute(%(UPDATE scan_results SET manifest = '"junk"', extension_details = '[1]', security_findings = '"junk"' WHERE extension_id = '#{format('%032d', 2)}'))
    connection.execute(%(UPDATE scan_results SET manifest = '[1, 2]', extension_details = '7', security_findings = '{"a": 1}' WHERE extension_id = '#{format('%032d', 3)}'))
    connection.execute(%(UPDATE scan_results SET manifest = NULL, extension_details = NULL, security_findings = NULL, extension_name = NULL WHERE extension_id = '#{format('%032d', 4)}'))

    result = nil
    log = capture_rails_log { result = collect }
    assert_equal 4, result.scans
    assert_empty result.failed
    assert_no_match(/skipped scan/, log)
    assert_equal({ "scans" => 4, "any" => 0, "host_access" => 0, "content_scripts" => 0 }, result.values[:all_sites])
    assert_equal({ "2" => 0, "3" => 0, "other" => 4 }, result.values[:manifest_versions])
    assert_equal 4, result.values[:users]["unknown"]
  end

  test "a statistic that raises on every scan is reported as failed and the others carry on" do
    3.times { |i| scan(i, manifest: { manifest_version: 3, permissions: ["tabs"] }, details: { users: "5,000" }) }

    result = nil
    log = capture_rails_log do
      ScanStats.stub(:user_bucket, ->(_) { raise "boom" }) { result = collect }
    end
    assert_equal [:users], result.failed
    assert_nil result.values[:users]
    assert_equal 3, result.values[:permissions]["top"].first["count"]
    assert_equal({ "2" => 0, "3" => 3, "other" => 0 }, result.values[:manifest_versions])
    assert_match(/Statistic users skipped scan \d+: RuntimeError: boom/, log)
    assert_equal 1, log.scan("skipped scan").size, "one log line, not one per scan"
  end

  test "a scan that one statistic cannot read is skipped for that statistic only" do
    scan(1, details: { users: "13" })
    scan(2, details: { users: "5,000" })
    scan(3, details: { users: "6,000" })
    real = ScanStats.method(:user_bucket)

    result = ScanStats.stub(:user_bucket, ->(users) { users == 13 ? raise("boom") : real.call(users) }) { collect }
    assert_empty result.failed
    assert_equal 2, result.values[:users]["buckets"]["1k_10k"]
    assert_equal 3, result.values[:manifest_versions]["other"]
  end

  test "a statistic that keeps raising is switched off" do
    6.times { |i| scan(i, details: { users: i < 4 ? "13" : "5,000" }) }
    real = ScanStats.method(:user_bucket)

    result = nil
    log = capture_rails_log do
      stub_const(ScanStats::Collector, :MAX_ERRORS, 2) do
        ScanStats.stub(:user_bucket, ->(users) { users == 13 ? raise("boom") : real.call(users) }) { result = collect }
      end
    end
    assert_equal [:users], result.failed
    assert_match(/Statistic users switched off after 3 errors/, log)
  end

  test "the manifest summary reads a stored manifest as the rules do" do
    manifest = { "manifest_version" => "2", "permissions" => ["tabs", "*://*/*", 5], "content_scripts" => [{ "matches" => ["https://*/*"] }, "x"] }
    summary = ExtensionSecurityAnalyzer.manifest_summary(manifest)
    rules = ExtensionSecurityAnalyzer.rule_findings(manifest).filter_map { |f| f[:rule] }

    assert_equal 2, summary.manifest_version
    assert_equal ["tabs"], summary.permissions
    assert summary.all_sites_host_access
    assert summary.all_sites_content_scripts
    assert_includes rules, "host.all_sites"
    assert_includes rules, "content_script.all_sites"

    [nil, "x", [], 5, {}].each do |junk|
      empty = ExtensionSecurityAnalyzer.manifest_summary(junk)
      assert_equal [nil, [], false, false], empty.to_a
    end
  end

  test "the stored access level is the access rating, or the overall level on older scans" do
    assert_equal "Critical", ScanRating.stored_access_level(overall("Medium", access: "Critical"))
    assert_equal "High", ScanRating.stored_access_level(overall("High"))
    [nil, "x", [], [1, nil], [{ title: "Permission: tabs", severity: "Low" }]].each do |findings|
      assert_nil ScanRating.stored_access_level(findings)
    end
  end
end
