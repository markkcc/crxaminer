require "test_helper"

# The statistics page: the cards it shows from the saved numbers, and that a
# missing or broken statistic never takes the rest of the page with it.
class StatsDashboardTest < ActionDispatch::IntegrationTest
  include ActiveJob::TestHelper

  setup do
    ScanResult.delete_all
    StatCache.delete_all
  end

  def scan(number, name: "Ext #{number}", users: nil, manifest: {}, findings: [{ title: "Overall Risk: High", severity: "High" }], image: nil)
    ScanResult.create!(extension_id: format("%032d", number), extension_name: name, extension_image: image,
                       manifest: { manifest_version: 3 }.merge(manifest), extension_details: { users: users }.compact,
                       security_findings: findings)
  end

  CRITICAL = [{ title: "Overall Risk: Critical", severity: "Critical" }].freeze

  def populate
    scan(1, name: "Big Blocker", users: "17,000,000", findings: CRITICAL, image: "https://img.example/1.png",
            manifest: { permissions: %w[storage tabs debugger], host_permissions: ["<all_urls>"] })
    scan(2, name: %(<img src=x onerror="alert(1)">), users: "3,000", findings: CRITICAL,
            manifest: { permissions: %w[storage tabs], content_scripts: [{ matches: ["*://*/*"] }] })
    scan(3, users: "500", manifest: { manifest_version: 2, permissions: ["storage", "madeUpPermission", "https://*/*"] })
    scan(4, manifest: { permissions: ["storage"], host_permissions: ["https://example.com/*"] })
    RefreshStatsJob.perform_now
  end

  def tile(key)
    css_select("[data-stat-row=tiles] [data-stat=#{key}]").first
  end

  ALL_CARDS = %w[total recent all-sites manifest-v2 popular-full-control users permissions spiciest ratings].freeze

  def cards
    css_select("[data-stat]").map { |card| card["data-stat"] }
  end

  test "shows every card from the saved statistics" do
    populate
    get stats_scan_index_path
    assert_response :success
    assert_equal ALL_CARDS, cards

    assert_equal "4", tile("total").at_css("[data-stat-value]").text
    assert_equal "4", tile("recent").at_css("[data-stat-value]").text

    all_sites = tile("all-sites")
    assert_equal "Can run on every site", all_sites.at_css("h2").text
    assert_equal "3", all_sites.at_css("[data-stat-value]").text
    assert_equal ["75% of scanned extensions", "Host access: 2 · Content scripts: 1"], all_sites.css("[data-stat-note]").map(&:text)
    assert_select "[data-stat=all-urls]", count: 0

    v2 = tile("manifest-v2")
    assert_equal "Still on Manifest V2", v2.at_css("h2").text
    assert_equal "1", v2.at_css("[data-stat-value]").text
    assert_equal ["25% of scanned extensions", "Manifest V3: 3"], v2.css("[data-stat-note]").map(&:text)

    assert_select "#stats-pending", count: 0
    assert_select "#stats-updated time[datetime]", text: /\A\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\z/
    assert_no_enqueued_jobs only: RefreshStatsJob
  end

  test "the permissions card ranks permissions with the tier the rules give each" do
    populate
    get stats_scan_index_path

    rows = css_select("[data-stat=permissions] [data-share]").map do |row|
      [row["data-share"], row.at_css("[data-share-percent]").text, row.at_css("[data-share-count]").text,
       row.at_css("[data-badge]")&.text&.strip, row.at_css("[style]")["style"]]
    end
    assert_equal [
      ["storage", "100%", "4", "Routine", "width: 100.0%;"],
      ["tabs", "50%", "2", "Scoped", "width: 50.0%;"],
      ["debugger", "25%", "1", "Full control", "width: 25.0%;"],
      ["madeUpPermission", "25%", "1", nil, "width: 25.0%;"]
    ], rows
    assert_select "[data-stat=permissions] [data-share=debugger] .bg-severity-critical", count: 2
  end

  test "the users card shows each bucket as a share of the scans that have a user count" do
    populate
    get stats_scan_index_path

    rows = css_select("[data-stat=users] [data-share]").map do |row|
      [row["data-share"], row.at_css("[data-share-percent]").text, row.at_css("[data-share-count]").text]
    end
    assert_equal [["under_1k", "33%", "1"], ["1k_10k", "33%", "1"], ["10k_100k", "0%", "0"], ["100k_1m", "0%", "0"],
                  ["1m_plus", "33%", "1"]], rows
    assert_equal "1 more has no user count saved.", css_select("[data-users-unknown]").text.squish
  end

  test "the extension lists link to the scans, escape names and need no query for them" do
    populate
    queries = []
    callback = ->(*, payload) { queries << payload[:sql] if payload[:sql].include?("scan_results") && payload[:name] != "SCHEMA" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { get stats_scan_index_path }

    popular = css_select("[data-stat=popular-full-control] li a")
    assert_equal [scan_path(format("%032d", 1)), scan_path(format("%032d", 2))], popular.map { |a| a["href"] }
    assert_equal ["17,000,000 users", "3,000 users"], popular.map { |a| a.at_css("[data-extension-number]").text }
    assert_equal "Big Blocker", popular.first.at_css("span.truncate").text
    assert_equal "https://img.example/1.png", popular.first.at_css("img")["src"]
    assert_includes popular.last.text, %(<img src=x onerror="alert(1)">)
    assert_not_includes response.body, "<img src=x onerror"

    spiciest = css_select("[data-stat=spiciest] li a")
    assert_equal 4, spiciest.size
    assert_match(/\A\d+ findings?\z/, spiciest.first.at_css("[data-extension-number]").text)

    assert_equal 2, queries.size, "the count and the recent scans: #{queries.inspect}"
    assert_no_match(/"scan_results"\.\*/, queries.join("\n"), "the recent scans are read without their manifests")
  end

  test "with nothing saved yet the page says so and asks for the statistics once" do
    scan(1)
    store = ActiveSupport::Cache::MemoryStore.new
    Rails.stub(:cache, store) do
      assert_enqueued_jobs 1, only: RefreshStatsJob do
        get stats_scan_index_path
        assert_response :success
        get stats_scan_index_path
        get stats_scan_index_path
      end
      travel(ScanController::STATS_REFRESH_EVERY + 1.minute) do
        assert_enqueued_jobs(1, only: RefreshStatsJob) { get stats_scan_index_path }
      end
    end

    assert_select "#stats-pending", text: /being worked out/
    assert_equal %w[total recent ratings], cards
    assert_select "[data-stat=recent] [data-stat-value]", text: "0"
    assert_select "[role=group] button.severity-filter-btn", count: 5
    assert_select "#recent-scans-tbody tr", count: 1
    assert_select "#stats-updated", count: 0
  end

  test "a queue that cannot take the refresh does not stop the page" do
    log = capture_rails_log do
      RefreshStatsJob.stub(:perform_later, -> { raise "queue down" }) { get stats_scan_index_path }
    end
    assert_response :success
    assert_match(/statistics refresh could not be queued: RuntimeError: queue down/, log)
  end

  test "before the migration has run the page shows the older statistics" do
    populate
    row = StatCache.select(:id, :severity_counts, :spiciest_extensions, :scans_last_30_days, :all_urls_count, :created_at, :updated_at).first

    StatCache.stub(:current, row) { get stats_scan_index_path }
    assert_response :success
    assert_equal %w[total recent all-urls spiciest ratings], cards
    assert_equal "Ext. with <all_urls>", tile("all-urls").at_css("h2").text
    assert_equal "1", tile("all-urls").at_css("[data-stat-value]").text, "the literal string, as this tile always counted"
    assert_select "[data-stat-row=tiles].md\\:grid-cols-3", count: 1
    assert_no_enqueued_jobs only: RefreshStatsJob
  end

  test "once the migration has run, a row saved before it asks for a refresh" do
    populate
    StatCache.update_all(metrics: nil)

    assert_enqueued_jobs(1, only: RefreshStatsJob) { get stats_scan_index_path }
    assert_response :success
    assert_equal %w[total recent all-urls spiciest ratings], cards

    perform_enqueued_jobs only: RefreshStatsJob
    get stats_scan_index_path
    assert_equal ALL_CARDS, cards
  end

  JUNK = [nil, [], "x", 5, {}, [nil], { "top" => 3, "buckets" => "x", "any" => [], "scans" => {} }].freeze

  test "statistics saved in the wrong shape leave their cards out and the page up" do
    populate
    good = StatCache.current.metrics

    ScanStats::METRIC_KEYS.each do |key|
      JUNK.each do |junk|
        StatCache.update_all(metrics: good.merge(key => junk))
        get stats_scan_index_path
        assert_response :success, "#{key} saved as #{junk.inspect}"
        missing = { "all_sites" => "all-sites", "manifest_versions" => "manifest-v2", "popular_full_control" => "popular-full-control" }.fetch(key, key)
        # Without the newer all-sites count the tile falls back to the older one.
        expected = ALL_CARDS.map { |card| card == missing && key == "all_sites" ? "all-urls" : card } - [missing]
        assert_equal expected, cards, "#{key} saved as #{junk.inspect}"
      end
    end

    (JUNK - [{}]).each do |junk|
      StatCache.update_all(metrics: junk, severity_counts: junk, spiciest_extensions: junk)
      get stats_scan_index_path
      assert_response :success, "everything saved as #{junk.inspect}"
      assert_includes cards, "ratings"
      assert_select "#recent-scans-tbody tr", count: 4
    end
  end

  test "a statistic that cannot be read or shown is left out and logged, and the others still appear" do
    populate
    stats = ScanStats::Dashboard.load
    stats.define_singleton_method(:users) { raise "boom reading" }
    stats.define_singleton_method(:permissions) { [Object.new] }

    log = capture_rails_log do
      ScanStats::Dashboard.stub(:load, stats) { get stats_scan_index_path }
    end
    assert_response :success
    assert_equal ALL_CARDS - %w[users permissions], cards
    assert_match(/Statistics card users could not be shown: RuntimeError: boom reading/, log)
    assert_match(/Statistics card permissions could not be shown: /, log)
    assert_select "[data-stat=popular-full-control]", count: 1
    assert_not_includes response.body, "Most requested permissions", "nothing of the broken card is left behind"
  end

  test "a card on its own takes the full width of its row" do
    populate
    stats = ScanStats::Dashboard.load
    stats.define_singleton_method(:users) { nil }
    ScanStats::Dashboard.stub(:load, stats) { get stats_scan_index_path }

    row = css_select("[data-stat=popular-full-control]").first.parent
    assert_not_includes row["class"], "lg:grid-cols-2"
    assert_includes css_select("[data-stat=spiciest]").first.parent["class"], "lg:grid-cols-2"
  end

  test "small shares and bars stay readable" do
    helper = Class.new { include StatsHelper }.new
    assert_equal ["0%", "<1%", "1%", "50%", "100%", "0%", "0%"],
                 [[0, 10], [1, 1000], [6, 1000], [1, 2], [7, 7], [3, 0], [nil, nil]].map { |c, t| helper.stat_percent(c, t) }
    assert_equal ["0%", "1%", "50.0%", "100%", "0%"],
                 [[0, 10], [1, 1000], [1, 2], [9, 7], [3, 0]].map { |c, t| helper.stat_bar_width(c, t) }
  end
end
