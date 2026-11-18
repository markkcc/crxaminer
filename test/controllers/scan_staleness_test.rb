require "test_helper"

# The "this scan may be out of date" notice, the store-version endpoint and
# the re-scan rule. No test reaches Google: StoreVersionClient is stubbed.
class ScanStalenessTest < ActionDispatch::IntegrationTest
  ID = "s" * 32
  MANIFEST = { manifest_version: 3, name: "X", version: "1.68.0", permissions: ["tabs"], raw: { "name" => "X" } }.freeze

  def create_scan(age:, id: ID, manifest: MANIFEST)
    scan = ScanResult.create!(extension_id: id, extension_name: "Demo", manifest: manifest,
                              extension_details: {}, security_findings: [])
    scan.update_columns(updated_at: age.ago)
    scan
  end

  def known(version) = StoreVersionClient::Result.new(status: :ok, version: version)
  def unavailable = StoreVersionClient::Result.new(status: :unavailable, reason: "noupdate")
  def failed = StoreVersionClient::Result.new(status: :error, reason: "HTTP 500")

  def with_store(result, &block)
    StoreVersionClient.stub(:lookup, ->(*) { result }) do
      StoreVersionClient.stub(:cached, ->(*) { nil }, &block)
    end
  end

  def with_memory_cache
    original = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    yield
  ensure
    Rails.cache = original
  end

  def banner
    css_select("#scan-freshness [data-freshness-banner]").first
  end

  # ---- Endpoint ---------------------------------------------------------------

  test "the endpoint reports a different store version with the notice" do
    create_scan(age: 3.days)
    with_store(known("1.70.2")) { get store_version_scan_path(ID) }

    assert_response :success
    assert_equal "application/json", response.media_type
    assert_equal({
      "extension_id" => ID, "status" => "ok", "store_version" => "1.70.2", "version_differs" => true, "old" => false,
      "store_note" => "in the store now: 1.70.2",
      "notice" => "This scan covers version 1.68.0. The Chrome Web Store now has version 1.70.2. " \
                  "The results below may not match the extension you would install today.",
      "rescan_allowed" => true
    }, response.parsed_body)
  end

  test "the endpoint reports the same version quietly" do
    create_scan(age: 3.hours)
    with_store(known("1.68.0")) { get store_version_scan_path(ID) }

    body = response.parsed_body
    assert_equal false, body["version_differs"]
    assert_nil body["notice"]
    assert_equal "the latest in the store", body["store_note"]
    assert_equal false, body["rescan_allowed"]
  end

  test "no version available and failures make no claim, but the age notice stays" do
    create_scan(age: 11.months)
    [unavailable, failed].each do |store|
      with_store(store) { get store_version_scan_path(ID) }

      assert_response :success
      body = response.parsed_body
      assert_equal store.status.to_s, body["status"]
      assert_nil body["store_version"]
      assert_equal false, body["version_differs"]
      assert_equal "store version not available", body["store_note"]
      assert_match "This scan is 11 months old", body["notice"]
      assert_no_match(/removed|now has/, body["notice"])
    end
  end

  test "IDs without a stored scan get 404 and never reach Google" do
    StoreVersionClient.stub(:lookup, ->(*) { raise "must not look up" }) do
      get store_version_scan_path("q" * 32)
      assert_response :not_found

      get "/scan/not-an-id/store_version"
      assert_response :unprocessable_entity
    end
  end

  test "a second request is answered from the cache" do
    create_scan(age: 3.days)
    fetches = 0
    fake = Object.new
    fake.define_singleton_method(:fetch) do
      fetches += 1
      StoreVersionClient::Result.new(status: :ok, version: "1.70.2")
    end

    with_memory_cache do
      StoreVersionClient.stub(:new, ->(*) { fake }) do
        2.times do
          get store_version_scan_path(ID)
          assert_equal "1.70.2", response.parsed_body["store_version"]
        end
        # The page itself reads the cached answer, without fetching.
        get scan_path(ID)
        assert_select "[data-store-version-note]", text: /in the store now: 1\.70\.2/
      end
    end
    assert_equal 1, fetches
  end

  test "hostile stored versions are escaped in the JSON and on the page" do
    hostile = %("><img src=x onerror=alert(1)><script>alert(2)</script>)
    create_scan(age: 11.months, manifest: MANIFEST.merge(version: hostile))

    with_store(known("1.0")) { get store_version_scan_path(ID) }
    assert_not_includes response.body, "<script"
    assert_not_includes response.body, "<img"
    assert_includes response.parsed_body["notice"], "covers version \"><img src=x"

    with_store(known("1.0")) { get scan_path(ID) }
    assert_response :success
    assert_not_includes response.body, "<img src=x onerror=alert(1)>"
    assert_not_includes response.body, "<script>alert(2)</script>"
    assert_includes css_select("[data-freshness-message]").first.text, "covers version \"><img src=x"
  end

  test "the endpoint is rate limited per IP" do
    create_scan(age: 3.days)
    counter = ActiveSupport::Cache::MemoryStore.new
    # Tests use the null cache, where the limit never triggers; count for real here.
    ScanController.cache_store.stub(:increment, ->(*args, **opts) { counter.increment(*args, **opts) }) do
      with_store(known("1.70.2")) do
        ScanController::STORE_VERSION_RATE_LIMIT.times do
          get store_version_scan_path(ID)
          assert_response :success
        end
        get store_version_scan_path(ID)
        assert_response :too_many_requests
        assert_match "Too many requests", response.parsed_body["error"]

        get store_version_scan_path(ID), env: { "REMOTE_ADDR" => "203.0.113.9" }
        assert_response :success

        travel 61.seconds
        get store_version_scan_path(ID)
        assert_response :success
      end
    end
  end

  # ---- Page (server-rendered, so it works without JavaScript) -----------------

  test "a fresh scan has a hidden notice and no store note until the store answers" do
    create_scan(age: 2.hours)
    StoreVersionClient.stub(:lookup, ->(*) { raise "the page must not wait for Google" }) do
      get scan_path(ID)
    end

    assert_response :success
    assert banner.key?("hidden")
    assert_equal store_version_scan_path(ID), css_select("#scan-freshness").first["data-store-version-url"]
    assert_equal "polite", css_select("#scan-freshness").first["aria-live"]
    assert_equal "", css_select("[data-store-version-note]").first.text
    assert css_select("[data-rescan-link]").first.key?("hidden")
  end

  test "an old scan shows the age notice and a Scan again button without JavaScript" do
    create_scan(age: 11.months)
    StoreVersionClient.stub(:lookup, ->(*) { raise "the page must not wait for Google" }) do
      get scan_path(ID)
    end

    assert_not banner.key?("hidden")
    assert_select "#scan-freshness [data-freshness-message]",
                  text: "This scan is 11 months old and covers version 1.68.0. The extension may have changed since then. " \
                        "The results below may not match the extension you would install today."
    assert_select "#scan-freshness a[href=?]", scan_path(ID, force: true), text: "Scan again"
    assert_not css_select("[data-rescan-link]").first.key?("hidden")
    assert_select "[data-rescan-link] a", text: "force re-scan"
  end

  test "a cached different store version shows the version notice on a fresh scan" do
    create_scan(age: 2.hours)
    StoreVersionClient.stub(:cached, ->(*) { known("1.70.2") }) do
      get scan_path(ID)
    end

    assert_not banner.key?("hidden")
    assert_select "[data-freshness-message]", text: /The Chrome Web Store now has version 1\.70\.2\./
    assert_select "[data-store-version-note]", text: "· in the store now: 1.70.2"
    assert_not css_select("[data-rescan-link]").first.key?("hidden")
  end

  test "the notice does not use the severity colours" do
    create_scan(age: 11.months)
    get scan_path(ID)

    assert_no_match(/severity/, banner["class"])
  end

  # ---- Re-scan rule -----------------------------------------------------------

  # Stands in for a scan that was started: the analyzer fails at once, so
  # nothing is downloaded and the stored scan stays.
  def with_analyzer
    started = 0
    fake = Object.new
    fake.define_singleton_method(:perform) do
      started += 1
      self
    end
    fake.define_singleton_method(:error?) { true }
    fake.define_singleton_method(:error) { "stubbed scan" }
    ExtensionAnalyzer.stub(:new, ->(*, **) { fake }) { yield }
    started
  end

  def analyze(params)
    get analyze_scan_index_path, params: { id: ID }.merge(params), xhr: true
  end

  test "a forced re-scan is allowed when the scan is older than 24 hours" do
    create_scan(age: 25.hours)
    started = with_analyzer do
      StoreVersionClient.stub(:lookup, ->(*) { raise "no store lookup needed" }) { analyze(force: "true") }
    end

    assert_equal 1, started
    assert_response :unprocessable_entity
    assert_equal "stubbed scan", response.parsed_body["error"]
  end

  test "a forced re-scan is allowed when the store has another version" do
    create_scan(age: 2.hours)
    started = with_analyzer { with_store(known("1.70.2")) { analyze(force: "true") } }

    assert_equal 1, started
  end

  test "a forced re-scan of a recent scan of the current version is refused" do
    create_scan(age: 2.hours)
    [known("1.68.0"), unavailable, failed].each do |store|
      started = with_analyzer { with_store(store) { analyze(force: "true") } }

      assert_equal 0, started, store.inspect
      assert_response :success
      assert_equal ID, response.parsed_body["extension_id"]
    end
  end

  test "the browser cannot claim a new version" do
    create_scan(age: 2.hours)
    started = with_analyzer do
      with_store(known("1.68.0")) do
        analyze(force: "true", store_version: "9.9.9", version_differs: "true", rescan_allowed: "true", old: "true")
      end
    end

    assert_equal 0, started
    assert_response :success
  end

  test "without force an existing scan is returned as before" do
    create_scan(age: 11.months)
    started = with_analyzer do
      StoreVersionClient.stub(:lookup, ->(*) { raise "no store lookup needed" }) { analyze({}) }
    end

    assert_equal 0, started
    assert_response :success
  end
end
