require "test_helper"

class ExtensionAnalyzerTest < ActiveSupport::TestCase
  def zip_bytes(files)
    buffer = Zip::OutputStream.write_buffer do |zip|
      files.each do |path, content|
        zip.put_next_entry(path)
        zip.write(content)
      end
    end
    buffer.string
  end

  # A unique id per call: extract_manifest writes tmp/extensions/extension_<id>.zip,
  # and tests may run in parallel processes.
  def extract(files, id: SecureRandom.hex(16))
    ExtensionAnalyzer.new(id).send(:extract_manifest, zip_bytes(files))
  end

  test "resolves __MSG_ placeholders for name and description from the default locale (case-insensitive keys)" do
    manifest = {
      manifest_version: 3, name: "__MSG_appName__", description: "__MSG_APPDESC__", version: "2.0",
      default_locale: "en_US", permissions: ["storage"],
      background: { service_worker: "bg.js" },
      web_accessible_resources: [{ resources: ["a.js"], matches: ["<all_urls>"] }]
    }
    messages = { "AppName" => { "message" => "Localized Name" }, "appDesc" => { "message" => "Localized description." } }
    result = extract({ "manifest.json" => JSON.generate(manifest),
                       "_locales/en_US/messages.json" => "\uFEFF" + JSON.generate(messages),
                       "_locales/de/messages.json" => JSON.generate({ "appName" => { "message" => "Deutsch" } }) })

    assert_equal "__MSG_appName__", result[:name], "the raw value is kept"
    assert_equal "Localized Name", result[:localized_name]
    assert_equal "Localized description.", result[:localized_description]
    assert_equal({ "service_worker" => "bg.js" }, result[:raw]["background"])

    payload = AiContextAnalysis.build_payload(manifest: result, extension_details: {}, extension_name: nil, findings: [])
    assert_equal "Localized Name", payload[:name]
    assert_equal "Localized description.", payload[:description]
    assert_equal ["a.js"], payload[:web_accessible_resources]
    assert_equal({ service_worker: "bg.js" }, payload[:background])
  end

  test "plain descriptions pass through and unresolvable placeholders become nil" do
    result = extract({ "manifest.json" => JSON.generate({ manifest_version: 3, name: "Plain", description: "Just text" }) })
    assert_equal "Plain", result[:localized_name]
    assert_equal "Just text", result[:localized_description]

    result = extract({ "manifest.json" => JSON.generate({ manifest_version: 3, name: "__MSG_missing__",
                                                           default_locale: "fr" }) })
    assert_nil result[:localized_name]
    assert_nil result[:localized_description]
  end

  test "store description comes from og:description, then meta description, and is nil-safe" do
    og = Nokogiri::HTML('<html><head><meta property="og:description" content=" From OG "><meta name="description" content="Meta"></head></html>')
    meta = Nokogiri::HTML('<html><head><meta name="description" content="From meta"></head></html>')
    none = Nokogiri::HTML("<html><head></head><body><h1>x</h1></body></html>")

    assert_equal "From OG", ChromeStoreClient.store_description(og)
    assert_equal "From meta", ChromeStoreClient.store_description(meta)
    assert_nil ChromeStoreClient.store_description(none)
    assert_nil ChromeStoreClient.store_description(nil)
  end

  def store_result(status, name: nil, details: ChromeStoreClient.empty_details)
    ChromeStoreClient::Result.new(status: status, name: name, image: name && "https://lh3.googleusercontent.com/x=s60",
                                  details: details, reason: nil)
  end

  test "store data comes from ChromeStoreClient, and a failed store fetch does not stop the scan" do
    [store_result(:ok, name: "Listed", details: ChromeStoreClient.empty_details.merge(author: "Acme")),
     store_result(:error), store_result(:unavailable)].each do |store|
      analyzer = ExtensionAnalyzer.new("a" * 32)
      downloaded = false
      fake_client = Struct.new(:result) { def fetch_details = result }.new(store)
      ChromeStoreClient.stub(:new, fake_client) do
        analyzer.stub(:download_and_analyze_extension, -> { downloaded = true }) { analyzer.perform }
      end

      assert downloaded, "download attempted for #{store.status}"
      assert_not analyzer.error?
      [[store.name, analyzer.extension_name], [store.image, analyzer.extension_image]].each do |expected, actual|
        expected.nil? ? assert_nil(actual) : assert_equal(expected, actual)
      end
      assert_equal store.details, analyzer.extension_details
    end
  end

  FakeCrxResponse = Struct.new(:code, :body, :location) do
    def [](header) = header.to_s.downcase == "location" ? location : nil
    def to_hash = {}
  end

  # Runs perform with the store result given and the update server answering
  # with the responses given, in order.
  def scan_with(store, *responses, id: SecureRandom.hex(16))
    analyzer = ExtensionAnalyzer.new(id)
    fake_client = Struct.new(:result) { def fetch_details = result }.new(store)
    ChromeStoreClient.stub(:new, fake_client) do
      analyzer.stub(:request_crx, ->(_uri) { responses.shift || raise("unexpected download request") }) { analyzer.perform }
    end
    analyzer
  end

  test "no download for a listing the store does not have says it is not in the store" do
    analyzer = scan_with(store_result(:unavailable), FakeCrxResponse.new("204", ""))
    assert_equal ExtensionAnalyzer::NOT_IN_STORE_MESSAGE, analyzer.error
    assert_includes analyzer.error, "not available in the Chrome Web Store"

    analyzer = scan_with(store_result(:unavailable), FakeCrxResponse.new("302", "", "https://clients2.googleusercontent.com/crx/x"),
                         FakeCrxResponse.new("200", ""))
    assert_equal ExtensionAnalyzer::NOT_IN_STORE_MESSAGE, analyzer.error
  end

  test "no download for a listed extension points at the Chrome version" do
    analyzer = scan_with(store_result(:ok, name: "Listed"), FakeCrxResponse.new("204", ""))
    assert_includes analyzer.error, "lists this extension but did not provide a download"
    assert_includes analyzer.error, "newer Chrome version than CRXaminer reports (Chrome #{ChromeVersion.major})"
  end

  test "no download when the store page could not be read gives the combined reasons" do
    analyzer = scan_with(store_result(:error), FakeCrxResponse.new("204", ""))
    assert_includes analyzer.error, "did not provide a download"
    assert_includes analyzer.error, "may have been removed"
    assert_not_equal ExtensionAnalyzer::NOT_IN_STORE_MESSAGE, analyzer.error
  end

  test "an unlisted extension that downloads is scanned and named from its manifest" do
    crx = zip_bytes({ "manifest.json" => JSON.generate({ manifest_version: 3, name: "__MSG_n__", version: "1.0",
                                                         default_locale: "en" }),
                      "_locales/en/messages.json" => JSON.generate({ "n" => { "message" => "Unlisted Tool" } }) })
    analyzer = scan_with(store_result(:unavailable), FakeCrxResponse.new("302", "", "https://clients2.googleusercontent.com/crx/x"),
                         FakeCrxResponse.new("200", crx))

    assert_not analyzer.error?, analyzer.error
    assert_equal "Unlisted Tool", analyzer.extension_name
    assert_equal ChromeStoreClient.empty_details, analyzer.extension_details
    assert analyzer.security_findings.any? { |f| f[:title].to_s.start_with?("Overall Risk") }
  end

  test "the store name is kept when there is one" do
    crx = zip_bytes({ "manifest.json" => JSON.generate({ manifest_version: 3, name: "Manifest Name", version: "1.0" }) })
    analyzer = scan_with(store_result(:ok, name: "Store Name"), FakeCrxResponse.new("200", crx))
    assert_equal "Store Name", analyzer.extension_name
  end

  test "the manifest display name skips unresolved placeholders and blanks" do
    assert_equal "Raw", ExtensionAnalyzer.manifest_display_name({ name: " Raw ", localized_name: nil })
    assert_equal "Loc", ExtensionAnalyzer.manifest_display_name({ name: "__MSG_x__", localized_name: "Loc" })
    assert_nil ExtensionAnalyzer.manifest_display_name({ name: "__MSG_x__", localized_name: nil })
    assert_nil ExtensionAnalyzer.manifest_display_name({ name: "  " })
    assert_nil ExtensionAnalyzer.manifest_display_name(nil)
  end
end
