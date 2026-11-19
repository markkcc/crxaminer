require "test_helper"

class StoreVersionClientTest < ActiveSupport::TestCase
  BITWARDEN = "nngceckbapebfimnlniiiahkandclblb".freeze
  UBLOCK = "cjpalhdlnbpafiamejdnhcphjbkeiagm".freeze
  UNKNOWN = "abcdefghijklmnopabcdefghijklmnop".freeze

  # Fixtures are live update-check replies (November 2026).
  def fixture(name)
    File.read(file_fixture("store_version/#{name}.xml"))
  end

  def reply(appid: BITWARDEN, app_status: "ok", check: %(<updatecheck status="ok" version="1.2.3"/>))
    %(<?xml version="1.0" encoding="UTF-8"?><gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">) +
      %(<app appid="#{appid}" status="#{app_status}">#{check}</app></gupdate>)
  end

  class FakeTransport
    attr_reader :requests

    def initialize(*responses)
      @responses = responses
      @requests = []
    end

    def get(uri, headers)
      @requests << [uri.to_s, headers]
      response = @responses.shift || raise("unexpected request to #{uri}")
      raise response if response.is_a?(Exception)

      response
    end
  end

  def client(transport, id = BITWARDEN)
    StoreVersionClient.new(id, transport: transport, logger: Logger.new(IO::NULL))
  end

  def ok(body) = StoreVersionClient::Response.new(code: 200, body: body)

  # ---- Parser ---------------------------------------------------------------

  test "a listed extension gives the updatecheck version, not the XML declaration's" do
    result = StoreVersionClient.parse(fixture("listed"), extension_id: BITWARDEN)

    assert result.ok?
    assert_equal "2026.10.2", result.version
  end

  test "noupdate means no version is available, with no claim that it was removed" do
    result = StoreVersionClient.parse(fixture("noupdate"), extension_id: UBLOCK)

    assert result.unavailable?
    assert_nil result.version
    assert_equal "noupdate", result.reason
  end

  test "an unknown ID means no version is available" do
    result = StoreVersionClient.parse(fixture("unknown"), extension_id: UNKNOWN)

    assert result.unavailable?
    assert_nil result.version
    assert_match "error-unknownApplication", result.reason
  end

  test "junk replies are errors" do
    ["", "   ", nil, 42, "<html><body>Sorry</body></html>", "not xml at all", "<gupdate><app",
     "<gupdate/>", reply(check: ""), reply(check: %(<updatecheck status="error-internal"/>)),
     %(<other><app appid="#{BITWARDEN}" status="ok"><updatecheck status="ok" version="1.0"/></app></other>)].each do |body|
      result = StoreVersionClient.parse(body, extension_id: BITWARDEN)
      assert result.error?, "expected an error for #{body.inspect}, got #{result.inspect}"
      assert_nil result.version
    end
  end

  test "only versions of one to four dot-separated integers up to 65535 are accepted" do
    %w[1 1.2 1.2.3 1.2.3.4 2026.10.2 0.0.0.0 65535.1].each do |version|
      result = StoreVersionClient.parse(reply(check: %(<updatecheck status="ok" version="#{version}"/>)), extension_id: BITWARDEN)
      assert result.ok?, version
      assert_equal version, result.version
    end

    ["", "1.2.3.4.5", "1..2", ".1", "1.", "v1.2", "1.2-beta", "65536", "1 .2", "&lt;b&gt;1&lt;/b&gt;", "123456", "1.2\n"].each do |version|
      result = StoreVersionClient.parse(reply(check: %(<updatecheck status="ok" version="#{version}"/>)), extension_id: BITWARDEN)
      assert result.error?, "expected #{version.inspect} to be refused"
      assert_nil result.version
    end
  end

  test "a reply for another extension is refused" do
    result = StoreVersionClient.parse(fixture("listed"), extension_id: UBLOCK)

    assert result.error?
  end

  test "an oversized reply is refused without parsing" do
    body = reply.sub("<app", "<!--#{'x' * StoreVersionClient::MAX_BODY_BYTES}--><app")
    result = StoreVersionClient.parse(body, extension_id: BITWARDEN)

    assert result.error?
    assert_match "larger than", result.reason
  end

  test "entities are never expanded and a DOCTYPE is refused" do
    [
      %(<?xml version="1.0"?><!DOCTYPE gupdate [<!ENTITY v "9.9.9">]><gupdate><app appid="#{BITWARDEN}" status="ok"><updatecheck status="ok" version="&v;"/></app></gupdate>),
      %(<?xml version="1.0"?><!DOCTYPE gupdate SYSTEM "http://127.0.0.1/evil.dtd"><gupdate><app appid="#{BITWARDEN}" status="ok"><updatecheck status="ok" version="1.0"/></app></gupdate>),
      reply(check: %(<updatecheck status="ok" version="&v;"/>))
    ].each do |body|
      result = StoreVersionClient.parse(body, extension_id: BITWARDEN)
      assert result.error?, body
      assert_nil result.version
    end
  end

  # ---- Fetching -------------------------------------------------------------

  test "fetch asks the update-check URL with our Chrome version and parses the reply" do
    transport = FakeTransport.new(ok(fixture("listed")))
    result = client(transport).fetch

    assert result.ok?
    assert_equal "2026.10.2", result.version
    url, headers = transport.requests.first
    assert_equal "https://clients2.google.com/service/update2/crx?response=updatecheck&prodversion=#{ChromeVersion.prodversion}" \
                 "&acceptformat=crx2,crx3&x=id%3D#{BITWARDEN}%26uc", url
    assert_equal ChromeVersion.user_agent, headers["User-Agent"]
  end

  test "HTTP errors, redirects and exceptions come back as errors" do
    [StoreVersionClient::Response.new(code: 500, body: ""),
     StoreVersionClient::Response.new(code: 302, body: ""),
     StoreVersionClient::Response.new(code: 204, body: ""),
     Net::OpenTimeout.new("execution expired"),
     StoreVersionClient::FetchError.new("reply larger than 65536 bytes")].each do |response|
      transport = FakeTransport.new(response)
      result = client(transport).fetch
      assert result.error?, response.inspect
      assert_equal 1, transport.requests.size, "no retries or redirects followed"
    end
  end

  test "fetch logs one line" do
    log = StringIO.new
    StoreVersionClient.new(UBLOCK, transport: FakeTransport.new(ok(fixture("noupdate"))), logger: Logger.new(log)).fetch

    assert_equal 1, log.string.lines.size
    assert_match "Store version #{UBLOCK}: status=unavailable", log.string
  end

  test "the transport stops reading at the size cap" do
    big = Net::HTTPOK.new("1.1", "200", "OK")
    big.define_singleton_method(:read_body) { |&block| 20.times { block.call("x" * 8192) } }
    fake_http = Object.new
    fake_http.define_singleton_method(:request) { |_req, &block| block.call(big) }
    fake_start = ->(*_args, **_opts, &block) { block.call(fake_http) }

    error = assert_raises(StoreVersionClient::FetchError) do
      Net::HTTP.stub(:start, fake_start) do
        StoreVersionClient::NetHttpTransport.new.get(StoreVersionClient.update_check_url(BITWARDEN), {})
      end
    end
    assert_match "larger than", error.message
  end

  # ---- Cache ----------------------------------------------------------------

  def counting_client(*results)
    calls = 0
    fake = Object.new
    fake.define_singleton_method(:fetch) do
      calls += 1
      results.shift || raise("unexpected fetch")
    end
    [->(*) { fake }, -> { calls }]
  end

  test "lookup caches a known version for about six hours" do
    cache = ActiveSupport::Cache::MemoryStore.new
    known = StoreVersionClient::Result.new(status: :ok, version: "1.2.3")
    factory, calls = counting_client(known, known)

    StoreVersionClient.stub(:new, factory) do
      assert_equal "1.2.3", StoreVersionClient.lookup(BITWARDEN, cache: cache).version
      assert_equal "1.2.3", StoreVersionClient.lookup(BITWARDEN, cache: cache).version
      assert_equal 1, calls.call
      assert_equal "1.2.3", StoreVersionClient.cached(BITWARDEN, cache: cache).version

      travel 5.hours + 50.minutes
      StoreVersionClient.lookup(BITWARDEN, cache: cache)
      assert_equal 1, calls.call

      travel 15.minutes
      StoreVersionClient.lookup(BITWARDEN, cache: cache)
      assert_equal 2, calls.call
    end
  end

  test "lookup keeps no version and failures for about fifteen minutes" do
    cache = ActiveSupport::Cache::MemoryStore.new
    failed = StoreVersionClient::Result.new(status: :error, reason: "HTTP 500")
    factory, calls = counting_client(failed, failed)

    StoreVersionClient.stub(:new, factory) do
      assert StoreVersionClient.lookup(UBLOCK, cache: cache).error?
      travel 14.minutes
      assert StoreVersionClient.lookup(UBLOCK, cache: cache).error?
      assert_equal 1, calls.call
      travel 2.minutes
      StoreVersionClient.lookup(UBLOCK, cache: cache)
      assert_equal 2, calls.call
    end
  end

  test "cached never fetches and ignores entries it did not write" do
    cache = ActiveSupport::Cache::MemoryStore.new
    StoreVersionClient.stub(:new, ->(*) { raise "must not fetch" }) do
      assert_nil StoreVersionClient.cached(BITWARDEN, cache: cache)

      cache.write(StoreVersionClient.cache_key(BITWARDEN), { status: :ok, version: "<b>1</b>" })
      assert_nil StoreVersionClient.cached(BITWARDEN, cache: cache)

      cache.write(StoreVersionClient.cache_key(BITWARDEN), "junk")
      assert_nil StoreVersionClient.cached(BITWARDEN, cache: cache)
    end
  end

  test "the cache key includes the Chrome version we report" do
    assert_equal "store_version/v1/#{ChromeVersion.prodversion}/#{BITWARDEN}", StoreVersionClient.cache_key(BITWARDEN)
  end
end
