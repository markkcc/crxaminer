require "test_helper"

class ChromeStoreClientTest < ActiveSupport::TestCase
  PAGE_ASSIST = "jfgfiigpkhlkbnfnbobbkinehhfdhndo".freeze
  BITWARDEN = "nngceckbapebfimnlniiiahkandclblb".freeze
  HONEY = "bmnlcjabgnpnenekpadlanbbkooimhnj".freeze
  TRANSLATE = "aapbdbdomjkkjkaonfhkkikfgjllcleb".freeze

  # Fixtures are cut down from live listing pages (November 2026): scripts,
  # styles, SVG and all class names removed; individual developers' contact
  # details replaced with placeholders.
  def fixture(name)
    File.read(file_fixture("chrome_store/#{name}.html"))
  end

  def parse(name, id)
    ChromeStoreClient.parse(fixture(name), extension_id: id)
  end

  # Records requests and answers from a list of responses (or exceptions).
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

  def response(code, location: nil, body: "")
    ChromeStoreClient::Response.new(code: code, location: location, body: body)
  end

  def client(transport, id = PAGE_ASSIST)
    ChromeStoreClient.new(id, transport: transport, logger: Logger.new(IO::NULL))
  end

  # ---- Parser ---------------------------------------------------------------

  test "an individual developer's listing uses Offered by as the author" do
    result = parse("individual_offered_by", PAGE_ASSIST)

    assert_equal :listing, result[:page]
    assert_equal "Page Assist - A Web UI for Local AI Models", result[:name]
    assert_match %r{\Ahttps://lh3\.googleusercontent\.com/.+=s60\z}, result[:image]
    assert_equal({
      author: "Example Developer",
      rating: "4.4",
      rating_count: "247 ratings",
      users: "300,000",
      size: "6.89MiB",
      last_updated: "November 15, 2026",
      developer_info: "Email: developer@example.com",
      store_description: "Use your locally running AI models to assist you in your web browsing.",
      featured: true
    }, result[:details])
  end

  test "a company listing takes the author and a one-line summary from the Developer block" do
    details = parse("company_developer_block", BITWARDEN)[:details]

    assert_equal "Bitwarden Inc.", details[:author]
    assert_equal "Bitwarden Inc., 1 N Calle Cesar Chavez Suite 102, Santa Barbara, CA 93103-5619, US; " \
                 "Website: bitwarden.com; Email: hello@bitwarden.com; Phone: +1 904-664-9194", details[:developer_info]
    assert_equal "2.8", details[:rating]
    assert_equal "8.2K ratings", details[:rating_count]
    assert_equal "7,000,000", details[:users]
    assert_equal "24.84MiB", details[:size]
    assert_equal "November 2, 2026", details[:last_updated]
    assert_not details.key?(:featured)
    assert_not details.key?(:established_publisher)
  end

  test "badges are recorded only when present" do
    featured = parse("featured_company", TRANSLATE)[:details]
    assert_equal true, featured[:featured]
    assert_not featured.key?(:established_publisher)
    assert_equal "Google Ireland, Ltd.", featured[:author]
    assert_equal "44.9K ratings", featured[:rating_count]
    assert_equal "39,000,000", featured[:users]

    established = parse("established_publisher", HONEY)[:details]
    assert_equal true, established[:established_publisher]
    assert_not established.key?(:featured)

    both = parse("both_badges_composite", HONEY)[:details]
    assert_equal true, both[:featured]
    assert_equal true, both[:established_publisher]
  end

  test "the header is scoped to the item: a related extension's rating is not used" do
    result = parse("established_publisher", HONEY)

    assert_includes fixture("established_publisher"), "Average rating 4.7 out of 5 stars", "the related card is in the fixture"
    assert_equal "Honey: Automated Coupons & Rewards", result[:name]
    assert_equal "2.2", result[:details][:rating]
    assert_equal "179.6K ratings", result[:details][:rating_count]
    assert_equal "13,000,000", result[:details][:users]
    assert_equal "PayPal Inc.", result[:details][:author]
  end

  test "the rating count comes only from this item's reviews link" do
    result = ChromeStoreClient.parse(fixture("company_developer_block"), extension_id: "b" * 32)
    assert_nil result[:details][:rating_count]
    assert_equal "2.8", result[:details][:rating]
  end

  test "an unavailable listing is recognised and reports nothing from the store shell" do
    result = parse("unavailable", "cjpalhdlnbpafiamejdnhcphjbkeiagm")

    assert_equal :unavailable, result[:page]
    assert_nil result[:name]
    assert_nil result[:image], "the generic store image is not the extension's"
    assert_equal ChromeStoreClient.empty_details, result[:details], "the generic store description is not kept"
  end

  test "a page in another language yields empty fields, never wrong ones" do
    result = parse("individual_german", PAGE_ASSIST)

    assert_equal :listing, result[:page]
    assert_equal "de", result[:lang]
    assert_equal "Page Assist - Eine Web-Benutzeroberfläche für lokale KI-Modelle", result[:name]
    %i[author rating rating_count users size last_updated developer_info].each do |key|
      assert_nil result[:details][key], key
    end
    assert_not result[:details].key?(:featured)
  end

  test "values of the wrong shape are dropped" do
    html = <<~HTML
      <html lang="en"><body><section><h1>Odd</h1>
        <span aria-label="Average rating lots out of 5 stars.">x</span>
        <a href="./detail/odd/#{'c' * 32}/reviews">Share</a>
        <div><a href="./category/extensions">Extension</a>Share</div>
      </section>
      <section><h2>Details</h2><ul>
        <li><div>Size</div><div>huge</div></li>
        <li><div>Updated</div><div>15. November 2026</div></li>
        <li><div>Offered by</div><div>   </div></li>
      </ul></section></body></html>
    HTML
    result = ChromeStoreClient.parse(html, extension_id: "c" * 32)

    assert_equal "Odd", result[:name]
    assert_equal ChromeStoreClient.empty_details, result[:details]
  end

  test "detail rows are found by label even without the Details heading, and long text is capped" do
    html = <<~HTML
      <html><body><h1>#{'N' * 500}</h1><ul>
        <li><div>Updated</div><div>March 3, 2025</div></li>
        <li><div>Developer</div><div><div>#{'Acme ' * 100}</div></div></li>
      </ul></body></html>
    HTML
    result = ChromeStoreClient.parse(html)

    assert_equal "March 3, 2025", result[:details][:last_updated]
    assert_equal ChromeStoreClient::SHORT_TEXT_LIMIT, result[:name].length
    assert_operator result[:details][:developer_info].length, :<=, ChromeStoreClient::DEVELOPER_INFO_LIMIT
    assert_operator result[:details][:author].length, :<=, 100
  end

  test "garbage, empty and nil input never raise" do
    [nil, "", "   ", "not html at all", "<<<>>>", "\xFF\xFE\x00<h1>".b, 42, "<h1></h1>", "<html>" * 5000].each do |input|
      result = ChromeStoreClient.parse(input)
      assert_equal ChromeStoreClient.empty_details, result[:details], input.inspect[0, 40]
      assert_nil result[:name], input.inspect[0, 40]
    end
  end

  test "an image must be an https URL" do
    html = '<html><head><meta property="og:image" content="javascript:alert(1)"></head><body><h1>X</h1></body></html>'
    assert_nil ChromeStoreClient.parse(html)[:image]
  end

  # ---- HTTP -----------------------------------------------------------------

  test "requests the English page with Chrome's User-Agent and follows the slug redirect, keeping hl=en" do
    transport = FakeTransport.new(
      response(301, location: "/detail/page-assist-a-web-ui-for/#{PAGE_ASSIST}?hl=de"),
      response(200, body: fixture("individual_offered_by"))
    )
    result = client(transport).fetch_details

    assert result.ok?
    assert_equal "Page Assist - A Web UI for Local AI Models", result.name
    assert_equal "Example Developer", result.details[:author]
    assert_equal "https://chromewebstore.google.com/detail/#{PAGE_ASSIST}?hl=en", transport.requests[0][0]
    assert_equal "https://chromewebstore.google.com/detail/page-assist-a-web-ui-for/#{PAGE_ASSIST}?hl=en", transport.requests[1][0]
    headers = transport.requests[0][1]
    assert_includes headers["User-Agent"], "Chrome/#{ChromeVersion.major}.0.0.0"
    assert_match(/\Aen/, headers["Accept-Language"])
  end

  test "a redirect without hl gets hl=en, and raw non-ASCII slugs are escaped" do
    transport = FakeTransport.new(
      response(302, location: "https://chromewebstore.google.com/detail/café/#{PAGE_ASSIST}"),
      response(200, body: fixture("individual_offered_by"))
    )
    assert client(transport).fetch_details.ok?
    assert_equal "https://chromewebstore.google.com/detail/caf%C3%A9/#{PAGE_ASSIST}?hl=en", transport.requests[1][0]
  end

  test "redirects off the store host or off HTTPS are refused" do
    ["https://evil.example/detail/x", "http://chromewebstore.google.com/detail/x",
     "https://chromewebstore.google.com:8443/detail/x", "https://user@chromewebstore.google.com/detail/x",
     "//evil.example/x", nil].each do |location|
      transport = FakeTransport.new(response(302, location: location))
      result = client(transport).fetch_details

      assert result.error?, location.inspect
      assert_equal 1, transport.requests.size, location.inspect
    end
  end

  test "a redirect loop and too many redirects stop with an error" do
    loop_transport = FakeTransport.new(
      response(301, location: "/detail/a/#{PAGE_ASSIST}"),
      response(301, location: "/detail/#{PAGE_ASSIST}")
    )
    result = client(loop_transport).fetch_details
    assert result.error?
    assert_match(/loop/, result.reason)
    assert_equal 2, loop_transport.requests.size

    chain = (1..10).map { |n| response(302, location: "/detail/hop#{n}/#{PAGE_ASSIST}") }
    chain_transport = FakeTransport.new(*chain)
    result = client(chain_transport).fetch_details
    assert result.error?
    assert_match(/redirects/, result.reason)
    assert_equal ChromeStoreClient::MAX_REDIRECTS + 1, chain_transport.requests.size
  end

  test "timeouts and connection errors come back as errors" do
    [Net::OpenTimeout.new("execution expired"), Net::ReadTimeout.new, SocketError.new("getaddrinfo"),
     OpenSSL::SSL::SSLError.new("bad cert")].each do |error|
      result = client(FakeTransport.new(error)).fetch_details
      assert result.error?, error.class.name
      assert_equal ChromeStoreClient.empty_details, result.details
      assert_nil result.name
    end
  end

  test "404 means no listing; 500 and other statuses are errors" do
    assert client(FakeTransport.new(response(404))).fetch_details.unavailable?
    assert client(FakeTransport.new(response(410))).fetch_details.unavailable?

    result = client(FakeTransport.new(response(500))).fetch_details
    assert result.error?
    assert_equal "HTTP 500", result.reason
    assert client(FakeTransport.new(response(429))).fetch_details.error?
  end

  test "the store's 200 'not found' shell is reported as unavailable" do
    transport = FakeTransport.new(
      response(301, location: "/detail/empty-title/#{'a' * 32}?hl=en"),
      response(200, body: fixture("unavailable"))
    )
    result = client(transport, "a" * 32).fetch_details

    assert result.unavailable?
    assert_nil result.name
    assert_equal ChromeStoreClient.empty_details, result.details
  end

  test "a page that is not a listing is an error, not a listing with blank fields" do
    result = client(FakeTransport.new(response(200, body: "<html><body>maintenance</body></html>"))).fetch_details
    assert result.error?
    assert_equal "listing page not recognised", result.reason
  end

  test "each scrape logs one line naming the fields found and missing" do
    log = capture_rails_log do
      ChromeStoreClient.new(PAGE_ASSIST, transport: FakeTransport.new(response(200, body: fixture("individual_german")))).fetch_details
    end
    lines = log.lines.grep(/Chrome Web Store/)

    assert_equal 1, lines.size
    assert_includes lines.first, "status=ok"
    assert_includes lines.first, "found=name,image,store_description"
    assert_includes lines.first, "missing=author,rating,rating_count,users,size,last_updated,developer_info"
    assert_includes lines.first, 'reason="page language de"'
  end

  test "the real transport uses HTTPS with open and read timeouts" do
    captured = nil
    fake_start = lambda do |host, port, **options|
      captured = [host, port, options]
      raise Net::OpenTimeout, "execution expired"
    end
    result = Net::HTTP.stub(:start, fake_start) do
      ChromeStoreClient.new(PAGE_ASSIST, logger: Logger.new(IO::NULL)).fetch_details
    end

    assert result.error?
    assert_match(/OpenTimeout/, result.reason)
    host, port, options = captured
    assert_equal ["chromewebstore.google.com", 443], [host, port]
    assert_equal true, options[:use_ssl]
    assert_equal ChromeStoreClient::OPEN_TIMEOUT, options[:open_timeout]
    assert_equal ChromeStoreClient::READ_TIMEOUT, options[:read_timeout]
  end

  test "the extension id is lowercased" do
    transport = FakeTransport.new(response(404))
    ChromeStoreClient.new(PAGE_ASSIST.upcase, transport: transport, logger: Logger.new(IO::NULL)).fetch_details
    assert_equal "https://chromewebstore.google.com/detail/#{PAGE_ASSIST}?hl=en", transport.requests[0][0]
  end
end
