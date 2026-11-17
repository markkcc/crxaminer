require "test_helper"

class ScanPage::NetworkDomainsTest < ActiveSupport::TestCase
  def domains(urls)
    ScanPage::NetworkDomains.new(urls).domains.index_by(&:name)
  end

  test "groups by registrable domain, busiest first" do
    result = ScanPage::NetworkDomains.new(%w[
      https://www.example.co.uk/a https://api.example.co.uk/b https://example.co.uk
      https://a.github.io/x https://b.github.io/y https://raw.githubusercontent.com/z https://single.test/
    ]).domains

    assert_equal ["example.co.uk", "github.io", "githubusercontent.com", "single.test"], result.map(&:name)
    assert_equal 3, result.first.urls.size
    assert_equal :developer, result[1].category
  end

  test "categories come from the built-in list, matched on parent domains" do
    d = domains(%w[https://www.w3.org/1999/xhtml https://cdn.jsdelivr.net/x https://www.google-analytics.com/a
                   https://bit.ly/abc https://fonts.googleapis.com/css https://www.google.de/ https://google.foo.test/
                   https://unknown.test/])
    assert_equal :reference, d["w3.org"].category
    assert_equal :cdn, d["jsdelivr.net"].category
    assert_equal :analytics, d["google-analytics.com"].category
    assert_equal :shortener, d["bit.ly"].category
    assert_equal :google, d["googleapis.com"].category
    assert_equal :google, d["google.de"].category
    assert_equal :other, d["foo.test"].category # a subdomain called google is not Google
    assert_equal :other, d["unknown.test"].category
  end

  test "flags are neutral facts" do
    d = domains(%w[http://plain.test/ https://ported.test:8443/ https://ported.test:443/x https://bit.ly/a http://93.184.216.34/ https://fine.test/])
    assert_equal [:http], d["plain.test"].flags
    assert_equal [:port], d["ported.test"].flags
    assert_equal [:shortener], d["bit.ly"].flags
    assert_equal %i[http ip], d["93.184.216.34"].flags
    assert_equal :ip, d["93.184.216.34"].category
    assert_equal [], d["fine.test"].flags
  end

  test "local hosts and private addresses are Local" do
    d = domains(%w[http://localhost:3000/ http://127.0.0.1/ http://192.168.1.2/ http://10.0.0.1/ http://app.local/ http://[::1]:8080/ file:///etc/hosts])
    %w[localhost 127.0.0.1 192.168.1.2 10.0.0.1 app.local ::1].each { |name| assert_equal :local, d[name]&.category, name }
    assert_equal :local, d[ScanPage::NetworkDomains::LOCAL_FILES].category
    assert_includes d["::1"].flags, :port
  end

  test "junk and unparseable strings share one bucket and never raise" do
    junk = ["<script>alert(1)</script>", "https://", "http://exa mple.com", "https://a:b@", "https://host:notaport/",
            "http://999.1.1.1/", 42, nil, { "a" => 1 }, "https://[::1", "javascript:alert(1)", "https://..../"]
    result = ScanPage::NetworkDomains.new(junk)
    unparsed = result.domains.find { |d| d.name == ScanPage::NetworkDomains::UNPARSED }

    assert_equal junk.size, result.domains.sum { |d| d.urls.size }
    assert unparsed.urls.size >= 9
    assert_includes unparsed.urls, "42"
    assert_includes unparsed.urls, "null"
    assert_equal 0, ScanPage::NetworkDomains.new(nil).url_count
    assert_equal 0, ScanPage::NetworkDomains.new("not a list").domain_count
  end

  test "the encoded form holds each URL once and cannot break its fields" do
    network = ScanPage::NetworkDomains.new(["https://a.test/1", "http://a.test/2?x=<b>&y=\"q\"", "https://b.test/\tinjected\nline"])
    lines = network.encoded.split("\n")

    assert_equal 2, lines.size
    a = lines.first.split("\t")
    assert_equal "a.test", a[0]
    assert_equal ScanPage::NetworkDomains::CATEGORIES.keys.index(:other), a[1].to_i
    assert_equal ScanPage::NetworkDomains::FLAG_BITS[:http], a[2].to_i
    assert_equal ["https://a.test/1", "http://a.test/2?x=<b>&y=\"q\""], a[3..]
    assert_equal ["b.test", "8", "0", "https://b.test/ injected line"], lines.last.split("\t")
  end

  test "summary carries what the page shows" do
    summary = ScanPage::NetworkDomains.new(%w[https://a.test/ https://b.test/ https://w3.org/]).summary
    assert_equal 3, summary.url_count
    assert_equal 3, summary.domain_count
    assert_equal({ reference: 1, other: 2 }, summary.category_counts)
  end
end
