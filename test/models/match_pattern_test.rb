require "test_helper"

class MatchPatternTest < ActiveSupport::TestCase
  def parse(value)
    MatchPattern.parse(value)
  end

  test "all sites: <all_urls> and a * host with a web scheme, whatever the path" do
    %w[<all_urls> *://*/* https://*/* http://*/ http://*/foo* ws://*/* wss://*/* HTTPS://*/*].each do |pattern|
      assert parse(pattern).valid?, pattern
      assert parse(pattern).all_sites?, pattern
    end
  end

  test "ftp and other schemes with a * host are not all sites" do
    %w[ftp://*/* chrome://*/* file://*/*].each do |pattern|
      assert parse(pattern).valid?, pattern
      assert_not parse(pattern).all_sites?, pattern
    end
  end

  test "a wildcard over a whole public suffix is all sites; a named site is not" do
    %w[*://*.com/* https://*.co.uk/* http://*.de/x].each do |pattern|
      p = parse(pattern)
      assert p.public_suffix_wildcard?, pattern
      assert p.all_sites?, pattern
    end

    %w[https://*.example.com/* *://*.github.io/* https://*.mail.example.co.uk/*].each do |pattern|
      p = parse(pattern)
      assert p.valid?, pattern
      assert_not p.public_suffix_wildcard?, pattern
      assert_not p.all_sites?, pattern
    end
    # An unlisted ending is not a known public suffix.
    assert_not parse("https://*.notarealsuffix/*").all_sites?
  end

  test "host, domain and registrable domain" do
    p = parse("https://*.Mail.Example.co.uk:8443/inbox/*")
    assert_equal "https", p.scheme
    assert_equal "*.mail.example.co.uk", p.host
    assert_equal "mail.example.co.uk", p.domain
    assert_equal "example.co.uk", p.registrable_domain
    assert_equal "example", p.domain_label
    assert p.subdomains?

    assert_equal "googleapis.com", parse("https://fonts.googleapis.com/*").registrable_domain
    assert_equal "localhost", parse("http://localhost:*/*").registrable_domain
    assert_nil parse("http://127.0.0.1/*").registrable_domain
    assert_nil parse("http://[::1]:8080/*").registrable_domain
    assert parse("http://[::1]:8080/*").valid?
    assert_nil parse("<all_urls>").domain
    assert_nil parse("*://*/*").registrable_domain
  end

  test "file patterns are their own kind, not all sites" do
    %w[file:///* file://*/* file:///home/*].each do |pattern|
      p = parse(pattern)
      assert p.valid?, pattern
      assert p.file?, pattern
      assert_not p.all_sites?, pattern
      assert_nil p.registrable_domain
    end
    assert_not parse("<all_urls>").file?
  end

  test "a bare * and other invalid patterns are not match patterns, as in Chrome" do
    ["*", "*://*", "https://*.example.com", "http://", "https:///*", "https://exa*mple.com/*", "https://*foo.com/*",
     "javascript://x/*", "https://a b.com/*", "example.com", "", "<ALL_URLS>", "https://x.com:abc/*",
     "https://\"><img src=x>/*", "urn:*"].each do |pattern|
      p = parse(pattern)
      assert_not p.valid?, pattern
      assert_not p.all_sites?, pattern
      assert_not p.file?, pattern
      assert_nil p.registrable_domain, pattern
    end
  end

  test "non-strings never raise and are invalid" do
    [nil, 5, 3.5, [], {}, ["<all_urls>"], { "a" => 1 }, true].each do |value|
      p = parse(value)
      assert_not p.valid?
      assert_not p.all_sites?
      assert_not p.public_suffix_wildcard?
      assert_nil p.domain
    end
  end
end
