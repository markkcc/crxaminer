# A Chrome match pattern ("<all_urls>" or "scheme://host/path"), as used in
# host_permissions, content_scripts[].matches and, in Manifest V2,
# permissions. Parsing never raises: anything that is not a pattern Chrome
# accepts is #valid? false, and callers ignore it, as Chrome does.
#
# What counts as all sites:
# - "<all_urls>";
# - host "*" with scheme "*", "http", "https", "ws" or "wss", whatever the
#   path. ws and wss count because such a pattern reaches the WebSocket
#   traffic of every server. "ftp" does not: Chrome no longer loads ftp://
#   URLs, so "ftp://*/*" reaches nothing;
# - a wildcard over a whole public suffix with one of those schemes, such
#   as "*://*.com/*" or "https://*.co.uk/*" (see #public_suffix_wildcard?).
# "https://*.example.com/*" is one named site, not all sites. "file:///*" is
# local files (#file?), which Chrome only allows when the user turns on file
# access for the extension.
class MatchPattern
  ALL_URLS = "<all_urls>".freeze
  # Schemes Chrome accepts in a match pattern (urn: patterns have no "//"
  # and are not parsed here: they are never a website).
  SCHEMES = %w[* http https ws wss ftp file chrome chrome-extension filesystem data].freeze
  ALL_SITES_SCHEMES = %w[* http https ws wss].freeze
  WEB_SCHEMES = %w[* http https].freeze
  SHAPE = %r{\A([a-z*][a-z0-9+.*-]*)://([^/]*)(/.*)\z}im
  HOST_SHAPE = /\A(?:\*|(?:\*\.)?[^*\s\/:\[\]]+|\[[0-9a-f:.]+\])\z/i
  PORT_SHAPE = /\A(?:\*|\d{1,5})\z/

  attr_reader :source, :scheme, :host, :path

  def self.parse(value)
    new(value)
  end

  def initialize(value)
    @source = value
    @valid = false
    return unless value.is_a?(String)

    if value == ALL_URLS
      @valid = true
      return
    end
    parse(value)
  rescue StandardError
    @valid = false
  end

  def valid?
    @valid
  end

  def all_urls?
    valid? && @source == ALL_URLS
  end

  # Every website: see the class comment.
  def all_sites?
    return false unless valid?
    return true if all_urls?

    ALL_SITES_SCHEMES.include?(scheme) && (host == "*" || public_suffix_wildcard?)
  end

  # "*://*.com/*": a wildcard over a whole public suffix (".com", ".co.uk").
  # Only suffixes on the ICANN part of the Public Suffix List count; a
  # private one such as "*.github.io" names one provider's sites.
  def public_suffix_wildcard?
    return false unless valid? && subdomains? && !file?

    self.class.public_suffix?(domain)
  end

  def file?
    valid? && scheme == "file"
  end

  # The host without a leading "*." ("*.example.com" -> "example.com"); nil
  # for "<all_urls>", a bare "*" host and file patterns.
  def domain
    return nil unless valid? && !all_urls? && !file? && host != "*"

    host.delete_prefix("*.")
  end

  # Does the host include its subdomains ("*.example.com")?
  def subdomains?
    valid? && host.to_s.start_with?("*.")
  end

  # "example.co.uk" for "https://*.mail.example.co.uk/*": the part of the
  # host that can be registered, by the ICANN suffixes of the Public Suffix
  # List. nil for IP addresses, all-site and file patterns, and a host that
  # is itself a public suffix. A single-label host such as "localhost" is
  # its own registrable domain.
  def registrable_domain
    return @registrable_domain if defined?(@registrable_domain)

    @registrable_domain = self.class.registrable_domain(domain)
  end

  # The registrable domain without its public suffix: "paypal" for paypal.co.uk.
  def domain_label
    registrable_domain&.split(".")&.first
  end

  def self.registrable_domain(name)
    return nil if name.nil? || name.empty? || ip_address?(name)
    return name unless name.include?(".")

    PublicSuffix.domain(name, ignore_private: true)
  rescue StandardError
    nil
  end

  def self.public_suffix?(name)
    return false if name.nil? || name.empty? || ip_address?(name)

    list = PublicSuffix::List.default
    rule = list.find(name, ignore_private: true)
    rule != list.default_rule && PublicSuffix.domain(name, ignore_private: true).nil?
  rescue StandardError
    false
  end

  def self.ip_address?(name)
    name.match?(/\A\d{1,3}(?:\.\d{1,3}){3}\z/) || name.start_with?("[")
  end

  def to_s
    @source.to_s
  end

  private

  def parse(value)
    match = SHAPE.match(value)
    return unless match

    scheme = match[1].downcase
    authority = match[2]
    return unless SCHEMES.include?(scheme)

    if scheme == "file"
      # Chrome ignores the host of a file pattern ("file:///*", "file://*/*").
      @scheme, @host, @path = scheme, "", match[3]
      @valid = true
      return
    end

    host, port = split_port(authority)
    return if host.nil? || host.empty? || !host.match?(HOST_SHAPE)
    return if port && !port.match?(PORT_SHAPE)

    @scheme = scheme
    @host = host.downcase
    @path = match[3]
    @valid = true
  end

  # "[::1]:8080" and "example.com:*" -> host and port (nil when absent).
  def split_port(authority)
    if authority.start_with?("[")
      close = authority.index("]")
      return [nil, nil] unless close

      rest = authority[(close + 1)..]
      return [authority[0..close], nil] if rest.empty?
      return [nil, nil] unless rest.start_with?(":")

      [authority[0..close], rest[1..]]
    elsif authority.count(":") == 1
      authority.split(":", 2)
    elsif authority.include?(":")
      [nil, nil]
    else
      [authority, nil]
    end
  end
end
