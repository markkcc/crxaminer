require "ipaddr"

module ScanPage
  # Groups the URLs found in an extension's files by registrable domain, with
  # a category from a short built-in list and neutral flags. The URLs come
  # from untrusted code, so nothing here contacts them or treats them as links.
  class NetworkDomains
    Domain = Struct.new(:name, :category, :urls, :flags, keyword_init: true)

    # What the page shows, small enough to cache. Bump VERSION when grouping,
    # categories or the encoding change, so cached summaries are rebuilt.
    Summary = Struct.new(:url_count, :domain_count, :category_counts, :encoded, keyword_init: true)
    VERSION = 2

    CATEGORIES = {
      reference: "Reference",
      developer: "Developer sites and code hosting",
      google: "Google",
      cdn: "CDN",
      analytics: "Analytics and tracking",
      shortener: "Link shortener",
      local: "Local",
      ip: "IP address",
      other: "Other"
    }.freeze

    FLAGS = {
      http: "plain HTTP",
      ip: "IP address",
      port: "non-standard port",
      shortener: "link shortener"
    }.freeze

    # Well-known domains only; anything else is "Other". Matched against the
    # host and each of its parent domains, most specific first.
    KNOWN_DOMAINS = {
      # Specs, namespaces, registries and licences that code mentions but
      # usually never contacts.
      reference: %w[
        w3.org schema.org xmlns.com purl.org ogp.me json-schema.org whatwg.org tc39.es ecma-international.org
        ietf.org rfc-editor.org iana.org unicode.org publicsuffix.org spdx.org opensource.org creativecommons.org
        gnu.org apache.org mozilla.org openxmlformats.org example.com example.org example.net
      ],
      developer: %w[
        github.com github.io githubusercontent.com gitlab.com bitbucket.org sourceforge.net stackoverflow.com
        npmjs.com npmjs.org chromium.org webkit.org nodejs.org jquery.com jqueryui.com codepen.io jsfiddle.net
      ],
      google: %w[
        google.com googleapis.com gstatic.com googleusercontent.com youtube.com ytimg.com chrome.com
        chromewebstore.google.com gmail.com web.dev
      ],
      cdn: %w[
        jsdelivr.net unpkg.com cdnjs.com cloudflare.com cloudfront.net akamaihd.net akamaized.net fastly.net
        bootstrapcdn.com statically.io maxcdn.com rawgit.com
      ],
      analytics: %w[
        google-analytics.com googletagmanager.com doubleclick.net googlesyndication.com googleadservices.com
        hotjar.com mixpanel.com segment.com segment.io amplitude.com sentry.io newrelic.com nr-data.net
        scorecardresearch.com facebook.net clarity.ms
      ],
      shortener: %w[
        bit.ly goo.gl t.co tinyurl.com ow.ly is.gd buff.ly rebrand.ly cutt.ly tiny.cc shorturl.at rb.gy
      ]
    }.flat_map { |category, domains| domains.map { |d| [d, category] } }.to_h.freeze

    DEFAULT_PORTS = { "http" => 80, "https" => 443, "ws" => 80, "wss" => 443, "ftp" => 21 }.freeze
    # scheme://[userinfo@]host[:port] followed by a path, query, fragment or
    # the end. Anything else (such as a port that is not a number) is unparsed.
    # Captures scheme, host and port.
    AUTHORITY = %r{\A([a-z][a-z0-9+.-]*)://(?:[^/?#\\@]*@)?(\[[^\]/]*\]|[^/?#\\:\[\]]*)(?::(\d{0,5}))?(?=[/?#\\]|\z)}i
    HOST_SHAPE = /\A[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\z/
    IPV4_SHAPE = /\A\d{1,3}(?:\.\d{1,3}){3}\z/

    UNPARSED = "(not a recognisable URL)".freeze
    LOCAL_FILES = "(local files)".freeze
    FLAG_BITS = FLAGS.keys.each_with_index.to_h { |flag, i| [flag, 1 << i] }.freeze
    # Flag names for every combination of bits, looked up once per domain.
    FLAG_SETS = (0...(1 << FLAGS.size)).map { |bits| FLAG_BITS.select { |_, b| bits & b != 0 }.keys.freeze }.freeze
    UNPARSED_RESULT = [UNPARSED, :other, 0].freeze
    LOCAL_FILES_RESULT = [LOCAL_FILES, :local, 0].freeze

    def initialize(urls)
      @urls = ScanPage.list(urls)
      @hosts = {}
    end

    def url_count
      @urls.size
    end

    def domain_count
      domains.size
    end

    # Most URLs first, then by name, so the busiest domains lead the list.
    # Flags are kept as bits while grouping: this runs per URL, and some
    # extensions carry tens of thousands.
    def domains
      @domains ||= begin
        buckets = {}
        @urls.each do |entry|
          url = entry.is_a?(String) ? entry : ScanPage.text(entry)
          name, category, bits = parse(url)
          bucket = (buckets[name] ||= [category, [], 0])
          bucket[1] << url
          bucket[2] |= bits
        end
        buckets
          .map { |name, (category, urls, bits)| Domain.new(name: name, category: category, urls: urls, flags: FLAG_SETS[bits]) }
          .sort_by { |d| [-d.urls.size, d.name] }
      end
    end

    def category_counts
      counts = domains.group_by(&:category).transform_values(&:size)
      CATEGORIES.keys.filter_map { |key| [key, counts[key]] if counts[key] }.to_h
    end

    # Labels the page script needs to decode #encoded.
    def self.labels
      { categories: CATEGORIES.values, flags: FLAGS.values }
    end

    def summary
      Summary.new(url_count: url_count, domain_count: domain_count, category_counts: category_counts, encoded: encoded)
    end

    # Compact text form for the page script, so each URL is in the HTML once
    # and needs no quoting: one domain per line, fields separated by tabs:
    #   name, category index, flag bits, url, url, ...
    # Indexes and bits follow CATEGORIES and FLAGS. Stored URLs never hold
    # whitespace, but junk could, so tabs and newlines are replaced.
    def encoded
      category_index = CATEGORIES.keys.each_with_index.to_h
      domains.map do |d|
        fields = [d.name, category_index.fetch(d.category), d.flags.sum { |f| FLAG_BITS.fetch(f) }, *d.urls]
        fields.map { |f| (f = f.to_s).match?(/[\t\n\r]/) ? f.tr("\t\n\r", "   ") : f }.join("\t")
      end.join("\n")
    end

    # [bucket, category, flag bits] for one URL string. Never raises.
    def parse(url)
      match = AUTHORITY.match(url)
      return UNPARSED_RESULT unless match

      scheme, raw_host, port = match.captures
      if raw_host.empty?
        return scheme.casecmp?("file") && port.nil? ? LOCAL_FILES_RESULT : UNPARSED_RESULT
      end

      bucket, category, bits = classify_host(raw_host)
      return UNPARSED_RESULT if bucket.nil?

      bits |= FLAG_BITS[:http] if scheme.casecmp?("http")
      bits |= FLAG_BITS[:port] if port && !port.empty? && port.to_i != DEFAULT_PORTS[scheme.downcase]
      [bucket, category, bits]
    end

    private

    # Cached per host as written: [bucket, category, flag bits], or nils when
    # the host is not a hostname or IP address.
    def classify_host(raw_host)
      @hosts[raw_host] ||= begin
        host = raw_host.delete_prefix("[").delete_suffix("]").downcase.chomp(".")
        if host.empty?
          [nil, nil, 0]
        elsif (ip = ip_address(host))
          local = ip.loopback? || ip.private? || ip.link_local? || ip.to_s == "0.0.0.0" || ip.to_s == "::"
          [host, local ? :local : :ip, FLAG_BITS[:ip]]
        elsif !host.match?(HOST_SHAPE) || host.match?(IPV4_SHAPE)
          [nil, nil, 0]
        elsif host == "localhost" || host.end_with?(".localhost", ".local")
          [host, :local, 0]
        else
          domain = registrable_domain(host)
          category = category_for(host, domain)
          [domain, category, category == :shortener ? FLAG_BITS[:shortener] : 0]
        end
      end
    end

    def ip_address(host)
      return nil unless host.match?(IPV4_SHAPE) || host.include?(":")

      IPAddr.new(host)
    rescue IPAddr::Error
      nil
    end

    # ICANN suffixes only: private entries such as github.io or
    # googleapis.com would give every subdomain its own row, which splits
    # one provider across many rows. The expanded row still shows full URLs.
    #
    # Same answer as PublicSuffix.domain(host, ignore_private: true) (checked against every host in the
    # sample scans, plus wildcard and exception rules) at about a third of the
    # cost: PublicSuffix::Rule#decompose builds a regexp per call, which adds
    # up with tens of thousands of hosts. Falls back to the host itself, e.g.
    # when the host is itself a public suffix.
    def registrable_domain(host)
      rule = PublicSuffix::List.default.find(host, ignore_private: true)
      suffix_labels = rule.parts.size + (rule.is_a?(PublicSuffix::Rule::Wildcard) ? 1 : 0)
      labels = host.split(".")
      labels.size > suffix_labels ? labels.last(suffix_labels + 1).join(".") : host
    rescue StandardError
      host
    end

    def category_for(host, domain)
      name = host
      while name
        category = KNOWN_DOMAINS[name]
        return category if category

        dot = name.index(".")
        name = dot && name[(dot + 1)..]
      end
      # Google's country domains (google.de, google.co.uk, ...).
      return :google if domain.include?(".") && domain.split(".").first == "google"

      :other
    end
  end
end
