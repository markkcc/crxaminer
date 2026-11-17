require "net/http"
require "nokogiri"
require "uri"

# Fetches and parses an extension's Chrome Web Store listing.
#
#   ChromeStoreClient.new(id).fetch_details # => ChromeStoreClient::Result
#   ChromeStoreClient.parse(html, extension_id: id) # pure, for tests
#
# Fields are found by what the page says (row labels, Open Graph tags,
# aria-labels, link targets), never by Google's generated class names, and
# each one independently, so one change on the page loses one field. Values
# that do not look right ("Share" as a user count) are dropped, not stored.
# The page is requested in English (hl=en): labels in other languages simply
# do not match, so a non-English page yields empty fields, not wrong ones.
#
# Nothing here raises: failures come back as a Result with status :error.
class ChromeStoreClient
  HOST = "chromewebstore.google.com".freeze
  MAX_REDIRECTS = 3
  OPEN_TIMEOUT = 5
  READ_TIMEOUT = 10
  MAX_BODY_BYTES = 5 * 1024 * 1024

  # The extension_details keys, in their stored formats: author "Acme",
  # rating "4.4", rating_count "247 ratings", users "300,000", size "6.89MiB",
  # last_updated "November 15, 2026", developer_info (one line),
  # store_description. Badges are added as true only when present.
  DETAIL_KEYS = %i[author rating rating_count users size last_updated developer_info store_description].freeze
  BADGE_KEYS = %i[featured established_publisher].freeze

  DEVELOPER_INFO_LIMIT = 300
  SHORT_TEXT_LIMIT = 200
  STORE_TITLE = "Chrome Web Store".freeze

  # status: :ok (a listing was parsed), :unavailable (the store has no
  # listing: removed, never existed, or 404), :error (fetch failed or the
  # page was not recognised; reason says why).
  Result = Struct.new(:status, :name, :image, :details, :reason, keyword_init: true) do
    def ok? = status == :ok
    def unavailable? = status == :unavailable
    def error? = status == :error
  end

  Response = Struct.new(:code, :location, :body, keyword_init: true)

  class FetchError < StandardError; end

  # One GET over HTTPS with timeouts and a body cap; redirects are returned,
  # not followed. Replaceable in tests.
  class NetHttpTransport
    def get(uri, headers)
      Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: OPEN_TIMEOUT,
                                          read_timeout: READ_TIMEOUT, write_timeout: READ_TIMEOUT,
                                          ssl_timeout: OPEN_TIMEOUT) do |http|
        result = nil
        http.request(Net::HTTP::Get.new(uri.request_uri, headers)) do |response|
          body = +""
          if response.is_a?(Net::HTTPSuccess)
            response.read_body do |chunk|
              body << chunk
              raise FetchError, "page larger than #{MAX_BODY_BYTES} bytes" if body.bytesize > MAX_BODY_BYTES
            end
          end
          result = Response.new(code: response.code.to_i, location: response["location"], body: body)
        end
        result
      end
    end
  end

  def self.listing_url(extension_id)
    URI("https://#{HOST}/detail/#{extension_id}?hl=en")
  end

  def initialize(extension_id, transport: NetHttpTransport.new, logger: Rails.logger)
    @extension_id = extension_id.to_s.downcase.gsub(/[^a-z0-9]/, "")
    @transport = transport
    @logger = logger
  end

  def fetch_details
    final_uri, html = fetch_page
    result = if html.nil?
      unavailable_result
    else
      result_from(self.class.parse(html, extension_id: @extension_id))
    end
    log(result, final_uri)
    result
  rescue StandardError => e
    result = Result.new(status: :error, name: nil, image: nil, details: self.class.empty_details,
                        reason: e.is_a?(FetchError) ? e.message : "#{e.class.name.demodulize}: #{e.message.to_s.truncate(200)}")
    log(result, nil)
    result
  end

  # ---- Parsing (pure) -------------------------------------------------------

  class << self
    def empty_details
      DETAIL_KEYS.index_with(nil)
    end

    # Returns { page:, lang:, name:, image:, details: }. page is :listing,
    # :unavailable (the store's generic "item not found" page) or
    # :unrecognized. Never raises.
    def parse(html, extension_id: nil)
      blank = { page: :unrecognized, lang: nil, name: nil, image: nil, details: empty_details }
      return blank unless html.is_a?(String) && !html.strip.empty?

      doc = Nokogiri::HTML5(utf8(html), max_errors: 0)
      lang = safely { doc.root&.[]("lang").to_s.strip.presence }
      h1 = safely { doc.at_css("h1") }
      og_title = meta(doc, "og:title")

      if h1.nil? && unavailable_page?(doc, og_title)
        return blank.merge(page: :unavailable, lang: lang)
      end

      header = safely { h1 && (h1.ancestors("section").first || h1.parent&.parent) }
      rows = safely { detail_rows(doc) } || {}
      developer = safely { developer_block(rows["Developer"]) } || {}
      offered_by = safely { short(text_of(rows["Offered by"])) }

      details = {
        author: offered_by || developer[:name],
        rating: safely { rating(header) },
        rating_count: safely { rating_count(header, extension_id) },
        users: safely { users(header) },
        size: safely { matching(text_of(rows["Size"]), /\A\d[\d.,]*\s?(?:[KMGT]i?B|B|bytes)\z/i) },
        last_updated: safely { matching(text_of(rows["Updated"]), /\A[A-Z][a-z]+ \d{1,2}, \d{4}\z/) },
        developer_info: developer[:summary],
        store_description: safely { store_description(doc) }
      }
      details[:featured] = true if safely { featured?(header) }
      details[:established_publisher] = true if safely { established_publisher?(header) }

      name = safely { short(clean_entities(squish(h1&.text))) } ||
             safely { short(clean_entities(og_title.to_s.delete_suffix(" - #{STORE_TITLE}").strip)) }
      name = nil if name == STORE_TITLE

      {
        page: name ? :listing : :unrecognized,
        lang: lang,
        name: name,
        image: safely { image(doc, header) },
        details: details
      }
    rescue StandardError
      blank
    end

    # Best-effort listing description from the standard meta tags.
    def store_description(doc)
      return nil unless doc

      meta(doc, "og:description") || doc.at_css('meta[name="description"]')&.[]("content").to_s.strip.presence
    rescue StandardError
      nil
    end

    private

    def safely
      yield
    rescue StandardError
      nil
    end

    def utf8(string)
      string.dup.force_encoding(Encoding::UTF_8).scrub("")
    end

    def squish(text)
      text.to_s.tr(" ", " ").squish.presence
    end

    def short(text, limit = SHORT_TEXT_LIMIT)
      text = squish(text)
      text && text.length > limit ? "#{text[0, limit - 1]}…" : text
    end

    def matching(text, pattern)
      text = squish(text)
      text if text&.match?(pattern)
    end

    def text_of(nodes)
      squish(Array(nodes).map(&:text).join(" "))
    end

    # The store sometimes double-escapes names ("&amp;amp;"), which leaves
    # entity text after parsing.
    def clean_entities(text)
      return nil if text.nil?

      text.gsub("&mdash;", "—").gsub("&ndash;", "-").gsub("&reg;", "®").gsub("&trade;", "™")
          .gsub("&copy;", "©").gsub("&amp;", "&")
    end

    def meta(doc, property)
      doc.at_css(%(meta[property="#{property}"]))&.[]("content").to_s.strip.presence
    end

    # The store answers removed and unknown IDs with HTTP 200 and its home
    # page shell: no <h1> and the bare store title.
    def unavailable_page?(doc, og_title)
      title = squish(doc.at_css("title")&.text)
      og_url = meta(doc, "og:url").to_s.chomp("/")
      title == STORE_TITLE || og_title == STORE_TITLE || og_url == "https://#{HOST}"
    end

    # The "Details" list: { "Label" => [value nodes] }. Each <li> is a label
    # element followed by the value. Falls back to every <li> on the page
    # if the heading moves.
    def detail_rows(doc)
      heading = doc.css("h2").find { |h| squish(h.text) == "Details" }
      container = heading&.ancestors&.find { |a| a.at_css("li") } || doc
      container.css("li").each_with_object({}) do |li, rows|
        label_node, *value = li.element_children
        next if label_node.nil? || value.empty?

        label = squish(label_node.xpath("./text()").text) || squish(label_node.text)
        rows[label] ||= value if label
      end
    end

    # The Developer block: name and address lines, then a Website link and
    # <details> for Email and Phone. Returns { name:, summary: }.
    def developer_block(nodes)
      block = Array(nodes).first
      return {} unless block

      lines = address_lines(block)
      website = block.css("a[href]").find { |a| squish(a.text) == "Website" }&.[]("href").to_s.strip
      website = website.match?(%r{\Ahttps?://[^\s/]+}i) ? website.sub(%r{\Ahttps?://}i, "").chomp("/") : nil
      contacts = block.css("details").to_h do |d|
        summary = d.at_css("summary")
        [squish(summary&.text), squish(d.element_children.reject { |c| c == summary }.map(&:text).join(" "))]
      end

      parts = [lines.join(", ").presence]
      parts << "Website: #{website}" if website
      %w[Email Phone].each { |label| parts << "#{label}: #{contacts[label]}" if contacts[label] }
      summary = parts.compact.join("; ").presence

      { name: short(lines.first, 100), summary: summary && short(summary, DEVELOPER_INFO_LIMIT) }
    end

    # Text of the block outside links and <details>, split on <br> and
    # newlines.
    def address_lines(block)
      buffer = +""
      block.traverse do |node|
        next if node.ancestors.any? { |a| %w[a details summary button].include?(a.name) }

        if node.text?
          buffer << node.text
        elsif node.name == "br"
          buffer << "\n"
        end
      end
      buffer.split("\n").filter_map { |line| squish(line) }
    end

    def rating(header)
      return nil unless header

      header.css("[aria-label]").each do |node|
        match = node["aria-label"].to_s.match(/\AAverage rating (\d(?:\.\d{1,2})?) out of 5 stars/)
        return match[1] if match
      end
      nil
    end

    # Text of the link to this item's reviews page: "247 ratings", "44.9K ratings".
    def rating_count(header, extension_id)
      return nil unless header

      suffix = extension_id.present? ? "/#{extension_id}/reviews" : "/reviews"
      header.css("a[href]").each do |a|
        next unless a["href"].to_s.split(/[?#]/).first.to_s.end_with?(suffix)

        text = matching(a.text, /\A\d[\d.,]*[KMB]? ratings?\z/i)
        return text if text
      end
      nil
    end

    # "300,000 users" next to the category links; stored without " users".
    def users(header)
      return nil unless header

      header.xpath(".//text()").each do |node|
        match = squish(node.text).to_s.match(/\A(\d[\d.,]*[KMB]?\+?) users?\z/i)
        return match[1] if match
      end
      nil
    end

    def featured?(header)
      return false unless header

      header.xpath(".//text()").any? { |node| squish(node.text) == "Featured" } ||
        header.css("[aria-label]").any? { |n| n["aria-label"].to_s.start_with?("Follows recommended practices for Chrome extensions") }
    end

    def established_publisher?(header)
      return false unless header

      header.css("[aria-label]").any? { |n| n["aria-label"].to_s.start_with?("Created by the owner of the listed website") } ||
        header.xpath(".//text()").any? { |node| squish(node.text)&.casecmp?("Established publisher") }
    end

    def image(doc, header)
      candidates = []
      if header
        candidates << header.css("img[alt]").find { |img| img["alt"].to_s.start_with?("Item logo image") }&.[]("src")
        candidates << header.at_css("img[src]")&.[]("src")
      end
      candidates << meta(doc, "og:image")
      candidates.map { |src| src.to_s.strip }.find { |src| src.match?(%r{\Ahttps://[^\s"'<>]+\z}) }
    end
  end

  private

  def request_headers
    {
      "User-Agent" => ChromeVersion.user_agent,
      "Accept" => "text/html,application/xhtml+xml",
      "Accept-Language" => "en-US,en;q=0.9"
    }
  end

  # Follows at most MAX_REDIRECTS redirects, only within HOST over HTTPS,
  # keeping hl=en. Returns [final_uri, html], or [final_uri, nil] for 404/410.
  def fetch_page
    uri = self.class.listing_url(@extension_id)
    seen = []
    (MAX_REDIRECTS + 1).times do
      raise FetchError, "redirect loop at #{uri.path}" if seen.include?(uri.to_s)

      seen << uri.to_s
      response = @transport.get(uri, request_headers)
      case response.code.to_i
      when 200
        return [uri, response.body.to_s]
      when 301, 302, 303, 307, 308
        uri = redirect_target(uri, response.location)
      when 404, 410
        return [uri, nil]
      else
        raise FetchError, "HTTP #{response.code}"
      end
    end
    raise FetchError, "more than #{MAX_REDIRECTS} redirects"
  end

  def redirect_target(from, location)
    raise FetchError, "redirect without a location" if location.to_s.strip.empty?

    # Slugs can carry raw non-ASCII characters, which URI rejects.
    escaped = location.strip.b.gsub(/[^\x21-\x7e]/n) { |byte| format("%%%02X", byte.ord) }
    target = from.merge(URI.parse(escaped))
    unless target.scheme == "https" && target.host.to_s.downcase == HOST && target.port == 443 && target.userinfo.nil?
      raise FetchError, "redirect to #{target.scheme}://#{target.host} refused"
    end

    params = URI.decode_www_form(target.query.to_s).reject { |key, _| key == "hl" }
    target.query = URI.encode_www_form(params + [%w[hl en]])
    target
  end

  def unavailable_result
    Result.new(status: :unavailable, name: nil, image: nil, details: self.class.empty_details,
               reason: "no listing in the Chrome Web Store")
  end

  def result_from(parsed)
    case parsed[:page]
    when :unavailable
      unavailable_result
    when :listing
      Result.new(status: :ok, name: parsed[:name], image: parsed[:image], details: parsed[:details],
                 reason: parsed[:lang].to_s.start_with?("en") || parsed[:lang].nil? ? nil : "page language #{parsed[:lang]}")
    else
      Result.new(status: :error, name: nil, image: parsed[:image], details: parsed[:details],
                 reason: "listing page not recognised")
    end
  end

  # One line per scrape, so the next change on the store shows in the logs.
  def log(result, final_uri)
    fields = { name: result.name, image: result.image }.merge(result.details.to_h.slice(*DETAIL_KEYS))
    found = fields.select { |_, v| v.present? }.keys
    missing = fields.keys - found
    badges = BADGE_KEYS.select { |k| result.details.to_h[k] }
    line = "Chrome Web Store #{@extension_id}: status=#{result.status}"
    line += " path=#{final_uri.path}" if final_uri
    line += " reason=#{result.reason.inspect}" if result.reason
    line += " found=#{found.join(',').presence || '-'} missing=#{missing.join(',').presence || '-'}"
    line += " badges=#{badges.join(',').presence || '-'}"
    result.ok? && missing.empty? ? @logger.info(line) : @logger.warn(line)
  rescue StandardError
    nil
  end
end
