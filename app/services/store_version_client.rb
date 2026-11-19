require "net/http"
require "nokogiri"
require "uri"

# Asks Google's update server which version of an extension the Chrome Web
# Store offers now, without downloading the package.
#
#   StoreVersionClient.lookup(id)     # => Result, cached per extension
#   StoreVersionClient.cached(id)     # => Result or nil, never fetches
#   StoreVersionClient.new(id).fetch  # => Result, always asks Google
#   StoreVersionClient.parse(xml, extension_id: id) # pure, for tests
#
# The update check answers "noupdate" both for extensions that left the store
# and for listed ones that need a newer Chrome than we report, so a missing
# version means "no version available to us", never "removed".
#
# Nothing here raises: failures come back as a Result with status :error.
class StoreVersionClient
  HOST = "clients2.google.com".freeze
  OPEN_TIMEOUT = 3
  READ_TIMEOUT = 4
  MAX_BODY_BYTES = 64 * 1024

  # How long an answer is kept: a known version changes rarely; "no version"
  # and failures are retried sooner, but not so often that a broken upstream
  # is asked on every page view.
  KNOWN_TTL = 6.hours
  UNKNOWN_TTL = 15.minutes
  CACHE_NAMESPACE = "store_version/v1".freeze

  # One to four dot-separated integers, each 0 to 65535, as Chrome requires.
  VERSION_FORMAT = /\A\d{1,5}(?:\.\d{1,5}){0,3}\z/

  # status: :ok (version is set), :unavailable (the update server has no
  # version for us: unknown ID, removed, or needs a newer Chrome), :error
  # (fetch failed or the reply was not understood; reason says why).
  Result = Struct.new(:status, :version, :reason, keyword_init: true) do
    def ok? = status == :ok
    def unavailable? = status == :unavailable
    def error? = status == :error
  end

  Response = Struct.new(:code, :body, keyword_init: true)

  class FetchError < StandardError; end

  # One GET over HTTPS with short timeouts and a body cap. Redirects are not
  # followed (the update check answers 200 directly). Replaceable in tests.
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
              raise FetchError, "reply larger than #{MAX_BODY_BYTES} bytes" if body.bytesize > MAX_BODY_BYTES
            end
          end
          result = Response.new(code: response.code.to_i, body: body)
        end
        result
      end
    end
  end

  class << self
    def update_check_url(extension_id)
      URI("https://#{HOST}/service/update2/crx?response=updatecheck&prodversion=#{ChromeVersion.prodversion}" \
          "&acceptformat=crx2,crx3&x=id%3D#{extension_id}%26uc")
    end

    # The answer depends on the Chrome version we report, so it is part of
    # the key.
    def cache_key(extension_id)
      "#{CACHE_NAMESPACE}/#{ChromeVersion.prodversion}/#{extension_id}"
    end

    # Cached answer, or a fresh one (then cached). Callers must only pass IDs
    # of stored scans.
    def lookup(extension_id, cache: Rails.cache)
      data = cache.fetch(cache_key(extension_id), expires_in: KNOWN_TTL) do |_key, options|
        result = new(extension_id).fetch
        options.expires_in = UNKNOWN_TTL unless result.ok?
        result.to_h
      end
      from_cache(data) || new(extension_id).fetch
    end

    # The cached answer if there is one; never touches the network.
    def cached(extension_id, cache: Rails.cache)
      from_cache(cache.read(cache_key(extension_id)))
    rescue StandardError
      nil
    end

    def valid_version?(value)
      value.is_a?(String) && value.match?(VERSION_FORMAT) && value.split(".").all? { |part| part.to_i <= 65_535 }
    end

    # Parses an update-check reply. Never raises.
    def parse(xml, extension_id: nil)
      return error("empty reply") unless xml.is_a?(String) && !xml.strip.empty?
      return error("reply larger than #{MAX_BODY_BYTES} bytes") if xml.bytesize > MAX_BODY_BYTES
      # The real reply has no DTD; refusing one rules out entity tricks.
      return error("reply has a DOCTYPE") if xml.include?("<!DOCTYPE")

      # strict: junk is an error, not a guess. nonet, nodtdload and no noent:
      # no network access and no entity expansion.
      doc = Nokogiri::XML(xml) { |config| config.strict.nonet.nodtdload }
      app = doc.at_xpath("/*[local-name()='gupdate']/*[local-name()='app']")
      return error("no app element") unless app

      appid = app["appid"].to_s.downcase
      return error("reply is for another extension") if extension_id.present? && appid != extension_id.to_s.downcase

      app_status = app["status"].to_s
      return unavailable("app status #{app_status.truncate(40)}") unless app_status == "ok"

      check = app.at_xpath("./*[local-name()='updatecheck']")
      return error("no updatecheck element") unless check

      case check["status"].to_s
      when "ok"
        version = check["version"].to_s
        return error("version not recognised") unless valid_version?(version)

        Result.new(status: :ok, version: version, reason: nil)
      when "noupdate"
        unavailable("noupdate")
      else
        error("updatecheck status #{check['status'].to_s.truncate(40)}")
      end
    rescue Nokogiri::XML::SyntaxError
      error("reply is not XML")
    rescue StandardError => e
      error("#{e.class.name.demodulize}: #{e.message.to_s.truncate(100)}")
    end

    private

    def error(reason) = Result.new(status: :error, version: nil, reason: reason)
    def unavailable(reason) = Result.new(status: :unavailable, version: nil, reason: reason)

    # Accepts only what lookup writes, re-checking the version.
    def from_cache(data)
      return nil unless data.is_a?(Hash)

      status = data[:status]
      case status
      when :ok
        valid_version?(data[:version]) ? Result.new(status: :ok, version: data[:version], reason: nil) : nil
      when :unavailable, :error
        Result.new(status: status, version: nil, reason: data[:reason])
      end
    end
  end

  def initialize(extension_id, transport: NetHttpTransport.new, logger: Rails.logger)
    @extension_id = extension_id.to_s.downcase.gsub(/[^a-z0-9]/, "")
    @transport = transport
    @logger = logger
  end

  def fetch
    result = begin
      response = @transport.get(self.class.update_check_url(@extension_id), request_headers)
      if response.code.to_i == 200
        self.class.parse(response.body.to_s, extension_id: @extension_id)
      else
        Result.new(status: :error, version: nil, reason: "HTTP #{response.code}")
      end
    rescue StandardError => e
      Result.new(status: :error, version: nil,
                 reason: e.is_a?(FetchError) ? e.message : "#{e.class.name.demodulize}: #{e.message.to_s.truncate(100)}")
    end
    log(result)
    result
  end

  private

  def request_headers
    { "User-Agent" => ChromeVersion.user_agent, "Accept" => "text/xml, application/xml" }
  end

  def log(result)
    line = "Store version #{@extension_id}: status=#{result.status}"
    line += " version=#{result.version}" if result.version
    line += " reason=#{result.reason.inspect}" if result.reason
    result.error? ? @logger.warn(line) : @logger.info(line)
  rescue StandardError
    nil
  end
end
