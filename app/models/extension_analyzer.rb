require 'net/http'
require 'nokogiri'
require 'zip'
require 'json'
require 'uri'
require 'cgi'
require 'open-uri'

class ExtensionAnalyzer
  include ActiveModel::Model

  attr_reader :extension_id, :extension_details, :extension_name,
              :extension_image, :manifest, :security_findings, :error

  # previous_findings: the stored findings of an earlier scan of this
  # extension, used to reuse its AI analysis when the input is unchanged.
  def initialize(extension_id, previous_findings: nil)
    @extension_id = extension_id.downcase
    @previous_findings = previous_findings
  end

  NOT_IN_STORE_MESSAGE = "This extension is not available in the Chrome Web Store. " \
                         "It may have been removed, or the extension ID may be wrong.".freeze

  # How JSON files inside an extension package are parsed. Chrome accepts
  # comments and repeated keys (the last one wins) in manifest.json; json 3
  # rejects both unless asked, so ask.
  PACKAGE_JSON_OPTIONS = { allow_comments: true, allow_duplicate_key: true }.freeze

  # The manifest's name for display: the resolved __MSG_ value, else the raw
  # name unless it is an unresolved placeholder. Nil when there is none.
  def self.manifest_display_name(manifest)
    return nil unless manifest.respond_to?(:[])

    name = manifest[:localized_name].presence || manifest[:name]
    name = name.to_s.squish
    return nil if name.empty? || name.match?(/\A__MSG_\w+__\z/)

    name.truncate(200)
  end

  # Resolves a "__MSG_key__" manifest value from
  # _locales/<default_locale>/messages.json (keys are case-insensitive).
  # Returns the value unchanged when it is not a placeholder, or nil when the
  # placeholder cannot be resolved.
  def self.resolve_locale_message(value, messages)
    return value unless value.is_a?(String)

    match = value.match(/\A__MSG_(\w+)__\z/)
    return value unless match

    message = messages[match[1].downcase]
    message.is_a?(Hash) ? message["message"].presence : nil
  end

  # Reads the default locale's messages.json from an open Zip::File and
  # returns it with downcased keys ({} when missing or unreadable).
  def self.locale_messages(zip_file, default_locale)
    candidates = [default_locale, "en"].compact.map(&:to_s).reject(&:empty?).uniq
    candidates.each do |locale|
      path = "_locales/#{locale}/messages.json".downcase
      entry = zip_file.entries.find { |e| e.name.downcase == path }
      next unless entry

      parsed = JSON.parse(entry.get_input_stream.read.force_encoding("UTF-8").delete_prefix("\uFEFF"), **PACKAGE_JSON_OPTIONS)
      return parsed.transform_keys { |k| k.to_s.downcase } if parsed.is_a?(Hash)
    end
    {}
  rescue StandardError => e
    Rails.logger.warn "Could not read locale messages: #{e.message}"
    {}
  end

  # The update server's CRX download URL, reporting ChromeVersion.prodversion.
  def self.crx_download_url(extension_id)
    "https://clients2.google.com/service/update2/crx?response=redirect&" \
      "prodversion=#{ChromeVersion.prodversion}&acceptformat=crx2,crx3&" \
      "x=id%3D#{extension_id}%26installsource%3Dondemand%26uc"
  end

  def perform
    validate_extension_id
    return self if error?

    fetch_chrome_store_data

    download_and_analyze_extension
    self
  end

  def error?
    @error.present?
  end

  private

  def validate_extension_id
    unless @extension_id =~ /^[a-z0-9]{32}$/
      @error = "Invalid extension ID: Must be 32 alphanumeric characters long."
    end
  end

  # Store listing data. Never stops the scan: an unlisted extension can still
  # be downloadable, and the download step reports what went wrong.
  def fetch_chrome_store_data
    @store_listing = ChromeStoreClient.new(@extension_id).fetch_details
    @extension_name = @store_listing.name
    @extension_image = @store_listing.image
    @extension_details = @store_listing.details
  end

  def download_and_analyze_extension
    download_url = self.class.crx_download_url(@extension_id)

    begin
      Turbo::StreamsChannel.broadcast_update_to(
        "analysis_#{@extension_id}",
        target: "analysis_status",
        partial: "scan/loading_status",
        locals: { message: "Downloading extension..." }
      )

      response = request_crx(URI(download_url))

      Rails.logger.debug "Download response code: #{response.code}"
      Rails.logger.debug "Download response headers: #{response.to_hash.inspect}"
      Rails.logger.debug "Download URL: #{download_url}"

      if response.code == "204"
        @error = no_download_message
        return
      end

      if response.code == "302" || response.code == "301"
        response = request_crx(URI(response['location']))
      end

      crx_data = response.body
      Rails.logger.debug "Downloaded bytes: #{crx_data&.bytesize || 0}"

      if crx_data.nil? || crx_data.empty?
        @error = @store_listing&.unavailable? ? NOT_IN_STORE_MESSAGE : "Failed to download extension (empty response)"
        return
      end

      @manifest = extract_manifest(crx_data)

      if @manifest
        # The store gave no name (unlisted, or the page changed): use the
        # manifest's so the page and the tweet are not blank.
        @extension_name = self.class.manifest_display_name(@manifest) if @extension_name.blank?

        Turbo::StreamsChannel.broadcast_update_to(
          "analysis_#{@extension_id}",
          target: "analysis_status",
          partial: "scan/loading_status",
          locals: { message: "Analyzing security..." }
        )

        analyzer = ExtensionSecurityAnalyzer.new(@manifest, @extension_details, @extension_name, @extension_id,
                                                 previous_findings: @previous_findings)
        @security_findings = analyzer.analyze
      end
    rescue OpenURI::HTTPError => e
      @error = "Failed to download extension. Please check the ID and try again."
    rescue StandardError => e
      Rails.logger.error "Error analyzing extension: #{e.message}"
      @error = "An error occurred while analyzing the extension."
    end
  end

  def request_crx(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri.request_uri)
    request['User-Agent'] = ChromeVersion.user_agent
    request['Accept'] = '*/*'
    http.request(request)
  end

  # The update server answered 204: no package for this ID and Chrome version.
  def no_download_message
    if @store_listing&.unavailable?
      NOT_IN_STORE_MESSAGE
    elsif @store_listing&.ok?
      "The Chrome Web Store lists this extension but did not provide a download. It may need a newer " \
        "Chrome version than CRXaminer reports (Chrome #{ChromeVersion.major}), or it may not be downloadable."
    else
      "The Chrome Web Store did not provide a download for this extension. It may have been removed, " \
        "may need a newer Chrome version than CRXaminer reports, or may not be downloadable."
    end
  end

  def extract_manifest(crx_data)
    temp_dir = Rails.root.join('tmp', 'extensions')
    FileUtils.mkdir_p(temp_dir)
    zip_path = temp_dir.join("extension_#{@extension_id}.zip")
    raise "Downloaded extension file is empty" if crx_data.empty?

    begin
      if crx_data.start_with?('Cr24')
        # Process CRX file
        version = crx_data[4..7].unpack('L<')[0]
        header_size = crx_data[8..11].unpack('L<')[0]
        offset = 12 + header_size

        File.open(zip_path, "wb") do |file|
          file.write(crx_data[offset..-1])
        end
      else
        # Process ZIP file directly
        File.open(zip_path, "wb") do |file|
          file.write(crx_data)
        end
      end

      # Read manifest from ZIP
      urls = []
      url_pattern = /(?:https?|ftp|file):\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9]{1,6}[-a-zA-Z0-9@:%_\+.~#?&\/=]*/

      Zip::File.open(zip_path) do |zip_file|
        manifest_entry = zip_file.glob('manifest.json').first
        raise "manifest.json not found in extension" unless manifest_entry
        manifest_content = manifest_entry.get_input_stream.read
        manifest = JSON.parse(manifest_content, **PACKAGE_JSON_OPTIONS)

        # Scan all files in the ZIP for URLs
        zip_file.each do |entry|
          next if entry.directory?

          begin
            content = entry.get_input_stream.read
            # Try to read as UTF-8 text, skip if binary
            content = content.force_encoding('UTF-8')
            next unless content.valid_encoding?

            # Find all URLs in the content
            found_urls = content.scan(url_pattern).flatten
            urls.concat(found_urls) if found_urls.any?
          rescue
            next # Skip files that can't be read as text
          end
        end

        # Extract content security policy values
        content_security_policy = []
        if manifest['content_security_policy']
          if manifest['content_security_policy'].is_a?(Hash)
            manifest['content_security_policy'].each do |key, value|
              content_security_policy << "#{key}: #{value}"
            end
          else
            content_security_policy << manifest['content_security_policy']
          end
        end

        # Resolve __MSG_*__ placeholders while the package is open.
        locale_messages = if [manifest['name'], manifest['description']].any? { |v| v.to_s.start_with?('__MSG_') }
          self.class.locale_messages(zip_file, manifest['default_locale'])
        else
          {}
        end

        return {
          manifest_version: manifest['manifest_version'],
          name: manifest['name'],
          localized_name: self.class.resolve_locale_message(manifest['name'], locale_messages),
          localized_description: self.class.resolve_locale_message(manifest['description'], locale_messages),
          version: manifest['version'],
          permissions: manifest['permissions'] || [],
          optional_permissions: manifest['optional_permissions'] || [],
          host_permissions: manifest['host_permissions'] || [],
          content_scripts: manifest['content_scripts'],
          embedded_urls: urls.uniq,
          content_security_policy: content_security_policy,
          raw: manifest
        }
      end
    ensure
      # Clean up temporary files
      FileUtils.rm_f(zip_path)
    end
  rescue => e
    Rails.logger.error "Error extracting manifest: #{e.message}"
    nil
  end
end 