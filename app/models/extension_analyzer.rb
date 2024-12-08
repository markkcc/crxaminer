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

  def initialize(extension_id)
    @extension_id = extension_id
  end

  def perform
    validate_extension_id
    return self if error?

    fetch_chrome_store_data
    return self if error?

    download_and_analyze_extension
    self
  end

  def error?
    @error.present?
  end

  private

  def validate_extension_id
    unless @extension_id =~ /^[a-zA-Z0-9]{32}$/
      @error = "Invalid extension ID: Must be 32 alphanumeric characters long."
    end
  end

  def fetch_chrome_store_data
    @extension_details = {}

    begin
      # Extract and clean the extension ID
      extension_id = @extension_id.to_s
                                .split('/')
                                .last
                                .gsub(/[^a-zA-Z0-9]/, '') # Remove any non-alphanumeric characters

      store_url = "https://chromewebstore.google.com/detail/#{extension_id}"

      uri = URI.parse(store_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      request = Net::HTTP::Get.new(uri.path)
      request['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

      response = http.request(request)

      # Follow redirect if necessary
      if response.code == "301" || response.code == "302"
        redirect_location = response['location']

        # Parse the URL into components
        uri_parts = redirect_location.match(%r{(https?://[^/]+)(/.*$)})
        if uri_parts
          protocol_and_host = uri_parts[1]
          path = uri_parts[2]

          # Only encode the path portion
          encoded_path = URI.encode_www_form_component(URI.decode_www_form_component(path))
                           .gsub('%2F', '/') # Preserve forward slashes

          redirect_location = protocol_and_host + encoded_path
        end

        redirect_uri = URI.parse(redirect_location)

        http = Net::HTTP.new(redirect_uri.host, redirect_uri.port)
        http.use_ssl = true
        request = Net::HTTP::Get.new(redirect_uri.path)
        request['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        response = http.request(request)
      end

      # Ensure proper encoding when parsing HTML
      doc = Nokogiri::HTML(response.body.force_encoding('UTF-8'))
      raw_extension_name = doc.css('h1').first&.text&.strip.to_s

      @extension_name = raw_extension_name
                        .gsub('&mdash;', '—')
                        .gsub('&ndash;', '-')
                        .gsub('&reg;', '®')
                        .gsub('&trade;', '™')
                        .gsub('&copy;', '©')
                        .gsub('&amp;', '&')


      @extension_image = doc.css('.rBxtY').first&.attr('src')

      # Find elements by their text content
      size_element = doc.css('.nws2nb').find { |el| el.text.strip == "Size" }
      updated_element = doc.css('.nws2nb').find { |el| el.text.strip == "Updated" }
      users_element = doc.css('.gqpEIe.bgp7Ye').first&.next_sibling&.text&.strip&.split(' ')&.first

      @extension_details = {
        author: doc.css('.cJI8ee').first&.text&.strip.to_s
                .gsub('&amp;', '&'),
        rating: doc.css('.Vq0ZA').first&.text&.strip,
        rating_count: doc.css('.xJEoWe').first&.text&.strip,
        last_updated: updated_element&.next_element&.text&.strip,
        size: size_element&.next_element&.text&.strip,
        users: users_element,
        developer_info: doc.css('.Fm8Cnb').first&.text&.strip.to_s
                       .gsub('&amp;', '&')
      }

    rescue Net::HTTPError => e
      Rails.logger.error "HTTP Error fetching store data: #{e.message}"
      @error = "Extension not found in Chrome Web Store."
    rescue StandardError => e
      Rails.logger.error "Error fetching store data: #{e.message}"
      @error = "Error fetching extension information."
    end
  end

  def download_and_analyze_extension
    download_url = "https://clients2.google.com/service/update2/crx?" +
                  "response=redirect&" +
                  "prodversion=102&" +
                  "acceptformat=crx2,crx3&" +
                  "x=id%3D#{@extension_id}%26installsource%3Dondemand%26uc"

    begin
      Turbo::StreamsChannel.broadcast_update_to(
        "analysis_#{@extension_id}",
        target: "analysis_status",
        partial: "scan/loading_status",
        locals: { message: "Downloading extension..." }
      )

      response = URI.open(download_url)
      crx_data = response.read
      @manifest = extract_manifest(crx_data)

      if @manifest
        Turbo::StreamsChannel.broadcast_update_to(
          "analysis_#{@extension_id}",
          target: "analysis_status",
          partial: "scan/loading_status",
          locals: { message: "Analyzing security..." }
        )

        analyzer = ExtensionSecurityAnalyzer.new(@manifest, @extension_details, @extension_name, @extension_id)
        @security_findings = analyzer.analyze
      end
    rescue OpenURI::HTTPError => e
      @error = "Failed to download extension. Please check the ID and try again."
    rescue StandardError => e
      Rails.logger.error "Error analyzing extension: #{e.message}"
      @error = "An error occurred while analyzing the extension."
    end
  end

  def extract_manifest(crx_data)
    temp_dir = Rails.root.join('tmp', 'extensions')
    FileUtils.mkdir_p(temp_dir)
    zip_path = temp_dir.join("extension_#{@extension_id}.zip")

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
      url_pattern = /((?:https?|ftp|file):\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6})/

      Zip::File.open(zip_path) do |zip_file|
        manifest_entry = zip_file.glob('manifest.json').first
        raise "manifest.json not found in extension" unless manifest_entry
        manifest_content = manifest_entry.get_input_stream.read
        manifest = JSON.parse(manifest_content)

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

        return {
          manifest_version: manifest['manifest_version'],
          name: manifest['name'],
          version: manifest['version'],
          permissions: manifest['permissions'] || [],
          optional_permissions: manifest['optional_permissions'] || [],
          host_permissions: manifest['host_permissions'] || [],
          content_scripts: manifest['content_scripts'],
          embedded_urls: urls.uniq,
          content_security_policy: content_security_policy
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