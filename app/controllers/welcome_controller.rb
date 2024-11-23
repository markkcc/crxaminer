require 'net/http'
require 'nokogiri'
require 'zip'
require 'json'
require 'uri'
require 'cgi'
require 'open-uri'

class WelcomeController < ApplicationController
  def show
    @extension_id = params[:id]
  end

  def analyze
    @extension_id = params[:id]&.strip

    # Validate extension ID format
    unless @extension_id =~ /^[a-zA-Z0-9]{32}$/
      flash[:error] = "Invalid extension ID: Must be 32 alphanumeric characters long."
      render :index, layout: false
      return
    end

    # Fetch Chrome store data
    fetch_chrome_store_data
    
    # Download and analyze extension
    download_and_analyze_extension

    if @error
      flash[:error] = @error
      render :index
    else
      render :show, layout: false
    end
  end

  private

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
        Rails.logger.info "Original redirect URL: #{redirect_location}"
        
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
        
        Rails.logger.info "Encoded redirect URL: #{redirect_location}"
        
        redirect_uri = URI.parse(redirect_location)
        Rails.logger.info "Parsed redirect URI: #{redirect_uri.inspect}"
        
        http = Net::HTTP.new(redirect_uri.host, redirect_uri.port)
        http.use_ssl = true
        request = Net::HTTP::Get.new(redirect_uri.path)
        request['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        response = http.request(request)
      end
      
      # Ensure proper encoding when parsing HTML
      doc = Nokogiri::HTML(response.body.force_encoding('UTF-8'))
      raw_extension_name = doc.css('h1').first&.text&.strip.to_s
      Rails.logger.info "Raw extension name: #{raw_extension_name}"
      
      @extension_name = raw_extension_name
                        .gsub('&mdash;', '—')
                        .gsub('&ndash;', '-')
                        .gsub('&reg;', '®')
                        .gsub('&trade;', '™')
                        .gsub('&copy;', '©')
                        .gsub('&amp;', '&')
      
      Rails.logger.info "Processed extension name: #{@extension_name}"
      
      @extension_image = doc.css('.rBxtY').first&.attr('src')
      
      # Find elements by their text content
      size_element = doc.css('.nws2nb').find { |el| el.text.strip == "Size" }
      updated_element = doc.css('.nws2nb').find { |el| el.text.strip == "Updated" }
      
      @extension_details = {
        author: doc.css('.cJI8ee').first&.text&.strip.to_s
                .gsub('&amp;', '&'),
        rating: doc.css('.Vq0ZA').first&.text&.strip,
        rating_count: doc.css('.xJEoWe').first&.text&.strip,
        last_updated: updated_element&.next_element&.text&.strip,
        size: size_element&.next_element&.text&.strip,
        developer_info: doc.css('.Fm8Cnb').first&.text&.strip.to_s
                       .gsub('&amp;', '&')
      }
      
      Rails.logger.info "Fetched details: #{@extension_details.inspect}"
      
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
        partial: "welcome/loading_status",
        locals: { message: "Downloading extension..." }
      )

      response = URI.open(download_url)
      crx_data = response.read
      @manifest = extract_manifest(crx_data)
      
      if @manifest
        Turbo::StreamsChannel.broadcast_update_to(
          "analysis_#{@extension_id}",
          target: "analysis_status",
          partial: "welcome/loading_status",
          locals: { message: "Analyzing security..." }
        )

        analysis_service = ExtensionAnalysisService.new(@manifest)
        @security_findings = analysis_service.analyze
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
      Zip::File.open(zip_path) do |zip_file|
        manifest_entry = zip_file.glob('manifest.json').first
        raise "manifest.json not found in extension" unless manifest_entry

        manifest_content = manifest_entry.get_input_stream.read
        manifest = JSON.parse(manifest_content)
        
        return {
          manifest_version: manifest['manifest_version'],
          name: manifest['name'],
          version: manifest['version'],
          permissions: manifest['permissions'] || [],
          optional_permissions: manifest['optional_permissions'] || [],
          host_permissions: manifest['host_permissions'] || [],
          content_scripts: manifest['content_scripts']
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
