class ScanController < ApplicationController
  def show
    @extension_id = params[:id]
    
    unless valid_extension_id?(@extension_id)
      if request.xhr?
        render json: { error: "Invalid extension ID format" }, status: :unprocessable_entity
      else
        flash[:error] = "Invalid extension ID format"
        redirect_to root_path
      end
      return
    end

    if request.xhr?
      @cached_results = Rails.cache.read("extension_#{@extension_id}")
      
      if @cached_results
        @manifest = @cached_results[:manifest]
        @extension_name = @cached_results[:extension_name]
        @extension_image = @cached_results[:extension_image]
        @extension_details = @cached_results[:extension_details]
        @security_findings = @cached_results[:security_findings]
        render partial: 'results'
      else
        render json: { error: "Analysis results not found" }, status: :not_found
      end
    else
      render :show
    end
  end

  def analyze
    @extension_id = params[:id]&.strip

    unless valid_extension_id?(@extension_id)
      render json: { error: "Invalid extension ID format" }, status: :unprocessable_entity
      return
    end

    analyzer = ExtensionAnalyzer.new(@extension_id)
    result = analyzer.perform

    if result.error?
      render json: { error: result.error }, status: :unprocessable_entity
    else
      Rails.cache.write("extension_#{@extension_id}", {
        extension_details: result.extension_details,
        extension_name: result.extension_name,
        extension_image: result.extension_image,
        manifest: result.manifest,
        security_findings: result.security_findings
      }, expires_in: 1.hour)

      render json: {
        extension_details: result.extension_details,
        extension_name: result.extension_name,
        extension_image: result.extension_image,
        manifest: result.manifest,
        security_findings: result.security_findings
      }
    end
  end

  def stats
    render :stats
  end

  private

  def valid_extension_id?(id)
    id.present? && id.match?(/\A[a-zA-Z0-9]{32}\z/)
  end
end 