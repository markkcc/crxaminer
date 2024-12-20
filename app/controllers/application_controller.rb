class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  rescue_from StandardError, with: :handle_error
  rescue_from ActiveRecord::RecordNotFound, with: :handle_not_found
  rescue_from ActionController::RoutingError, with: :handle_not_found

def handle_not_found
    respond_to do |format|
      format.html do
        @error = "Page Not Found (404)"
        render "scan/error", status: :not_found
      end
      format.json do
        render json: { error: "Not Found" }, status: :not_found
      end
    end
  end

  def handle_error(exception)
    error_message = Rails.env.development? ? exception.message : "An unexpected error occurred"
    
    respond_to do |format|
      format.html do
        @error = error_message
        render "scan/error", status: :internal_server_error
      end
      format.json do
        render json: { error: error_message }, status: :internal_server_error
      end
    end
  end
end
