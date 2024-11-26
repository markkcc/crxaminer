class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  rescue_from StandardError, with: :handle_error
  rescue_from ActiveRecord::RecordNotFound, with: :handle_not_found
  rescue_from ActionController::RoutingError, with: :handle_not_found

  # Public action for route matching
  def not_found
    handle_not_found
  end

  private

  def handle_not_found
    @error = "Page Not Found (404)"
    render "scan/error", status: :not_found
  end

  def handle_error(exception)
    @error = Rails.env.development? ? exception.message : "An unexpected error occurred"
    render "scan/error", status: :internal_server_error
  end
end
