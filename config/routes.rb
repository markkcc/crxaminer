Rails.application.routes.draw do
  root 'scan#index'

  resources :scan, only: [:index, :show] do
    collection do
      get :analyze
      get :stats
    end
  end

  get "help", to: "help#show", as: :help

  match "*path", to: "application#handle_not_found", via: :all, constraints: ->(req) { !req.path.start_with?('/assets') }
end
