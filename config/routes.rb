Rails.application.routes.draw do
  root 'scan#index'

  resources :scan, only: [:index, :show] do
    collection do
      get :analyze
      get :stats
    end
  end

  match "*path", to: "application#not_found", via: :all
end
