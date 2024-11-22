Rails.application.routes.draw do
  get '/welcome', to: 'welcome#show'
  get '/welcome/analyze', to: 'welcome#analyze'
  root 'welcome#index'
end
