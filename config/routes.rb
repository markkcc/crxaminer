Rails.application.routes.draw do
  get '/welcome', to: 'welcome#show'
  get '/welcome/analyze', to: 'welcome#analyze'
  get 'stats', to: 'welcome#stats'
  root 'welcome#index'
end
