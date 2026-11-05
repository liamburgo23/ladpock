Rails.application.routes.draw do
  resources :users, only: [:index, :create]
  namespace :api do
    resources :invoices, only: [:show, :destroy] do
      member do
        post :refund
      end
    end
  end
  post "login", to: "sessions#create"
end
