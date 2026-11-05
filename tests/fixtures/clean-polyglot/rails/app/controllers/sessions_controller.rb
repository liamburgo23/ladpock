class SessionsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:create]
  rate_limit to: 5, within: 1.minute, only: :create

  def create
    user = User.find_by(email: session_params[:email])
    head user&.authenticate(session_params[:password]) ? :ok : :unauthorized
  end

  private

  def session_params
    params.permit(:email, :password)
  end
end
