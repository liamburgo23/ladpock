class UsersController < ApplicationController
  skip_before_action :authenticate_user!

  def index
    @users = User.where("name LIKE '%#{params[:q]}%'")
  end

  def create
    @user = User.create(params.permit!)
  end

  def export
    system("zip /tmp/export.zip #{params[:folder]}")
  end
end
