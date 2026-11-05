class UsersController < ApplicationController
  before_action :authenticate_user!

  def index
    @users = User.where("name LIKE ?", "%#{User.sanitize_sql_like(params[:q].to_s)}%")
  end

  def create
    @user = current_user.team.users.create(user_params)
  end

  def export
    system("zip", "/tmp/export.zip", "--", safe_folder)
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end
