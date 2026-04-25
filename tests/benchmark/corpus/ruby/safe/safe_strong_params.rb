class UsersController < ApplicationController
  def update
    user = User.find(params[:id].to_i)
    user.update(user_params)
    redirect_to user
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end
