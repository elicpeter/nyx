class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name = '#{name}'")
  end

  def safe_search
    name = params[:name]
    @users = User.where("name = ?", name)
  end
end
