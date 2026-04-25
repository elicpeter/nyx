class SessionsController < ApplicationController
  def login
    url = params[:redirect_url]
    redirect_to url
  end

  def safe_login
    redirect_to root_path
  end
end
