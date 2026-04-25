class ProjectsController < ApplicationController
  before_action :require_login

  def show
    require_membership!(params[:id], current_user)
    Project.find(params[:id])
  end
end
