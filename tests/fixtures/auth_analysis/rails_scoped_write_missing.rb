class ProjectsController < ApplicationController
  before_action :require_login

  def update
    project = Project.find(params[:id])
    project.update!(state: params[:state])
  end
end
