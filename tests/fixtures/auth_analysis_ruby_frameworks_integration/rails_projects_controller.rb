class ProjectsController < ApplicationController
  def update
    project = Project.find(params[:id])
    project.update!(state: params[:state])
  end

  def archive
    ids = params[:ids]
    require_membership!(ids[0], current_user)
    ProjectArchive.archive(ids)
  end
end
