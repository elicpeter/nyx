class ProjectsController < ApplicationController
  def archive
    ids = params[:ids]
    require_membership!(ids[0], current_user)
    ProjectArchive.archive(ids)
  end
end
