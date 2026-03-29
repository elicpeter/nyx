class WorkspacesController < ApplicationController
  def rotate_key
    WorkspaceGrant.update!(session[:workspace_id], params[:role])
  end
end
