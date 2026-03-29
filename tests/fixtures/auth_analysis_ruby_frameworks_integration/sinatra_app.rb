before do
  require_login!
end

post "/workspaces/current/role" do
  WorkspaceGrant.update!(session[:workspace_id], params[:role])
end
