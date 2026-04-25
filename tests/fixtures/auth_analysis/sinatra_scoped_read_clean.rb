before do
  require_login!
end

get "/projects/:id" do
  require_membership!(params[:id], current_user)
  Project.find(params[:id])
end
