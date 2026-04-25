before do
  require_login!
end

get "/projects/:id" do
  Project.find(params[:id])
end
