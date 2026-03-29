before do
  require_login!
end

post "/admin/users/:id/role" do
  AdminRoleService.update!(params[:id], params[:role])
end
