before do
  require_admin!
end

post "/admin/users/:id/role" do
  AdminRoleService.update!(params[:id], params[:role])
end
