before do
  require_login!
end

post "/admin/projects/archive" do
  AdminAuditService.publish!
end
