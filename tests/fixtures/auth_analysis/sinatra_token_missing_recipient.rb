before do
  require_login!
end

post "/invitations/accept" do
  invitation = Invitation.find_by(token: params[:token])
  halt 403 if invitation.expires_at < Time.now
  Membership.create!(
    email: params[:email] || invitation.email,
    workspace_id: invitation.workspace_id
  )
end
