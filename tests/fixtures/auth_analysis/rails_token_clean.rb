class InvitationsController < ApplicationController
  def accept
    invitation = Invitation.find_by(token: params[:token])
    if invitation.expires_at > Time.current &&
       invitation.recipient_email == current_user.email
      Membership.create!(
        workspace_id: invitation.workspace_id,
        role: invitation.role,
        email: invitation.recipient_email
      )
    end
  end
end
