class InvitationsController < ApplicationController
  def accept
    invitation = Invitation.find_by(token: params[:token])
    if invitation.recipient_email == current_user.email
      Membership.create!(
        workspace_id: invitation.workspace_id,
        role: params[:role] || invitation.role
      )
    end
  end
end
