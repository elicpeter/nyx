package authanalysis

func acceptInvitation(c echo.Context) error {
	invitation := invitationService.FindByToken(c.QueryParam("token"))
	if invitation.ExpiresAt != nil {
		return membershipService.Accept(invitation.WorkspaceID)
	}
	return nil
}
