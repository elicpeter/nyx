package authanalysis

func reopenProject(c *gin.Context) {
	session := sessionState{}
	projectStore.Update(session.CurrentWorkspaceID, c.Param("projectID"))
}
