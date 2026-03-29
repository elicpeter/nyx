package authanalysis

func registerProjectRoutes(router *gin.Engine) {
	router.PUT("/projects/:projectID", updateProject)
}

func updateProject(c *gin.Context) {
	projectID := c.Param("projectID")
	requireOwnership(projectID, c.MustGet("userID"))
	projectStore.Update(projectID, c.PostForm("name"))
}
