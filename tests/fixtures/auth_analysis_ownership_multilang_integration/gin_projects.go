package authintegration

func registerProjectRoutes(router *gin.Engine) {
	router.GET("/projects/:projectID", requireLogin, showProject)
}

func showProject(c *gin.Context) {
	projectService.Find(c.Param("projectID"))
}
