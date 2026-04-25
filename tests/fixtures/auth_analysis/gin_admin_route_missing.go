package authanalysis

func registerAdminRoutes(router *gin.Engine) {
	admin := router.Group("/admin", requireLogin)
	admin.POST("/projects/:projectID/archive", archiveProject)
}

func archiveProject(c *gin.Context) {
	adminAuditService.Publish()
}
