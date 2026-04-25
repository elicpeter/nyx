package authanalysis

func registerBulkRoutes(e *echo.Echo) {
	e.POST("/projects/bulk-archive", bulkArchiveProjects, requireLogin)
}

func bulkArchiveProjects(c echo.Context) error {
	projectIDs := []string{"p1", "p2"}
	requireMembership(projectIDs[0], c.Get("userID"))
	return projectService.Delete(projectIDs)
}
