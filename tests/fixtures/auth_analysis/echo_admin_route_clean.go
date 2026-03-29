package authanalysis

func registerEchoAdmin(e *echo.Echo) {
	admin := e.Group("/admin", requireLogin)
	admin.Use(requireAdmin)
	admin.POST("/reports/publish", publishReport)
}

func publishReport(c echo.Context) error {
	return reportService.Publish()
}
