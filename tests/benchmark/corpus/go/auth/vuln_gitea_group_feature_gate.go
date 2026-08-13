// Recall guard for the gitea `web.Router` closure-group extractor.
// The trailing middleware `reqStarsEnabled()` is a FEATURE gate, not an
// ownership guard: its factory closure reads a global config field
// (`setting.Repository.DisableStars`), NOT a request-context permission
// field.  The body-based recogniser must therefore treat it as
// non-authorization, so the id-scoped DAO read in `GetPackage` must
// STILL fire `go.auth.missing_ownership_check`.
//
// Distilled from routers/api/v1/api.go `reqStarsEnabled` — proves the
// recogniser discriminates authority (`ctx.*` permission fields) from
// feature flags and does not over-suppress.
package packages

func reqStarsEnabled() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if setting.Repository.DisableStars {
			ctx.APIError(403, "stars are disabled by the administrator")
			return
		}
	}
}

func Routes() {
	r.Group("/{username}", func() {
		r.Group("/packages", func() {
			r.Get("/{id}", GetPackage)
		}, reqStarsEnabled())
	})
}

func GetPackage(ctx *context.APIContext) {
	id := ctx.PathParam("id")
	pkg, _ := packages_model.GetPackageByID(ctx, id)
	_ = pkg
}
