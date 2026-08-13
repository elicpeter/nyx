// Gitea `web.Router` closure-nested route group whose trailing
// middleware `reqRepoReader(...)` is an ownership guard: its factory
// closure reads the request-context permission field
// `ctx.Repo.Permission.CanRead(...)` (plus `ctx.IsUserRepoAdmin()` /
// `ctx.IsUserSiteAdmin()`) and rejects with `ctx.APIError`.  The gitea
// extractor lifts the guard onto every handler registered lexically
// inside the closure, so the id-scoped DAO read in `GetPackage` must
// NOT fire `go.auth.missing_ownership_check`.
//
// Distilled from routers/api/packages/api.go (`r.Group(path, func(){…},
// reqPackageAccess(perm.AccessModeRead))`) + routers/api/v1/api.go
// (`reqRepoReader`).
package packages

func reqRepoReader(unitType unit.Type) func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.Repo.Permission.CanRead(unitType) && !ctx.IsUserRepoAdmin() && !ctx.IsUserSiteAdmin() {
			ctx.APIError(403, "user should have specific read permission or be an admin")
			return
		}
	}
}

func Routes() {
	r.Group("/{username}", func() {
		r.Group("/packages", func() {
			r.Get("/{id}", GetPackage)
		}, reqRepoReader(unit.TypePackages))
	})
}

func GetPackage(ctx *context.APIContext) {
	id := ctx.PathParam("id")
	pkg, _ := packages_model.GetPackageByID(ctx, id)
	_ = pkg
}
