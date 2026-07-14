// Gitea `web.Router` route registration file.  The ownership-guard
// middleware factory `reqPackageAccess` is colocated here with the
// closure-group registrations; the handlers themselves live in sibling
// packages (`container`, `public`).
package packages

import (
	"example/container"
	"example/public"
)

func reqPackageAccess(accessMode perm.AccessMode) func(ctx *context.Context) {
	return func(ctx *context.Context) {
		if ctx.Package.AccessMode < accessMode && !ctx.IsUserSiteAdmin() {
			ctx.HTTPError(403, "user should have specific package permission")
			return
		}
	}
}

func CommonRoutes() {
	r.Group("/{username}", func() {
		// Guarded: reqPackageAccess ownership check applies to every
		// route registered inside this closure.  `container.GetBlobsUpload`
		// must be lifted authorized cross-file.
		r.Group("/container", func() {
			r.Get("/blobs/{uuid}", container.GetBlobsUpload)
		}, reqPackageAccess(perm.AccessModeRead))

		// Unguarded: no ownership middleware; `public.ListByID` stays
		// unauthorized and MUST still fire missing_ownership_check.
		r.Group("/public", func() {
			r.Get("/list/{id}", public.ListByID)
		})
	})
}
