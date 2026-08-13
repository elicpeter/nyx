// Unguarded handler: registered under a bare closure group (no
// ownership middleware) in routers/api.go.  The id-scoped DAO read MUST
// still fire missing_ownership_check — recall guard proving the
// cross-file lift does not over-suppress.
package public

func ListByID(ctx *context.Context) {
	id := ctx.PathParam("id")
	items, _ := packages_model.FindByOwnerID(ctx, id)
	_ = items
}
