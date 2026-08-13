// Guarded handler: registered under the reqPackageAccess ownership group
// in routers/api.go.  The id-scoped DAO read must NOT fire
// missing_ownership_check — the cross-file caller-scope lift authorizes
// this unit.
package container

func GetBlobsUpload(ctx *context.Context) {
	uuid := ctx.PathParam("uuid")
	upload, _ := packages_model.GetBlobUploadByID(ctx, uuid)
	_ = upload
}
