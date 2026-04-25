// Target: handler in this file delegates ownership checking to a
// helper declared in a sibling file
// (`cross_file_helper_authz.rs`).  The ownership guard lives in
// `require_owner` over there; this handler only calls the guard
// before mutating.
//
// Without cross-file helper lifting the scanner would flag
// `db.update(..)` as `rs.auth.missing_ownership_check` because
// single-file lifting cannot see the helper's body.  With cross-file
// lifting the guard covers `row_id` and the finding disappears.
struct Ctx;
struct Req;
struct Db;
impl Db {
    fn update(&self, _s: &str, _a: &[i64]) {}
}
struct User {
    id: i64,
}

mod auth {
    pub async fn require_auth(
        _r: &super::Req,
        _c: &super::Ctx,
    ) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

pub async fn handle_update_row(
    req: Req,
    ctx: Ctx,
    row_id: i64,
    new_title: String,
) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // Ownership check via the cross-file helper
    // (`cross_file_helper_authz.rs::require_owner`).  After cross-file
    // helper-summary lifting this synthesises an AuthCheck at the
    // call site covering `row_id`, so the downstream mutation is
    // NOT flagged as missing_ownership_check.
    require_owner(&db, row_id, user.id).await?;

    let _ = new_title;
    db.update(
        "UPDATE rows SET title = ?1 WHERE id = ?2",
        &[row_id],
    );
    Ok("ok".into())
}
