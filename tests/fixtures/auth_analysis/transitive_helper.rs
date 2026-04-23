// target: authorization happens inside `validate_target`, which
// internally calls `authz::require_membership` against the same
// `group_id` the handler subsequently mutates. The current rule cannot
// see this transitively — B4 lifts per-function auth-check summaries
// (which positional params are auth-checked) so the handler-level call
// to `validate_target(&db, group_id, user.id)` is recognised as an
// auth check covering `group_id`. Result: `db.exec(..)` MUST NOT flag
// after B4 lands.
struct Ctx;
struct Req;
struct User {
    id: i64,
}
struct Db;
impl Db {
    fn insert(&self, _s: &str, _a: &[i64]) {}
}
mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}
mod authz {
    pub async fn require_membership(
        _db: &super::Db,
        _group: i64,
        _user: i64,
    ) -> Result<(), ()> {
        Ok(())
    }
}

async fn validate_target(db: &Db, group_id: i64, user_id: i64) -> Result<(), ()> {
    // Helper encapsulates the ownership check.
    authz::require_membership(db, group_id, user_id).await?;
    Ok(())
}

pub async fn handle_create_comment(
    req: Req,
    ctx: Ctx,
    group_id: i64,
    body: String,
) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // Authorization happens inside validate_target — helper-summary
    // lifting propagates the per-param auth check so this covers
    // `group_id`.
    validate_target(&db, group_id, user.id).await?;

    let _ = body;
    db.insert(
        "INSERT INTO comments (group_id, body) VALUES (?1, ?2)",
        &[group_id],
    );
    Ok("ok".into())
}
