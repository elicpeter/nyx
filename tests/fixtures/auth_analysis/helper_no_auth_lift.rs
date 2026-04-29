// B4 regression guard: `format_target` does NOT auth-check
// `group_id`, it just constructs a string from it. The helper-lift
// pass must not synthesise a covering AuthCheck on the handler's call
// site, so the subsequent `db.exec("INSERT INTO comments …", &[group_id])`
// MUST still flag.
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

fn format_target(group_id: i64, suffix: &str) -> String {
    // No auth check here, pure formatting.
    format!("group:{}{}", group_id, suffix)
}

pub async fn handle_post_comment(
    req: Req,
    ctx: Ctx,
    group_id: i64,
    body: String,
) -> Result<String, ()> {
    let _user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // No auth check on `group_id` anywhere in this file.
    let _label = format_target(group_id, "/x");
    let _ = body;
    db.insert(
        "INSERT INTO comments (group_id, body) VALUES (?1, ?2)",
        &[group_id],
    );
    Ok("ok".into())
}
