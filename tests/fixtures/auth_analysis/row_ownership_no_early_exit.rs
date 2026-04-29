struct Ctx;
struct Req;
struct User {
    id: i64,
}
struct Db;
impl Db {
    fn query_one(&self, _s: &str, _a: &[i64]) -> Row {
        Row
    }
    fn exec(&self, _s: &str, _a: &[i64]) {}
}
struct Row;
impl Row {
    fn get_i64(&self, _c: &str) -> i64 {
        0
    }
}
mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

pub async fn handle_update_doc(req: Req, ctx: Ctx, doc_id: i64) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;
    let existing = db.query_one(
        "SELECT user_id, group_id FROM docs WHERE id = ?1",
        &[doc_id],
    );
    let owner_id = existing.get_i64("user_id");

    // Equality compared but no early exit, the check has no effect.
    if owner_id != user.id {
        // missing return
        println!("not your doc (but proceeding anyway)");
    }

    db.exec("UPDATE docs SET updated = 1 WHERE id = ?1", &[doc_id]);
    Ok("ok".into())
}
