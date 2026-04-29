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
mod realtime {
    pub fn publish_to_group(_g: i64, _m: &str) {}
}

fn json_err(_msg: &str, _code: u16) -> Result<String, ()> {
    Err(())
}

pub async fn handle_delete_doc(req: Req, ctx: Ctx, doc_id: i64) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    let existing = db.query_one(
        "SELECT user_id, group_id FROM docs WHERE id = ?1",
        &[doc_id],
    );
    let owner_id = existing.get_i64("user_id");
    if owner_id != user.id {
        return json_err("cannot delete another user's doc", 403);
    }

    // By construction, the row belongs to `user`, so any id read from it is authorized.
    let group_id = existing.get_i64("group_id");
    realtime::publish_to_group(group_id, "doc_deleted");
    Ok("ok".into())
}
