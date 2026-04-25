struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn exec(&self, _s: &str, _a: &[i64]) {} }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }
mod realtime { pub fn publish_to_group(_g: i64, _m: &str) {} }

pub async fn handle_delete_any_doc(req: Req, ctx: Ctx, doc_id: i64, group_id: i64) -> Result<String, ()> {
    let _user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // BUG: no ownership/membership check on group_id or doc_id.
    // User might not be a member of `group_id` and might not own `doc_id`.
    db.exec("DELETE FROM docs WHERE id = ?1", &[doc_id]);
    realtime::publish_to_group(group_id, "doc_deleted");
    Ok("ok".into())
}
