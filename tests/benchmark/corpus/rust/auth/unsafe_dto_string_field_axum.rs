// Phase 6 D06 (negative): same DTO shape as
// `safe_dto_int_field_axum.rs` but the flow uses the `doc_id` field
// whose declared type is `String`.  Phase 6 must NOT exempt the
// member-access subject — String DTO fields can carry an injection
// payload, so the auth rule must continue to fire.
use axum::extract::Json;

#[derive(serde::Deserialize)]
pub struct UpdateDoc {
    pub doc_id: String,
    pub email: String,
}

struct Ctx;
struct Req;
struct User { id: i64 }
struct Db;
impl Db {
    fn query_one(&self, _s: &str, _a: &[&str]) -> Row { Row }
    fn exec(&self, _s: &str, _a: &[&str]) {}
}
struct Row;
mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

pub async fn handle_update_doc(
    req: Req,
    ctx: Ctx,
    Json(dto): Json<UpdateDoc>,
) -> Result<String, ()> {
    let _user = auth::require_auth(&req, &ctx).await?;
    let db = Db;
    let doc_id = dto.doc_id.as_str();
    let _existing = db.query_one(
        "SELECT user_id FROM docs WHERE id = ?1",
        &[doc_id],
    );
    db.exec("UPDATE docs SET updated = 1 WHERE id = ?1", &[doc_id]);
    Ok("ok".into())
}
