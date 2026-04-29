// Phase 6 D05: an Axum `Json<UpdateDoc>` extractor whose `doc_id`
// field is declared as `i64`.  The DTO field-level taint analysis
// proves the value reaching `db.exec` is numeric and exempts
// `dto.doc_id` from the auth subject classifier — the rule must NOT
// fire because numeric DTO fields cannot bypass ownership.
use axum::extract::Json;

#[derive(serde::Deserialize)]
pub struct UpdateDoc {
    pub doc_id: i64,
    pub email: String,
}

struct Ctx;
struct Req;
struct User { id: i64 }
struct Db;
impl Db {
    fn query_one(&self, _s: &str, _a: &[i64]) -> Row { Row }
    fn exec(&self, _s: &str, _a: &[i64]) {}
}
struct Row;
impl Row {
    fn get_i64(&self, _c: &str) -> i64 { 0 }
}
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
    let _existing = db.query_one(
        "SELECT user_id FROM docs WHERE id = ?1",
        &[dto.doc_id],
    );
    db.exec("UPDATE docs SET updated = 1 WHERE id = ?1", &[dto.doc_id]);
    Ok("ok".into())
}
