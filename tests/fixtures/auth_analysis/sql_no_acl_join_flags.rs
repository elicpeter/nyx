// B3 regression guard: the SELECT JOINs through `audit_log` (NOT in
// the configured ACL list) and the WHERE clause pins on
// `al.user_id = ?1`. The audit-log row's user is the audit subject,
// not the doc owner — so this query does NOT prove caller ownership
// of the returned `doc_id`. The downstream realtime publish MUST
// still flag for a missing ownership check after B3.
struct Ctx;
struct Req;
struct User {
    id: i64,
}
struct Db;
impl Db {
    fn prepare(&self, _s: &str) -> Query {
        Query
    }
}
struct Query;
impl Query {
    fn bind(&self, _v: i64) -> Self {
        Query
    }
    fn all(&self) -> Vec<Row> {
        vec![]
    }
}
struct Row;
impl Row {
    fn get(&self, _c: &str) -> i64 {
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

pub async fn handle_audit_view(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    let rows = db
        .prepare(
            "SELECT d.id, d.group_id \
             FROM docs d \
             JOIN audit_log al ON al.doc_id = d.id \
             WHERE al.user_id = ?1",
        )
        .bind(user.id)
        .all();

    for row in rows {
        let group_id: i64 = row.get("group_id");
        realtime::publish_to_group(group_id, "audited");
    }
    Ok("ok".into())
}
