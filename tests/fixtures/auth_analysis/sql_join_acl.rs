// target: authorization is enforced at the SQL layer via a JOIN
// against an ACL table (`group_members`) with a WHERE clause that pins
// the row to the current user (`gm.user_id = ?1` bound to `user.id`).
// Every returned row is membership-gated by construction, so downstream
// uses of the row's columns (`group_id` here) are authorized, the
// `realtime::publish_to_group` call MUST NOT be flagged as missing an
// ownership check after B3.
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

pub async fn handle_list_group_docs(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    let rows = db
        .prepare(
            "SELECT d.id, d.group_id, d.title \
             FROM docs d \
             JOIN group_members gm ON gm.group_id = d.group_id \
             WHERE gm.user_id = ?1 \
             ORDER BY d.updated_at DESC",
        )
        .bind(user.id)
        .all();

    for row in rows {
        let group_id: i64 = row.get("group_id");
        realtime::publish_to_group(group_id, "doc_listed");
    }
    Ok("ok".into())
}
