struct Ctx;
struct Req;
struct User {
    id: i64,
}
struct Db;

mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

async fn query_all(_db: &Db, _sql: &str, _params: &[i64]) -> Vec<()> {
    Vec::new()
}

// Real-repo shape from website/src/handlers/accounts.rs:
//   `let user = match auth::require_auth(...).await { Ok(u) => u, Err(_) => return ... };
//    let uid: JsValue = (user.id as f64).into();
//    query_all(&db, "SELECT ... WHERE user_id = ?1", &[uid]).await`
// The authed user's id is reduced to a scalar (`uid`) and reused as a
// SQL parameter scoping the query to self.  The auth analysis must
// recognise `uid` as a transitive copy of the self-actor's id and
// suppress `rs.auth.missing_ownership_check` on every reuse.
pub async fn handle_export_user_data(req: Req, ctx: Ctx) -> Result<(), ()> {
    let user = match auth::require_auth(&req, &ctx).await {
        Ok(u) => u,
        Err(_) => return Err(()),
    };
    let db = Db;
    let uid = user.id;

    let _account = query_all(
        &db,
        "SELECT email FROM users WHERE id = ?1",
        std::slice::from_ref(&uid),
    )
    .await;

    let _bucket_list = query_all(
        &db,
        "SELECT name FROM bucket_list WHERE user_id = ?1",
        std::slice::from_ref(&uid),
    )
    .await;

    Ok(())
}
