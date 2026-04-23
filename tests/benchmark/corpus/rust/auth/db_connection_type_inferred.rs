// Regression fixture: `let conn = rusqlite::Connection::open(..).unwrap();`
// produces a `DatabaseConnection` via SSA `constructor_type` (through
// `peel_identity_suffix`, which strips `.unwrap()` before matching).  The
// handler then calls `conn.execute(..)`, a callee name that appears in
// neither `mutation_indicator_names` nor `read_indicator_names` for Rust —
// name-based classification returns `None`, so the ownership gate
// already cannot flag the call.  The type-map refinement should *still*
// leave the call unflagged (the type map produces `DbMutation`, but
// there is no scoped subject on the operation, so the ownership check
// does not fire either way).  This fixture is therefore a
// non-regression witness: adding SSA-type classification must not
// introduce a false positive.

struct Ctx;
struct Req;
struct User {
    id: i64,
}

mod rusqlite {
    pub struct Connection;
    impl Connection {
        pub fn open(_path: &str) -> Result<Self, ()> {
            Ok(Connection)
        }
        pub fn execute(&self, _sql: &str, _params: &[i64]) -> Result<(), ()> {
            Ok(())
        }
    }
}

mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

pub async fn handle_log_event(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    // `conn` is DatabaseConnection-typed via SSA.  No scoped foreign id
    // flows into `execute`, so the ownership gate has nothing to flag.
    let conn = rusqlite::Connection::open("app.db").unwrap();
    let _ = conn.execute("INSERT INTO audit (actor) VALUES (?1)", &[user.id]);
    Ok("ok".into())
}
