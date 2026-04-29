use axum::extract::Path;

struct User {
    id: i64,
}

mod realtime {
    pub fn publish_to_group(_group_id: i64, _msg: &str) {}
}

mod authz {
    pub fn require_group_member(_group: i64, _user: i64) -> Result<(), ()> {
        Ok(())
    }
}

mod auth {
    use super::User;
    pub fn current_user() -> User {
        User { id: 1 }
    }
}

// Negative control: the handler validates ownership via
// `authz::require_group_member(...)?` before the realtime publish.  Phase C
// should NOT emit `rs.auth.missing_ownership_check.taint` here, the
// sanitizer clears `UNAUTHORIZED_ID` from the argument SSA values.
pub async fn handle_publish_checked(Path(group_id): Path<i64>) -> Result<&'static str, ()> {
    let user = auth::current_user();
    authz::require_group_member(group_id, user.id)?;
    realtime::publish_to_group(group_id, "doc_updated");
    Ok("ok")
}
