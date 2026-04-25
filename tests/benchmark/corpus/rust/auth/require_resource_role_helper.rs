struct Ctx;
struct Req;
struct User {
    id: i64,
}
struct Db;
struct Env;

mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

mod authz {
    pub async fn require_trip_member(
        _db: &super::Db,
        _trip_id: f64,
        _user_id: i64,
    ) -> Result<(), ()> {
        Ok(())
    }
}

mod realtime {
    pub async fn publish_to_trip(_env: &super::Env, _trip_id: i64, _topic: &str) -> Result<(), ()> {
        Ok(())
    }
}

// Real-repo shape from website/src/handlers/activities.rs.  Project
// helpers like `require_trip_member` / `require_doc_owner` /
// `require_workspace_admin` are project-specific and not enumerable in
// nyx's static defaults.  The structural recogniser
// `require_<resource>_<role>` (where `<role>` is a closed-vocabulary
// auth noun: member, owner, admin, access, permission, manager,
// editor, viewer) lifts them as authorization checks regardless of
// the resource segment.
pub async fn handle_create_activity(req: Req, ctx: Ctx) -> Result<(), ()> {
    let user = match auth::require_auth(&req, &ctx).await {
        Ok(u) => u,
        Err(_) => return Err(()),
    };
    let db = Db;
    let env = Env;
    let trip_id: f64 = 42.0;

    if let Err(_) = authz::require_trip_member(&db, trip_id, user.id).await {
        return Err(());
    }

    realtime::publish_to_trip(&env, trip_id as i64, "activities.created")
        .await
        .ok();

    Ok(())
}
