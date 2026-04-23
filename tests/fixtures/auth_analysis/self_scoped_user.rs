use std::collections::HashSet;

struct Ctx; struct Req; struct User { id: i64 } struct Db;
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }

// Phase A3 target: the handler's `get_peer_ids(&db, user.id)` call below
// must not be flagged. `user` is bound from `auth::require_auth(..)` so
// `user.id` is the caller's own id — the call is self-referential, not a
// foreign scoped id. The library-style helper below is a pass-through so
// its body contains no DB sinks (the internal `user_id` → DB flow is the
// separate P4 pattern, punted to Phase B4).
async fn get_peer_ids(_db: &Db, _user_id: i64) -> HashSet<i64> {
    HashSet::new()
}

pub async fn handle_list_peers(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;
    let peers = get_peer_ids(&db, user.id).await;
    Ok(format!("{}", peers.len()))
}
