// Vulnerable counterpart to `safe_local_collection_param_types.rs`
// and `safe_param_type_segment_idents.rs`.  Proves the LocalCollection
// receiver-type override and the Rust `parameter` arm in
// `collect_param_names` don't blanket-suppress real handlers that mix
// in-memory containers with persistent-store calls (`db.update`).
// Scoped identifier (`req.target_user_id`) flows into a real DB
// mutation with no preceding ownership check, must still fire.

use std::collections::HashMap;

struct DocumentRequest {
    target_user_id: u64,
    new_owner: u64,
}

struct DbConnection;
impl DbConnection {
    fn update_owner(&self, _doc_id: u64, _owner: u64) {}
}

// `cache: &mut HashMap<u64, String>` is a local container, its
// mutations are non-auth-relevant.  But `db.update_owner` is a
// real persistent-store write, classified as `DbMutation`, and the
// handler still has no auth check on `req.target_user_id`.
async fn change_owner(req: DocumentRequest, cache: &mut HashMap<u64, String>, db: DbConnection) {
    cache.remove(&req.target_user_id); // local container op, OK
    db.update_owner(req.target_user_id, req.new_owner); // <-- IDOR sink
}
