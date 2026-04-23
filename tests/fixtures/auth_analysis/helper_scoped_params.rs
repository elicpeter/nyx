use std::collections::HashSet;

// Library-style helper. Authorization is the caller's responsibility.
// The `result.insert` / `result.contains` calls below are pure
// in-memory work on a locally-constructed HashSet and must not be
// flagged as authorization-relevant Read/Mutation operations.
// Helper-summary lifting covers cross-procedural scoped-id flows
// separately; the DB layer is intentionally excluded here.
pub async fn get_peer_ids(user_id: i64, other_ids: &[i64]) -> HashSet<i64> {
    let mut result: HashSet<i64> = HashSet::new();
    for &other_id in other_ids {
        if !result.contains(&other_id) {
            result.insert(other_id);
        }
    }
    let _ = user_id;
    result
}
