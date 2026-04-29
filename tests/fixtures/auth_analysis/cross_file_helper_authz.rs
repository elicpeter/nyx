// Target: authorization happens inside `require_owner`, which
// delegates to `require_group_member` (a configured authorization
// check name).  The handler in `cross_file_helper_handler.rs`
// delegates ownership validation to this helper, cross-file helper
// lifting should recognise the call as an auth check covering the
// supplied `row`.
struct Db;
impl Db {
    fn get(&self, _id: i64) -> i64 {
        0
    }
}

mod authz {
    pub async fn require_group_member(
        _db: &super::Db,
        _row_id: i64,
        _user_id: i64,
    ) -> Result<(), ()> {
        Ok(())
    }
}

/// Ownership / group-membership guard.  Delegates to the configured
/// authorization check `require_group_member`, passing `row_id` as
/// the resource id and `user_id` as the actor id.  The single-file
/// extractor produces an `AuthCheckSummary` with param 1 (`row_id`)
/// marked as `Membership`-checked.
pub async fn require_owner(db: &Db, row_id: i64, user_id: i64) -> Result<(), ()> {
    authz::require_group_member(db, row_id, user_id).await?;
    let _ = db.get(row_id);
    Ok(())
}
