// Negative counterpart for the row-population reverse-walk.
//
// Same fetch-then-mutate shape as `safe_row_population_reverse_walk.rs`
// but **no auth check** is performed on the fetched row.  The
// reverse-walk is purely structural: when no check covers `community`,
// the downstream mutation by `req.community_id` must still flag.
// Guards against the fix over-suppressing the unsafe shape.

use std::result::Result;

pub struct TransferCommunity {
    pub community_id: i64,
}
pub struct Pool;
pub struct Community {
    pub id: i64,
}
pub struct CommunityActions;

impl Community {
    pub fn read(_pool: &mut Pool, _id: i64) -> Result<Community, ()> {
        unimplemented!()
    }
}

impl CommunityActions {
    pub fn delete_mods_for_community(_pool: &mut Pool, _id: i64) -> Result<(), ()> {
        Ok(())
    }
}

pub async fn transfer_community(
    req: TransferCommunity,
    pool: &mut Pool,
) -> Result<(), ()> {
    // Row fetch, populates `community → [req.community_id]`, but
    // no `check_*_action(&user, &community, ..)` follows.
    let _community = Community::read(pool, req.community_id)?;

    // Mutation by id with no preceding ownership/membership check.
    // This is the genuine IDOR, must flag.
    CommunityActions::delete_mods_for_community(pool, req.community_id)?;

    Ok(())
}
