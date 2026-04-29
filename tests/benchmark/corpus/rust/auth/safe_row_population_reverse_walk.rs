// Real-repo regression (lemmy `community/transfer.rs`,
// `comment/distinguish.rs`).
//
// `let community = Community::read(pool, req.community_id)` records
// `community → [req.community_id]` in `row_population_data`.  An auth
// check `check_community_user_action(&user, &community, ..)` then
// authorises the row, and any **downstream** operation that re-uses
// `req.community_id` (a later mutation by the same id, or a related
// view fetched by the same id) is materially covered by that check.
//
// Before the row-population reverse-walk, only the row-fetch site
// itself was exempted.  Lemmy-style handlers commonly re-use the
// original request id after the check (delete-by-id, fetch-related-
// view) and those re-uses fired `rs.auth.missing_ownership_check`
// despite the textual auth check on the fetched row.

use std::result::Result;

pub struct TransferCommunity {
    pub community_id: i64,
    pub person_id: i64,
}
pub struct LocalUserView {
    pub person: Person,
    pub local_user: LocalUser,
}
pub struct Person {
    pub id: i64,
}
pub struct LocalUser;
pub struct Pool;
pub struct Community {
    pub id: i64,
}
pub struct CommunityActions;
pub struct CommunityView;

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

impl CommunityView {
    pub fn read(
        _pool: &mut Pool,
        _id: i64,
        _u: Option<&LocalUser>,
        _b: bool,
    ) -> Result<CommunityView, ()> {
        unimplemented!()
    }
}

pub fn check_community_user_action(
    _uv: &LocalUserView,
    _c: &Community,
    _p: &mut Pool,
) -> Result<(), ()> {
    Ok(())
}

pub async fn transfer_community(
    req: TransferCommunity,
    pool: &mut Pool,
    local_user_view: LocalUserView,
) -> Result<(), ()> {
    // Row fetch, `community` is populated from `req.community_id`.
    let community = Community::read(pool, req.community_id)?;

    // Authorisation check on the fetched row.  Subject = `community`
    // (chain root match in `auth_check_covers_subject`).
    check_community_user_action(&local_user_view, &community, pool)?;

    // Downstream mutation re-using the original request field.  The
    // engine's row-population reverse-walk treats `req.community_id`
    // as covered by the check above (the check authorised access to
    // the row that was fetched with this id).
    CommunityActions::delete_mods_for_community(pool, req.community_id)?;

    // Local alias of the same request field, `var_alias_chain`
    // records `community_id → "req.community_id"` so the reverse-walk
    // also covers downstream sinks that pass the bare alias.  Before
    // the alias-chain fix, the next read fired
    // `rs.auth.missing_ownership_check` despite the textual auth
    // check on `community` above.
    let community_id = req.community_id;
    let _community_view = CommunityView::read(
        pool,
        community_id,
        Some(&local_user_view.local_user),
        false,
    )?;

    Ok(())
}
