// Phase A4: row-level "fetch-then-authorize" idiom.  The handler fetches
// the row by id first to obtain the resource it needs to authorize, then
// calls a named authorization function on the fetched row.  This is the
// canonical pattern in Lemmy's Actix handlers (and most row-level Rails /
// Django authz code) — the authorization check appears textually after the
// fetch but is the first thing the function does on the row.

use std::result::Result;

pub struct DistinguishComment { pub comment_id: i64 }
pub struct LocalUserView { pub person: Person, pub local_user: LocalUser }
pub struct Person { pub id: i64, pub instance_id: i64 }
pub struct LocalUser;
pub struct Pool;
pub struct CommentView { pub community: Community, pub creator: Creator }
pub struct Community;
pub struct Creator { pub id: i64 }
pub struct Comment;
pub struct CommentResponse;

impl CommentView {
    pub fn read(_pool: &mut Pool, _id: i64, _u: Option<&LocalUser>, _i: i64) -> Result<CommentView, ()> {
        unimplemented!()
    }
}

impl Comment {
    pub fn update(_pool: &mut Pool, _id: i64, _form: &()) -> Result<Comment, ()> { unimplemented!() }
}

// Lemmy-style auth function: `check_<resource>_<role>_action`.
pub fn check_community_user_action(_uv: &LocalUserView, _c: &Community, _p: &mut Pool) -> Result<(), ()> { Ok(()) }
pub fn check_community_mod_action(_uv: &LocalUserView, _c: &Community, _b: bool, _p: &mut Pool) -> Result<(), ()> { Ok(()) }

pub async fn distinguish_comment(
    req: DistinguishComment,
    pool: &mut Pool,
    local_user_view: LocalUserView,
) -> Result<CommentResponse, ()> {
    let local_instance_id = local_user_view.person.instance_id;

    // Fetch the row first to obtain `community` for authz.
    let orig_comment = CommentView::read(
        pool,
        req.comment_id,
        Some(&local_user_view.local_user),
        local_instance_id,
    )?;

    // Auth check on the fetched row's resource.  Engine recognises the
    // `check_<resource>_<role>_action` shape, sees `orig_comment` as a
    // subject, and applies the row-fetch exemption to the read above.
    check_community_user_action(&local_user_view, &orig_comment.community, pool)?;

    if local_user_view.person.id != orig_comment.creator.id {
        return Err(());
    }

    check_community_mod_action(&local_user_view, &orig_comment.community, false, pool)?;

    Ok(CommentResponse)
}
