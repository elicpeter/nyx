// Real-repo regression (lemmy `comment/lock.rs:31`).
//
// `let orig_comment = CommentView::read(...)` split across two lines
// (the call body wraps onto the next line for readability).  Before
// the line-counting fix, `row_population_data` recorded the
// `let_declaration`'s start row while `op.line` saw the inner call's
// start row — they differed by one and the row-fetch exemption
// missed.  Recording the **call**'s start line aligns the two and
// the exemption fires for the multi-line shape too.

use std::result::Result;

pub struct LockComment {
    pub comment_id: i64,
}
pub struct LocalUserView {
    pub person: Person,
}
pub struct Person {
    pub instance_id: i64,
}
pub struct Pool;
pub struct CommentView {
    pub community: Community,
    pub comment: Comment,
}
pub struct Community;
pub struct Comment {
    pub path: String,
}

impl CommentView {
    pub fn read(_pool: &mut Pool, _id: i64, _opt: Option<()>, _i: i64) -> Result<CommentView, ()> {
        unimplemented!()
    }
}

pub fn check_community_mod_action(
    _uv: &LocalUserView,
    _c: &Community,
    _b: bool,
    _p: &mut Pool,
) -> Result<(), ()> {
    Ok(())
}

pub async fn lock_comment(
    req: LockComment,
    pool: &mut Pool,
    local_user_view: LocalUserView,
) -> Result<(), ()> {
    let comment_id = req.comment_id;
    let local_instance_id = local_user_view.person.instance_id;

    // Multi-line let — the let_declaration starts on this line, but
    // the inner `CommentView::read(..)` call starts on the next line.
    // `op.line` for the read sink is the call's line, not the let's.
    let orig_comment =
        CommentView::read(pool, comment_id, None, local_instance_id)?;

    // Auth check on the fetched row.
    check_community_mod_action(&local_user_view, &orig_comment.community, false, pool)?;

    Ok(())
}
