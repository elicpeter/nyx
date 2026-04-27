// Phase A4: `is_<role>_or_<role>` predicate authorization shape.
// Authorization helpers named as boolean predicates (`is_admin`,
// `is_mod_or_admin`, `is_owner_and_admin`) are the standard Rails /
// Lemmy / Diesel idiom for role checks.  The structural recogniser
// accepts the `is_<role>` and `is_<role>_(or|and)_<role>` shapes when
// every conjunct is a known authorization role token.

use std::result::Result;

pub struct LocalUserView;
pub struct Pool;
pub struct CommentView;

pub struct ListCommentLikes { pub comment_id: i64 }
pub struct CommunityRef { pub id: i64 }
pub struct CommentRow { pub community: CommunityRef }

impl CommentView {
    pub fn read(_pool: &mut Pool, _id: i64) -> Result<CommentRow, ()> { unimplemented!() }
}

// Predicate auth check: each conjunct (`mod`, `admin`) is a known role.
pub fn is_mod_or_admin(_pool: &mut Pool, _uv: &LocalUserView, _community_id: i64) -> Result<(), ()> {
    Ok(())
}

pub async fn list_comment_likes(
    req: ListCommentLikes,
    pool: &mut Pool,
    local_user_view: LocalUserView,
) -> Result<CommentRow, ()> {
    // Fetch row first to obtain community id for the role check.
    let comment_view = CommentView::read(pool, req.comment_id)?;

    // Predicate role check authorises the fetched row.  Row-fetch
    // exemption suppresses the `CommentView.read` finding above:
    // `is_mod_or_admin` matches the `is_<role>_or_<role>` shape and
    // its third arg `comment_view.community.id` chains back to the
    // row var `comment_view`.
    is_mod_or_admin(pool, &local_user_view, comment_view.community.id)?;

    Ok(comment_view)
}
