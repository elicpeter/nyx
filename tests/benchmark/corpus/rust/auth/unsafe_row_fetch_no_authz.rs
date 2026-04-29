// Vulnerable counterpart to `row_fetch_then_authorize.rs`, the row is
// fetched by user-supplied id but no authorization function names it.
// The row-fetch exemption must NOT fire here; the rule should still
// flag the read as missing an ownership/membership check.

use std::result::Result;

pub struct DataReq { pub comment_id: i64 }
pub struct LocalUserView;
pub struct Pool;
pub struct CommentView;

impl CommentView {
    pub fn read(_p: &mut Pool, _id: i64) -> Result<CommentView, ()> { unimplemented!() }
    pub fn delete(_p: &mut Pool, _id: i64) -> Result<(), ()> { unimplemented!() }
}

// NOTE: no authorization check is invoked anywhere in this handler.
pub async fn unsafe_handler(
    req: DataReq,
    pool: &mut Pool,
    _local_user_view: LocalUserView,
) -> Result<(), ()> {
    let _orig = CommentView::read(pool, req.comment_id)?;
    CommentView::delete(pool, req.comment_id)?;
    Ok(())
}
