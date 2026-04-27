// Negative counterpart for the `LocalUserView` self-actor recogniser.
//
// Even when the handler takes a typed `LocalUserView` extractor, a
// sink that reads or mutates a row by **someone else's** id is still
// missing-ownership-check.  The actor recogniser only suppresses
// subjects rooted in `local_user_view.*` (the actor's own fields);
// foreign scoped ids (`req.target_user_id`) must continue to flag.
//
// Regression guard against an over-broad recogniser that would treat
// any handler with a self-actor extractor as "authorised by default".

use std::result::Result;

pub struct LocalUserView {
    pub person: Person,
}
pub struct Person {
    pub id: i64,
}
pub struct Form {
    pub target_user_id: i64,
    pub note: String,
}
pub struct Pool;
pub struct UserActions;

impl UserActions {
    pub fn add_note_for_user(_pool: &mut Pool, _target: i64, _note: String) -> Result<(), ()> {
        Ok(())
    }
}

pub async fn add_note_about_user(
    req: Form,
    pool: &mut Pool,
    local_user_view: LocalUserView,
) -> Result<(), ()> {
    // Authentication is established (`local_user_view` is a typed
    // self-actor extractor) but no ownership/membership check
    // gates the foreign id `req.target_user_id`.  Must flag.
    let _ = local_user_view.person.id;
    UserActions::add_note_for_user(pool, req.target_user_id, req.note)?;
    Ok(())
}
