// Real-repo motivation (lemmy `LocalUserView` extractor).
//
// Lemmy's authenticated-actor extractor type is named `LocalUserView`
// — every route handler signature is
// `pub async fn handler(.., local_user_view: LocalUserView)`.  The
// previous exact-name list in `is_self_actor_type_text`
// (`CurrentUser`, `SessionUser`, `AuthUser`, `AdminUser`,
// `AuthenticatedUser`, `RequireAuth`, `RequireLogin`,
// `Authenticated`) missed it, so subjects rooted in
// `local_user_view.*` weren't recognised as the caller's own id and
// any access of `local_user_view.person.id` flagged.
//
// The structural `<PREFIX>User<SUFFIX>?` recogniser now accepts
// `LocalUserView`, so this self-actor read on the principal must NOT
// flag `rs.auth.missing_ownership_check`.

use std::result::Result;

pub struct LocalUserView {
    pub person: Person,
}
pub struct Person {
    pub id: i64,
    pub name: String,
}
pub struct Form {
    pub note: String,
}
pub struct Pool;
pub struct UserActions;

impl UserActions {
    pub fn record_self_note(_pool: &mut Pool, _id: i64, _note: String) -> Result<(), ()> {
        Ok(())
    }
}

pub fn is_admin(_uv: &LocalUserView) -> Result<(), ()> {
    Ok(())
}

pub async fn write_self_note(
    req: Form,
    pool: &mut Pool,
    local_user_view: LocalUserView,
) -> Result<(), ()> {
    // Login predicate on the actor itself — subject is the actor.
    // No additional ownership check needed because the subject is the
    // caller's own row.
    let _ = is_admin(&local_user_view);

    // `local_user_view.person.id` is the caller's own id.  With
    // `LocalUserView` recognised as a self-actor type, this passes
    // through `is_actor_context_subject`.
    UserActions::record_self_note(pool, local_user_view.person.id, req.note)?;
    Ok(())
}
