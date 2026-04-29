struct Ctx;
struct Req;
struct User {
    id: i64,
    email: String,
}
struct Env;

mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User {
            id: 1,
            email: "u@example.com".into(),
        })
    }
}

mod realtime {
    pub async fn publish_to_user(
        _env: &super::Env,
        _email: &str,
        _topic: &str,
        _payload: serde_json::Value,
    ) -> Result<(), ()> {
        Ok(())
    }
}

mod serde_json {
    pub use serde::Serialize;
    pub fn json(v: impl Serialize) -> String {
        let _ = v;
        String::new()
    }
    pub type Value = String;
}

// Real-repo shape from website/src/handlers/social.rs:
//   `realtime::publish_to_user(&ctx.env, &user.email, ...)`, publish
//   to the authed user's OWN channel keyed by their email.  The
//   `email` / `username` / `handle` fields of a self-actor binding
//   reference the actor's own identity, just like `id` / `user_id`,
//   and must not flag `rs.auth.missing_ownership_check`.
pub async fn handle_update_profile(req: Req, ctx: Ctx) -> Result<(), ()> {
    let user = match auth::require_auth(&req, &ctx).await {
        Ok(u) => u,
        Err(_) => return Err(()),
    };
    let env = Env;

    realtime::publish_to_user(&env, &user.email, "profile.updated", String::new())
        .await
        .ok();

    Ok(())
}
