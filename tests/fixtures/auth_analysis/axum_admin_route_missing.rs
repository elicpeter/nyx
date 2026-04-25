use axum::{Router, middleware, routing::get};

struct CurrentUser;

fn require_login() {}

async fn admin_audit_log(_user: CurrentUser) {
    admin_audit_service::publish();
}

fn router() -> Router {
    Router::new()
        .layer(middleware::from_fn(require_login))
        .route("/admin/audits", get(admin_audit_log))
}

mod admin_audit_service {
    pub fn publish() {}
}
