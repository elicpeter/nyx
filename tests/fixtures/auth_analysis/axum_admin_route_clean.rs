use axum::{Router, middleware, routing::get};

struct AdminUser;

fn require_admin() {}

async fn admin_audit_log(_admin: AdminUser) {
    admin_audit_service::publish();
}

fn router() -> Router {
    Router::new()
        .layer(middleware::from_fn(require_admin))
        .route("/admin/audits", get(admin_audit_log))
}

mod admin_audit_service {
    pub fn publish() {}
}
