use axum::{Router, middleware, routing::post};

struct CurrentUser;

fn require_login() {}

async fn archive_project(_user: CurrentUser) {
    admin_audit_service::publish();
}

fn router() -> Router {
    Router::new()
        .layer(middleware::from_fn(require_login))
        .route("/admin/projects/archive", post(archive_project))
}

mod admin_audit_service {
    pub fn publish() {}
}
