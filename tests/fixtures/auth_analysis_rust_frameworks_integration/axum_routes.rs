use axum::{Json, Router, middleware, routing::{get, post}};

struct CurrentUser {
    user_id: String,
}

struct BulkArchive {
    project_ids: Vec<String>,
}

fn require_login() {}

async fn admin_audit_log(_user: CurrentUser) {
    admin_audit_service::publish();
}

async fn bulk_archive_projects(user: CurrentUser, Json(body): Json<BulkArchive>) {
    let project_ids = body.project_ids;
    require_membership(project_ids[0], user.user_id);
    project_service::delete(project_ids);
}

fn router() -> Router {
    Router::new()
        .layer(middleware::from_fn(require_login))
        .route("/admin/audits", get(admin_audit_log))
        .route("/projects/bulk-archive", post(bulk_archive_projects))
}

fn require_membership<T, U>(_project_id: T, _actor_id: U) {}

mod admin_audit_service {
    pub fn publish() {}
}

mod project_service {
    pub fn delete<T>(_project_ids: T) {}
}
