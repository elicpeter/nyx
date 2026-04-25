use axum::{Json, Router, routing::post};

struct CurrentUser {
    user_id: String,
}

struct BulkArchive {
    project_ids: Vec<String>,
}

fn require_membership<T, U>(_project_id: T, _actor_id: U) {}

async fn bulk_archive_projects(user: CurrentUser, Json(body): Json<BulkArchive>) {
    let project_ids = body.project_ids;
    require_membership(project_ids[0], user.user_id);
    project_service::delete(project_ids);
}

fn router() -> Router {
    Router::new().route("/projects/bulk-archive", post(bulk_archive_projects))
}

mod project_service {
    pub fn delete<T>(_project_ids: T) {}
}
