use actix_web::web;

struct CurrentUser;

struct UpdateProject {
    owner_id: String,
}

fn require_login() {}

async fn update_project(
    _user: CurrentUser,
    path: web::Path<String>,
    payload: web::Json<UpdateProject>,
) {
    let project_id = path.into_inner();
    project_service::update(project_id, payload.owner_id.clone());
}

fn routes() {
    web::resource("/projects/{project_id}")
        .wrap(require_login)
        .route(web::put().to(update_project));
}

mod project_service {
    pub fn update<T, U>(_project_id: T, _owner_id: U) {}
}
