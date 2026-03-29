struct SessionUser {
    project_id: String,
}

#[post("/projects/archive")]
fn archive_project(session: SessionUser) {
    project_service::archive(session.project_id);
}

mod project_service {
    pub fn archive<T>(_project_id: T) {}
}
