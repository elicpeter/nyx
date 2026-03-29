use actix_web::web;

struct AdminUser;

fn require_admin() {}

async fn archive_projects(_admin: AdminUser) {
    admin_audit_service::publish();
}

fn routes() {
    web::resource("/admin/projects/archive")
        .wrap(require_admin)
        .route(web::post().to(archive_projects));
}

mod admin_audit_service {
    pub fn publish() {}
}
