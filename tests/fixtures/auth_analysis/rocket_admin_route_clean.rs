struct AdminUser;

#[get("/admin/audits")]
fn admin_audits(_admin: AdminUser) {
    admin_audit_service::publish();
}

mod admin_audit_service {
    pub fn publish() {}
}
