struct AdminUser;

struct SessionUser {
    project_id: String,
}

struct AcceptInvite {
    email: String,
}

struct Json<T>(T);

struct Invitation {
    email: Option<String>,
}

#[get("/admin/audits")]
fn admin_audits(_admin: AdminUser) {
    admin_audit_service::publish();
}

#[post("/projects/archive")]
fn archive_project(session: SessionUser) {
    project_service::archive(session.project_id);
}

#[post("/invites/<token>/accept", data = "<body>")]
fn accept_invite(token: String, body: Json<AcceptInvite>) {
    let invitation = invitation_store::find_by_token(token);
    invitation_service::accept(invitation.email.or(Some(body.0.email)));
}

mod admin_audit_service {
    pub fn publish() {}
}

mod project_service {
    pub fn archive<T>(_project_id: T) {}
}

mod invitation_store {
    use super::Invitation;

    pub fn find_by_token<T>(_token: T) -> Invitation {
        Invitation { email: None }
    }
}

mod invitation_service {
    pub fn accept<T>(_email: T) {}
}
