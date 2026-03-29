struct AcceptInvite {
    email: String,
}

struct Json<T>(T);

struct Invitation {
    email: Option<String>,
}

#[post("/invites/<token>/accept", data = "<body>")]
fn accept_invite(token: String, body: Json<AcceptInvite>) {
    let invitation = invitation_store::find_by_token(token);
    invitation_service::accept(invitation.email.or(Some(body.0.email)));
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
