use std::process::Command;

#[require_auth]
fn handle_request(req: &str) {
    Command::new("sh").arg("-c").arg("ls /tmp").status().unwrap();
}
