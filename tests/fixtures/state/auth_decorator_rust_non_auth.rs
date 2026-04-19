use std::process::Command;

// #[inline] is NOT an auth attribute — finding should fire.
#[inline]
fn handle_request(req: &str) {
    Command::new("sh").arg("-c").arg("ls /tmp").status().unwrap();
}
