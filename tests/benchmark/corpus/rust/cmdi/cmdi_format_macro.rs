use std::env;
use std::process::Command;

fn main() {
    let user = env::var("USER_INPUT").unwrap();
    let cmd = format!("ls -la {}", user);
    Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
}
