use std::env;
use std::process::Command;

fn run_user_command() {
    let cmd = env::var("USER_CMD").unwrap();
    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .unwrap();
}

fn run_safe_command() {
    let cmd = env::var("USER_CMD").unwrap_or_default();
    let allowed = ["ls", "date"];
    if allowed.contains(&cmd.as_str()) {
        Command::new(&cmd).output().unwrap();
    }
}
