use std::env;
use std::process::Command;

fn main() {
    let input = env::var("USER_INPUT").unwrap();
    let clean = sanitize_shell(&input);
    Command::new("echo").arg(&clean).status().unwrap();
}

fn sanitize_shell(s: &str) -> String {
    s.replace("'", "\\'")
}
