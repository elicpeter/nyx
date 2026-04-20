use std::env;
use std::process::Command;

fn main() {
    let input = env::var("USER_CMD").unwrap();
    if input.contains(";") || input.contains("|") || input.contains("&") {
        return;
    }
    Command::new("echo").arg(&input).status().unwrap();
}
