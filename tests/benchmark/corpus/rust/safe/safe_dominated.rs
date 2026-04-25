use std::env;
use std::process::Command;

fn main() {
    let input = env::var("USER_CMD").unwrap();
    if input.len() > 100 || input.contains(";") || input.contains("|") {
        return;
    }
    Command::new("echo").arg(&input).status().unwrap();
}
