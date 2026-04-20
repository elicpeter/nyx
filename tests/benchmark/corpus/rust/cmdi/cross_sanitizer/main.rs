use std::env;
use std::process::Command;

mod sanitizer;

fn main() {
    let raw = env::var("USER_ARG").unwrap();
    let clean = sanitizer::sanitize_shell(&raw);
    Command::new("echo").arg(&clean).status().unwrap();
}
