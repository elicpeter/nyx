use std::env;
use std::process::Command;

fn main() {
    let raw = env::var("USER_NAME").unwrap();
    let name = match raw.as_str() {
        v if v.chars().all(|c| c.is_ascii_alphanumeric()) => v.to_string(),
        _ => return,
    };
    Command::new("id").arg(&name).status().unwrap();
}
