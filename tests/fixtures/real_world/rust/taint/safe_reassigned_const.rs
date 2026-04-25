use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("CMD").unwrap();
    let cmd = "safe";
    Command::new("sh").arg(cmd).status().unwrap();
}
