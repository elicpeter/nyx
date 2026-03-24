use std::env;
use std::process::Command;

fn main() {
    let _input = env::var("USER_CMD").unwrap();
    let cmd = "echo safe";
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}
