use std::env;
use std::process::Command;

fn run_cmd(cmd: &str) {
    Command::new("bash").arg("-c").arg(cmd).status().unwrap();
}

fn main() {
    let input = env::var("USER_INPUT").unwrap();
    run_cmd(&input);
}
