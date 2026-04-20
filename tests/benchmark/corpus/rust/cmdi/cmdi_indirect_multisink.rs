use std::env;
use std::process::Command;

fn run_both(primary: &str, secondary: &str) {
    Command::new("sh").arg("-c").arg(primary).status().unwrap();
    Command::new("bash").arg("-c").arg(secondary).status().unwrap();
}

fn main() {
    let a = env::var("USER_CMD_A").unwrap();
    let b = env::var("USER_CMD_B").unwrap();
    run_both(&a, &b);
}
