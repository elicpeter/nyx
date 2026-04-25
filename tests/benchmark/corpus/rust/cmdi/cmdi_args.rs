use std::env;
use std::process::Command;

fn main() {
    let user_arg = env::var("USER_ARG").unwrap();
    Command::new("find").args(&["/tmp", "-name", &user_arg]).status().unwrap();
}
