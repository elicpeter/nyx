use std::env;
use std::process::Command;

fn main() {
    let user = env::var("TARGET").unwrap();
    let full = String::from("find /tmp -name ") + &user;
    Command::new("sh").arg("-c").arg(&full).status().unwrap();
}
