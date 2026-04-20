use std::env;
use std::process::Command;

mod transform;

fn main() {
    let input = env::var("USER_ARG").unwrap();
    let shaped = transform::wrap(&input);
    Command::new("sh").arg("-c").arg(&shaped).status().unwrap();
}
