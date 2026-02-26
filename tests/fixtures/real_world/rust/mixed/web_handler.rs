use std::env;
use std::process::Command;
use std::fs;

fn handle_request() {
    let cmd = env::var("USER_CMD").unwrap();
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .unwrap();

    let path = env::var("USER_PATH").unwrap();
    let content = fs::read_to_string(&path).unwrap();
    println!("{}", content);
}
