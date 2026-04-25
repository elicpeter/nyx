use std::env;
use std::process::Command;

fn main() {
    let prog = env::var("PROG_NAME").unwrap();
    let out = Command::new(&prog).output().unwrap();
    println!("{}", String::from_utf8_lossy(&out.stdout));
}
