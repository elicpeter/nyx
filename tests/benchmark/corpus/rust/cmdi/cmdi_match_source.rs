use std::env;
use std::process::Command;

fn main() {
    let prog = match env::var("TOOL") {
        Ok(v) => v,
        Err(_) => "ls".to_string(),
    };
    Command::new(&prog).arg("/tmp").status().unwrap();
}
