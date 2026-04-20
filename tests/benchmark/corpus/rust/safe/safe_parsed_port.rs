use std::env;
use std::process::Command;

fn main() {
    let raw = env::var("PORT").unwrap();
    let port: u16 = raw.parse().expect("invalid port");
    Command::new("listener").arg(port.to_string()).status().unwrap();
}
