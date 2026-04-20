use std::env;
use serde::Deserialize;

#[derive(Deserialize)]
struct Payload { _cmd: String }

fn main() {
    let raw = env::var("PAYLOAD_YAML").unwrap();
    let _p: Payload = serde_yaml::from_str(&raw).unwrap();
}
