use std::env;
use std::fs;

fn main() {
    let path = env::var("OUTPUT_PATH").unwrap();
    fs::write(&path, "data").unwrap();
}
