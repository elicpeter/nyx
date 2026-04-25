use std::env;
use std::fs;

fn main() {
    let path = env::var("DOOMED_PATH").unwrap();
    fs::remove_file(&path).unwrap();
}
