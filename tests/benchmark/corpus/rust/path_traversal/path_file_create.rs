use std::env;
use std::fs::File;

fn main() {
    let path = env::var("OUTPUT_PATH").unwrap();
    let _f = File::create(&path).unwrap();
}
