use std::env;
use std::fs::File;

fn main() {
    let path = env::var("FILE_PATH").unwrap();
    let _f = File::open(&path).unwrap();
}
