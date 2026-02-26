use std::env;
use std::fs;

fn read_user_file() -> String {
    let path = env::var("FILE_PATH").unwrap();
    fs::read_to_string(&path).unwrap()
}
