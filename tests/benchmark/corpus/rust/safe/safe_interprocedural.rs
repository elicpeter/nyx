use std::env;
use std::fs;

fn canonicalize_path(p: &str) -> String {
    sanitize_input(p)
}

fn sanitize_input(s: &str) -> String {
    s.replace("..", "").replace("/", "_")
}

fn main() {
    let path = env::var("FILE_PATH").unwrap();
    let clean = canonicalize_path(&path);
    let contents = fs::read_to_string(&clean).unwrap();
    println!("{}", contents);
}
