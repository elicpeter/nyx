use std::env;
use std::fs;

// Wrapper whose replace chain ostensibly targets path-traversal but whose
// replacement literal reintroduces the dangerous `..` sequence.  The scanner
// must refuse to credit this as a sanitizer.
fn evil_rewrite(s: &str) -> String {
    s.replace("x", "..")
}

fn main() {
    let path = env::var("FILE_PATH").unwrap();
    let rewritten = evil_rewrite(&path);
    let _contents = fs::read_to_string(&rewritten).unwrap();
}
