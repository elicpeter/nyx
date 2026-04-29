use std::env;
use std::fs;

// Wrapper whose replace chain strips only unrelated characters.  The scanner
// must NOT treat this as a path-traversal sanitizer, the taint path should
// still be flagged.
fn rewrite(s: &str) -> String {
    s.replace("foo", "bar").replace("baz", "qux")
}

fn main() {
    let path = env::var("FILE_PATH").unwrap();
    let rewritten = rewrite(&path);
    let _contents = fs::read_to_string(&rewritten).unwrap();
}
