// rs-safe-016: cross-function `.contains("..")` rejection helper.
//
// `validate_no_dotdot` returns `false` whenever its input contains
// the parent-directory marker.  The caller's `if !validate_no_dotdot(s)
// { return; }` rejection narrows the input's PathFact `dotdot = No` on
// the surviving branch.  Combined with the absolute-axis check inside
// the helper, the path argument that reaches `File::open` is provably
// path-safe even though the helper's body lives in a separate function.
use std::env;
use std::fs::File;

fn validate_no_dotdot(s: &str) -> bool {
    !s.contains("..") && !s.starts_with('/') && !s.starts_with('\\')
}

fn main() -> std::io::Result<()> {
    let raw = env::var("USER_PATH").unwrap();
    if !validate_no_dotdot(&raw) {
        return Ok(());
    }
    let _f = File::open(&raw)?;
    Ok(())
}
