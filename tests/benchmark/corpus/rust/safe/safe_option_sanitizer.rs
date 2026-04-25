// rs-safe-014: Option-returning user sanitiser.
//
// `sanitize_path` rejects `..` / absolute-rooted paths and returns the
// validated string; the caller unwraps via `match`, so the `Some` arm
// re-binds a path value that Phase B's inline PathFact propagation has
// proved `dotdot = No && absolute = No`.  Scanner must **not** flag the
// `File::open` sink: the argument's PathFact is provably path-safe.
use std::env;
use std::fs::File;

fn sanitize_path(s: &str) -> Option<String> {
    if s.contains("..") || s.starts_with('/') || s.starts_with('\\') {
        return None;
    }
    Some(s.to_string())
}

fn main() -> std::io::Result<()> {
    let raw = env::var("USER_PATH").unwrap();
    let safe = match sanitize_path(&raw) {
        Some(s) => s,
        None => return Ok(()),
    };
    let _f = File::open(&safe)?;
    Ok(())
}
