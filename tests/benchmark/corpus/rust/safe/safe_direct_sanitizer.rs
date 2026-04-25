// Simpler variant: direct-return path sanitizer (no Option unwrap).
//
// `sanitize_path` rejects `..` / absolute-rooted paths and returns the
// validated string directly.  Phase B inline PathFact propagation should
// narrow `safe` to `dotdot = No && absolute = No` → File::open is clean.
use std::env;
use std::fs::File;

fn sanitize_path(s: &str) -> String {
    if s.contains("..") || s.starts_with('/') || s.starts_with('\\') {
        return String::new();
    }
    s.to_string()
}

fn main() -> std::io::Result<()> {
    let raw = env::var("USER_PATH").unwrap();
    let safe = sanitize_path(&raw);
    let _f = File::open(&safe)?;
    Ok(())
}
