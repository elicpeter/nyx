// rs-safe-012: Intraprocedural path-traversal rejection via `contains("..")`.
//
// Input is rejected before any FILE_IO sink when it contains a parent-dir
// component or an absolute-path root.  Phase A PathFact branch narrowing
// on the false branch proves `dotdot = No && absolute = No` on `raw`, so
// File::open must not flag.
use std::env;
use std::fs::File;

fn main() -> std::io::Result<()> {
    let raw = env::var("USER_PATH").unwrap();
    if raw.contains("..") || raw.starts_with('/') || raw.starts_with('\\') {
        return Ok(());
    }
    let _f = File::open(&raw)?;
    Ok(())
}
