// rs-path-006: Negative-case guard for PathFact.
//
// No sanitiser and no narrowing, PathFact stays Top on every axis, so
// the FILE_IO sink MUST fire.  This fixture guards against PathFact
// over-suppression sneaking into `is_path_safe_for_sink`.
use std::env;
use std::fs::File;

fn main() -> std::io::Result<()> {
    let raw = env::var("USER_PATH").unwrap();
    let _f = File::open(&raw)?;
    Ok(())
}
