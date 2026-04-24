// rs-safe-015: Intraprocedural `is_absolute()` rejection.
//
// `Path::new(raw).is_absolute()` true on the reject branch; false branch
// proves `absolute = No`.  Combined with a `..` rejection this clears
// both PathFact axes used by the FILE_IO sink guard.
use std::env;
use std::fs::File;
use std::path::Path;

fn main() -> std::io::Result<()> {
    let raw = env::var("USER_PATH").unwrap();
    if Path::new(&raw).is_absolute() {
        return Ok(());
    }
    if raw.contains("..") {
        return Ok(());
    }
    let _f = File::open(&raw)?;
    Ok(())
}
