use std::fs::{self, File};

/// Recall guard for the inner-nested-sink argument-attribution fix.
///
/// Same `Ok(...)`-wrapped shape as the safe sibling fixture, but here the
/// tainted file *contents* (`name`, read from a first file) ARE the path
/// argument to the inner `File::open` sink.  The taint genuinely reaches the
/// sink's argument (not a sibling struct field), so the flow must still fire
/// even though the classified `File::open` sink is nested inside the outer
/// `Ok(...)` aggregate wrapper.
pub fn open(dir: &std::path::Path) -> std::io::Result<File> {
    let name = fs::read_to_string(dir.join("meta.json"))?;
    Ok(File::open(&name)?)
}
