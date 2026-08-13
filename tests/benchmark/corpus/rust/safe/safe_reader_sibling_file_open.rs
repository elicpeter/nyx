use std::fs::{self, File};
use std::io::BufReader;

/// Precision counterpart to `rust/path_traversal/reader_wrapped_file_open.rs`.
///
/// Distilled from meilisearch `crates/dump/src/reader/v{2..6}/mod.rs`.  A dump
/// reader reads one file's *contents* (`fs::read`, a "file system data"
/// source) into a struct field, and opens ANOTHER file at a CONSTANT relative
/// path in a SIBLING field of the same `Ok(Reader { ... })` aggregate.  The
/// tainted contents (`metadata`) never flow into the `File::open` path
/// argument — they occupy a different sub-position of the flattened aggregate
/// node.  The engine must not report `metadata` as reaching the sibling
/// `File::open` FILE_IO sink.
pub struct Reader {
    metadata: String,
    tasks: BufReader<File>,
}

pub fn open(dir: &std::path::Path) -> std::io::Result<Reader> {
    let meta_file = fs::read(dir.join("metadata.json"))?;
    let metadata = String::from_utf8(meta_file).unwrap();

    Ok(Reader {
        metadata,
        tasks: BufReader::new(File::open(dir.join("updates/data.jsonl")).unwrap()),
    })
}
