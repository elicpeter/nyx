// Recall counterpart to rust/safe/safe_dump_reader_sibling_reads.rs.
//
// The dump reader reads a manifest file's *contents* (`fs::read_to_string`, a
// `file_system` source) and then uses those contents DIRECTLY as the PATH
// argument of a second `fs::read`.  The tainted value genuinely reaches the
// sink's path position (arg 0), so the path-argument confinement gate must
// keep the flow: reading a path out of one file and opening it is a real
// file-content -> path-traversal flow (CWE-22).  This proves the gate confines
// to the path argument WITHOUT suppressing a genuine data-dependent
// file-content -> FILE_IO flow (contrast the sibling-reads precision fixture,
// where the tainted contents never reach any path argument).

use std::fs;

type Result<T> = std::result::Result<T, std::io::Error>;

pub struct TempDir;
impl TempDir {
    fn path(&self) -> &std::path::Path {
        std::path::Path::new("/")
    }
}

pub fn load(dump: TempDir) -> Result<Vec<u8>> {
    let manifest = fs::read_to_string(dump.path().join("manifest.txt"))?;
    // `manifest` file contents are used directly as the path of the next read.
    let data = fs::read(&manifest)?;
    Ok(data)
}
