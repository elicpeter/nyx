// Precision fixture distilled from meilisearch
// `crates/dump/src/reader/v6/mod.rs::V6Reader::open` (bucket-1 of the
// `File::open`/`fs::read` dual Source+Sink cluster).
//
// A dump reader reads several files' *contents* at CONSTANT relative paths
// (`fs::read(dump.path().join("network.json"))` etc.) inside `match` arms and
// collects the results into an `Ok(Struct { … })` aggregate.  `fs::read` is
// BOTH a `Source(Cap::all())` ("file system data") AND a `Sink(Cap::FILE_IO)`
// (its path argument), so before the path-argument confinement gate the
// file-system-tainted result of one read bled — via an implicit-trailing SSA
// use of the flattened `match` statement — into the path-argument slot of a
// SIBLING read, reporting a spurious `file_system -> FILE_IO` self-flow
// (meilisearch v6/mod.rs:104,126).  Every path here is a constant relative
// segment and no attacker input is involved, so nothing must fire.
//
// Paired recall counterpart: rust/path_traversal/dump_reader_content_as_path.rs
// (a read whose CONTENTS are genuinely used as the next read's path — must
// still fire).

use std::fs;
use std::io::ErrorKind;

type Result<T> = std::result::Result<T, std::io::Error>;

pub struct TempDir;
impl TempDir {
    fn path(&self) -> &std::path::Path {
        std::path::Path::new("/")
    }
}

pub struct Reader {
    features: Option<u32>,
    instance_uid: Option<u32>,
    network: Option<u32>,
    webhooks: Option<u32>,
}

impl Reader {
    pub fn open(dump: TempDir) -> Result<Self> {
        let feature_file = match fs::read(dump.path().join("experimental-features.json")) {
            Ok(f) => Some(f),
            Err(error) => match error.kind() {
                ErrorKind::NotFound => None,
                _ => return Err(error),
            },
        };
        let features = if let Some(f) = feature_file {
            Some(serde_json::from_reader(&*f)?)
        } else {
            None
        };
        let instance_uid = match fs::read(dump.path().join("instance_uid.uuid")) {
            Ok(f) => Some(serde_json::from_reader(&*f)?),
            Err(error) => match error.kind() {
                ErrorKind::NotFound => None,
                _ => return Err(error),
            },
        };
        let network = match fs::read(dump.path().join("network.json")) {
            Ok(f) => Some(serde_json::from_reader(&*f)?),
            Err(error) => match error.kind() {
                ErrorKind::NotFound => None,
                _ => return Err(error),
            },
        };
        let webhooks = match fs::read(dump.path().join("webhooks.json")) {
            Ok(f) => Some(serde_json::from_reader(&*f)?),
            Err(error) => match error.kind() {
                ErrorKind::NotFound => None,
                _ => return Err(error),
            },
        };
        Ok(Reader {
            features,
            instance_uid,
            network,
            webhooks,
        })
    }
}
