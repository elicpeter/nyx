// Recall counterpart to safe/safe_leaf_name_collision_file_reader.rs.
//
// The same `open` / `new` leaf-name collision decoys are present, but here
// an attacker-controlled request header flows into `File::open`'s path
// argument.  The namespace-qualifier authority fix must still let this
// genuine path-traversal flow fire: `File::open` resolves to its stdlib
// FILE_IO sink label (not to the decoy `Reader::open` / `IndexReader::new`
// methods), so the tainted `p` reaching the path arg is reported.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

pub fn download(req: &HttpRequest) -> Result<()> {
    let p = req.headers().get("x-file").unwrap();
    let f = File::open(p)?;
    let _r = BufReader::new(f);
    Ok(())
}

// Collision decoys sharing the `open` / `new` leaf names.
pub struct Reader {
    index_uuid: Vec<u8>,
}

impl Reader {
    pub fn open(dump: TempDir) -> Result<Self> {
        let meta_file = fs::read(dump.path().join("metadata.json"))?;
        let _metadata = serde_json::from_reader(&*meta_file)?;
        Ok(Reader { index_uuid: Vec::new() })
    }
}

pub struct IndexReader {
    documents: BufReader<File>,
}

impl IndexReader {
    pub fn new(path: &Path) -> Result<Self> {
        Ok(IndexReader {
            documents: BufReader::new(File::open(path.join("documents.jsonl"))?),
        })
    }
}
