// Leaf-name collision precision fixture (distilled from meilisearch
// `crates/dump/src/reader/v{2..6}/mod.rs`).
//
// The stdlib associated functions `File::open` (leaf `open`) and
// `BufReader::new` (leaf `new`) share their leaf name with the
// user-defined methods `Reader::open` / `IndexReader::new`.  Before the
// namespace-qualifier authority fix in `resolve_callee` /
// `resolve_local_func_key_query`, the callee resolver bound the stdlib
// `File::open` to the enclosing `impl Reader { fn open }` (caller-container
// self-collision) and `BufReader::new` to the unique-arity
// `IndexReader::new` (arity-only leaf collision).  `Reader::open`'s summary
// is a file-system source (it does `fs::read`), so `File::open`'s handle
// was tainted; `IndexReader::new`'s summary marks its `path` param a
// FILE_IO sink, so `BufReader::new(handle)` fired a spurious
// `file_system -> FILE_IO` taint flow even though every path here is a
// constant relative segment and no attacker input is involved.
//
// A `::`-qualified callee names a concrete type/module; with no local
// definition in that container it is an external associated function and
// must NOT bind a same-leaf method from an unrelated container.

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct Reader {
    index_uuid: Vec<u8>,
}

impl Reader {
    pub fn open(dump: TempDir) -> Result<Self> {
        let meta_file = fs::read(dump.path().join("metadata.json"))?;
        let _metadata = serde_json::from_reader(&*meta_file)?;
        let index_uuid = File::open(dump.path().join("index_uuids/data.jsonl"))?;
        let index_uuid = BufReader::new(index_uuid);
        let index_uuid = index_uuid
            .lines()
            .map(|line| -> Result<_> { Ok(serde_json::from_str(&line?)?) })
            .collect::<Result<Vec<_>>>()?;
        Ok(Reader { index_uuid })
    }
}

pub struct IndexReader {
    documents: BufReader<File>,
}

impl IndexReader {
    pub fn new(path: &Path) -> Result<Self> {
        let meta = File::open(path.join("meta.json"))?;
        let _meta: DumpMeta = serde_json::from_reader(meta)?;
        Ok(IndexReader {
            documents: BufReader::new(File::open(path.join("documents.jsonl"))?),
        })
    }
}
