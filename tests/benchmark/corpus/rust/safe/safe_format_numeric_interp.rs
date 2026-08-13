// Numeric interpolation into a filesystem path via `format!`.
//
// `id.parse::<u32>().unwrap()` confines the tainted env value to a `u32`
// before `format!` interpolates it, so the rendered path component is a bare
// decimal number — it cannot carry `..` or path-separator payloads.  Inside a
// `format!` macro tree-sitter-rust flattens the inner numeric chain into the
// macro's `token_tree` (no dedicated SSA value), so the CFG-level
// `numeric_confined_uses` recogniser must re-parse the interpolation argument
// to clear both the taint flow and the structural `cfg-unguarded-sink`.
use std::env;
use std::fs;

fn read_record() {
    let id = env::var("RECORD_ID").unwrap_or_default();
    let _ = fs::read(format!("/var/data/{}", id.parse::<u32>().unwrap()));
}
