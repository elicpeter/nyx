// Inline numeric parse chain flowing into a shell argument.
//
// `raw_port.parse::<u16>().unwrap().to_string()` confines the tainted env
// value to a `u16` before stringifying it, so the argument is a bare decimal
// number — it cannot carry shell metacharacters.  The inner numeric chain
// never lowers to its own SSA value (the outer `Command` chain flattens the
// source leaf `raw_port` directly into its use set), so the value-level
// `TypeKind::Int` suppression cannot reach it; the CFG-level
// `numeric_confined_uses` recogniser must clear both the taint flow and the
// structural `cfg-unguarded-sink`.
use std::process::Command;

fn spawn_listener() {
    let raw_port = std::env::var("LISTEN_PORT").unwrap_or_default();
    let _ = Command::new("nc")
        .arg(raw_port.parse::<u16>().unwrap().to_string())
        .output();
}
