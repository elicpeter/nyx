// ─────────────────────────────────────────────────────────────────────────────
// examples/cross-file/config.rs — Sources
//
// This module reads untrusted data from the environment and filesystem.
// Every public function here acts as a **source** — its return value
// carries taint.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  FuncSummary produced by pass 1:                                       │
// │                                                                        │
// │  get_user_command  → source_caps: ALL, sink: 0, sanitizer: 0           │
// │  get_config_path   → source_caps: ALL, sink: 0, sanitizer: 0           │
// │  load_template     → source_caps: ALL, sink: 0, sanitizer: 0           │
// └─────────────────────────────────────────────────────────────────────────┘
// ─────────────────────────────────────────────────────────────────────────────

use std::env;
use std::fs;

/// Reads a user-supplied command from the environment.
/// Taint: SOURCE(ALL) — caller must sanitise before passing to any sink.
pub fn get_user_command() -> String {
    env::var("USER_CMD").unwrap_or_default()
}

/// Reads a path from the environment.
/// Taint: SOURCE(ALL)
pub fn get_config_path() -> String {
    env::var("CONFIG_PATH").unwrap_or_default()
}

/// Reads an HTML template from disk (path is trusted, *content* is not).
/// Taint: SOURCE(ALL)
pub fn load_template(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}
