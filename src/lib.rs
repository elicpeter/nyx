// Re-exports for benchmarks and integration tests.
// The binary crate (main.rs) is the primary entry point; this lib target
// exposes internals for criterion and other tooling.

pub mod ast;
pub mod cfg;
pub mod cfg_analysis;
pub(crate) mod cli;
pub mod commands;
pub mod database;
pub mod errors;
pub mod interop;
pub mod labels;
pub mod patterns;
pub mod summary;
pub mod symbol;
pub mod taint;
pub mod utils;
pub mod walk;

use errors::NyxResult;
use std::path::Path;
use utils::config::Config;

/// Run a two-pass scan without index (filesystem only).
/// This is the primary entry point for integration tests.
pub fn scan_no_index(root: &Path, cfg: &Config) -> NyxResult<Vec<commands::scan::Diag>> {
    commands::scan::scan_filesystem(root, cfg)
}
