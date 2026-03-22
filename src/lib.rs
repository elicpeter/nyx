//! # Nyx Scanner
//!
//! A multi-language static vulnerability scanner. Nyx parses source files with
//! [tree-sitter](https://tree-sitter.github.io/), builds intra-procedural
//! control-flow graphs ([petgraph](https://docs.rs/petgraph)), and runs
//! cross-file taint analysis with a capability-based sanitizer system.
//!
//! ## Architecture
//!
//! Nyx uses a **two-pass architecture**:
//!
//! 1. **Pass 1 — Summary extraction**: Parse each file, build a CFG per function,
//!    and export a [`summary::FuncSummary`] capturing source/sanitizer/sink capabilities,
//!    taint propagation behavior, and callee lists. Summaries are persisted to SQLite.
//!
//! 2. **Pass 2 — Analysis**: Load all summaries into a [`summary::GlobalSummaries`] map,
//!    re-parse files, and run taint analysis with cross-file callee resolution. CFG
//!    structural analysis checks for auth gaps, unguarded sinks, and resource leaks.
//!
//! ## Four Detector Families
//!
//! - **Taint** ([`taint`]) — Monotone forward dataflow tracking source-to-sink flows
//! - **CFG Structural** ([`cfg_analysis`]) — Dominator-based guard and auth-gap detection
//! - **State Model** ([`state`]) — Resource lifecycle and authentication state lattices
//! - **AST Patterns** ([`patterns`]) — Tree-sitter structural queries per language
//!
//! ## Supported Languages
//!
//! Rust, C, C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript.
//!
//! ## Entry Points
//!
//! - [`scan_no_index`] — Run a two-pass scan without indexing (for tests)
//! - [`commands::scan::scan_filesystem`] — Filesystem scan with optional indexing
//! - [`commands::scan::scan_with_index_parallel`] — Index-backed parallel scan
//!
//! ## Documentation
//!
//! See the [`docs/`](https://github.com/elicpeter/nyx/tree/master/docs) directory
//! for user and contributor documentation.

pub mod ast;
pub mod callgraph;
pub mod cfg;
pub mod cfg_analysis;
pub(crate) mod cli;
pub mod commands;
pub mod database;
pub mod errors;
pub mod evidence;
pub mod fmt;
pub mod interop;
pub mod labels;
pub mod output;
pub mod patterns;
pub mod rank;
pub mod ssa;
pub mod state;
pub mod summary;
pub mod suppress;
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
    commands::scan::scan_filesystem(root, cfg, false)
}
