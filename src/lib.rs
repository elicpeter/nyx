//! Multi-language static vulnerability scanner. Tree-sitter parsing, petgraph
//! CFGs, SSA-based dataflow, and cross-file taint analysis with a
//! capability-based sanitizer system. Supports Rust, C, C++, Java, Go, PHP,
//! Python, Ruby, TypeScript, and JavaScript.
//!
//! The handbook below is embedded verbatim from
//! [`docs/how-it-works.md`](https://github.com/elicpeter/nyx/blob/master/docs/how-it-works.md).
//! Per-detector documentation lives on the [`taint`], [`cfg_analysis`],
//! [`state`], [`patterns`], and [`auth_analysis`] modules. The primary
//! library entry point for tests and embedders is [`scan_no_index`].
#![doc = include_str!(concat!(env!("OUT_DIR"), "/lib_intro.md"))]

pub mod abstract_interp;
pub mod ast;
pub mod auth_analysis;
pub mod callgraph;
pub mod cfg;
pub mod cfg_analysis;
pub mod cli;
pub mod commands;
pub mod constraint;
pub mod convergence_telemetry;
pub mod database;
pub mod engine_notes;
pub mod errors;
pub mod evidence;
pub mod fmt;
pub mod interop;
pub mod labels;
pub mod output;
pub mod patterns;
pub mod pointer;
pub mod rank;
pub mod rust_resolve;
#[cfg(feature = "serve")]
pub mod server;
pub mod ssa;
pub mod state;
pub mod summary;
pub mod suppress;
pub mod symbol;
pub mod symex;
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
