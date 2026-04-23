//! Phase 12.6 fixture coverage.
//!
//! * `large_switch_go` — Go switch with 6+ mutually exclusive cases
//!   dispatching to distinct sinks. Exercises multi-case taint flow;
//!   succeeds regardless of whether SSA lowering emits
//!   `Terminator::Switch` or the legacy cascade of `Branch` headers.
//!
//! * `switch_fall_through_c` — C switch with explicit fall-through,
//!   regression-guarding the cascade-preserving lowering for languages
//!   whose switch semantics allow cases to be non-exclusive.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn large_switch_go() {
    let dir = fixture_path("large_switch_go");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn switch_fall_through_c() {
    let dir = fixture_path("switch_fall_through_c");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
