//! Phase CF-3 integration tests: per-parameter [`AbstractTransfer`]
//! channels propagate abstract facts across cross-file calls.
//!
//! Two fixtures cover the documented transfer forms currently tractable
//! against the existing JS/Python abstract-suppression pipelines:
//!
//! * `cross_file_abstract_port_range` (Python) — Identity transfer on an
//!   integer-typed passthrough.  The caller's literal `8080` crosses the
//!   file boundary and SHELL_ESCAPE suppression fires on the bounded int.
//! * `cross_file_abstract_bounded_index` (Python) — Clamped transfer
//!   derived from a baseline-invariant fact.  The callee returns a
//!   literal `42`; CF-3 attaches it as `Clamped { 42, 42 }` and the
//!   caller sees a bounded integer without Phase 17's return-abstract
//!   alone carrying the fact through summary resolution ambiguity.
//!
//! A JS string-prefix fixture (`url_prefix_lock`) was intentionally held
//! back while auditing the non-CF-3 pass-divergence issue documented in
//! `memory/project_cf3_suppression_quirks.md` — the suppression
//! downstream of CF-3 drops a prefix-locked URL across the JS two-pass
//! lowering even in the single-file literal-prefix case.  The unit-level
//! coverage in `tests/abstract_transfer_tests.rs` verifies that the CF-3
//! Identity detection and transfer-apply primitives are correct; the
//! fixture will come back once the JS pipeline is sound.
//!
//! Each fixture's `expectations.json` treats the cross-file SHELL sink
//! as *forbidden* on the main file — if CF-3 regresses, the sink fires
//! and the forbidden-finding assertion trips.

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
fn cross_file_abstract_port_range() {
    let dir = fixture_path("cross_file_abstract_port_range");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_abstract_bounded_index() {
    let dir = fixture_path("cross_file_abstract_bounded_index");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
