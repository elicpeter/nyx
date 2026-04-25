//! Regression coverage: closure capture, async/await, and
//! container-element taint fixtures.
//!
//! Each fixture either asserts the intended taint finding (where the
//! engine handles the pattern today) or codifies current behaviour
//! via `forbidden_findings` with a companion README.md explaining the
//! gap.  The latter form guarantees that an engine improvement which
//! starts producing the finding will force whoever lands it to come
//! here and update the expectations.
//!
//! Fixture layout:
//!   * closure capture —
//!     - `closure_capture_py` (required)
//!     - `closure_capture_js` (known gap)
//!     - `closure_capture_ts` (known gap)
//!   * async/await —
//!     - `async_python` (required)
//!     - `async_rust`   (required — Tokio process coverage)
//!     - `async_promise_chain_js` (known gap)
//!   * container-element taint —
//!     - `container_taint_py` (required)
//!     - `container_taint_js` (required)
//!
//! Edit-and-rescan parity is already guarded by
//! `tests/incremental_index_tests.rs`.  That file intentionally lives
//! separately because it drives an SQLite-backed incremental scan
//! rather than `scan_no_index`.

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

// ── 8.1 closure capture ─────────────────────────────────────────────────────

#[test]
fn closure_capture_py() {
    let dir = fixture_path("closure_capture_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// See README.md — current behaviour is zero findings; expectation is
/// codified as a `forbidden_findings` entry so a future improvement
/// forces an expectation update.
#[test]
fn closure_capture_js() {
    let dir = fixture_path("closure_capture_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// See README.md — current behaviour is zero findings (parallels the
/// JS sibling).  The TS fixture is separately regression-guarded so
/// the TypeScript grammar path does not silently diverge when the JS
/// gap is eventually closed.
#[test]
fn closure_capture_ts() {
    let dir = fixture_path("closure_capture_ts");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── 8.2 async/await ─────────────────────────────────────────────────────────

#[test]
fn async_python() {
    let dir = fixture_path("async_python");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn async_rust() {
    let dir = fixture_path("async_rust");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// See README.md — taint across chained `.then` callbacks is not
/// modelled today.  The `forbidden_findings` entry pins current
/// behaviour; a future promise-resolution improvement must flip the
/// expectation.
#[test]
fn async_promise_chain_js() {
    let dir = fixture_path("async_promise_chain_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── 8.3 container-element taint ─────────────────────────────────────────────

#[test]
fn container_taint_py() {
    let dir = fixture_path("container_taint_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn container_taint_js() {
    let dir = fixture_path("container_taint_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
