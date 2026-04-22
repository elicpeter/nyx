//! Phase CF-4 integration tests: per-return-path decomposition survives
//! cross-file summary serialisation and application.
//!
//! Three fixtures cover distinct structural shapes of the per-return-path
//! transform:
//!
//! * `cross_file_phi_validated_branch` (Python) — a callee whose two
//!   return branches are both `Identity` on the value, differing only in
//!   the predicate gate.  The required SQLi finding confirms the
//!   summary-application path does not regress on the common "union is
//!   precise enough" case.
//! * `cross_file_phi_partial_sanitiser` (JS) — the callee has two
//!   returns with *different* transforms (Identity vs
//!   StripBits(HTML_ESCAPE)).  The caller invokes the unsanitised branch,
//!   so the XSS sink must still fire — a regression guard against a
//!   per-path application that over-eagerly attributes sanitation across
//!   all branches.
//! * `cross_file_phi_both_branches_safe` (Go) — both return paths run
//!   the same sanitising validator.  The SQL sink is on the forbidden
//!   list: if the per-path decomposition regresses to "either branch
//!   could be raw" the caller would pick up a false positive.
//!
//! The fixtures are *structural* (they exercise the plumbing: extraction,
//! serde, resolution, predicate-consistent application).  Each assertion
//! distinguishes "per-path data survives and is applied" from "summary
//! application silently ignores the new field."

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
fn cross_file_phi_validated_branch() {
    let dir = fixture_path("cross_file_phi_validated_branch");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_phi_partial_sanitiser() {
    let dir = fixture_path("cross_file_phi_partial_sanitiser");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_phi_both_branches_safe() {
    let dir = fixture_path("cross_file_phi_both_branches_safe");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
