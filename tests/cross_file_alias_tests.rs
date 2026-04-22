//! Integration tests for parameter-granularity points-to summaries:
//! they carry alias information across file boundaries, closing
//! cross-file taint flows that travel through shared-object mutation
//! rather than through return values.
//!
//! Three fixtures cover distinct structural shapes of the summary
//! channel:
//!
//! * `cross_file_alias_mutating_helper` (Java) — a void-returning
//!   helper that stores its second argument into a field of its first
//!   argument.  Without the points-to channel the cross-file summary
//!   loses every taint edge (void return, no container-op in
//!   pointsto.rs).  With it the helper emits a `Param(1) → Param(0)`
//!   edge and the caller observes the field write through the argument
//!   alias, producing a Runtime.exec finding.
//!
//! * `cross_file_alias_returned_alias` (JS) — a passthrough helper
//!   whose return aliases its first parameter.  `param_to_return` with
//!   `Identity` already covered the taint cap; the points-to channel
//!   adds the heap-identity alias `Param(0) → Return` so the caller
//!   threads the points-to set through the call.  The existing
//!   shell-exec sink must still fire — a regression guard on the
//!   return-alias channel.
//!
//! * `cross_file_alias_bounded_graph` (Python) — a helper with a 20-
//!   edge alias graph that intentionally overflows `MAX_ALIAS_EDGES`.
//!   The assertion is that the scan *terminates* under the bounded
//!   analysis and falls back to the conservative
//!   `PointsToSummary::overflow` behaviour, not a specific finding
//!   count — overflow is an operational guarantee, not a precision one.

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
fn cross_file_alias_mutating_helper() {
    let dir = fixture_path("cross_file_alias_mutating_helper");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_alias_returned_alias() {
    let dir = fixture_path("cross_file_alias_returned_alias");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_alias_bounded_graph() {
    let dir = fixture_path("cross_file_alias_bounded_graph");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
