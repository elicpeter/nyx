//! Integration tests for per-parameter [`AbstractTransfer`] channels
//! propagating abstract facts across cross-file calls.
//!
//! Three fixtures cover the documented transfer forms currently tractable
//! against the JS/Python abstract-suppression pipelines:
//!
//! * `cross_file_abstract_port_range` (Python), Identity transfer on an
//!   integer-typed passthrough.  The caller's literal `8080` crosses the
//!   file boundary and SHELL_ESCAPE suppression fires on the bounded int.
//! * `cross_file_abstract_bounded_index` (Python), Clamped transfer
//!   derived from a baseline-invariant fact.  The callee returns a
//!   literal `42`; the per-parameter transfer attaches it as
//!   `Clamped { 42, 42 }` and the caller sees a bounded integer
//!   without the return-abstract channel alone carrying the fact
//!   through summary resolution ambiguity.
//! * `cross_file_abstract_url_prefix_lock` (JS), String-prefix transfer
//!   across an Identity wrapper.  The caller writes
//!   `url = asIs('https://internal/...' + userPath)` and passes `url` to
//!   `axios.get`.  The CFG node's `string_prefix` is consumed by the
//!   abstract transfer's Call-with-prefix arm; the resulting StringFact
//!   prefix locks the host and SSRF suppression fires.
//!
//! Each fixture's `expectations.json` treats the cross-file SHELL/SSRF
//! sink as *forbidden* on the main file, if cross-file abstract
//! propagation regresses, the sink fires and the forbidden-finding
//! assertion trips.

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

#[test]
fn cross_file_abstract_url_prefix_lock() {
    let dir = fixture_path("cross_file_abstract_url_prefix_lock");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
