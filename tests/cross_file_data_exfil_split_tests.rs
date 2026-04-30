//! Integration test for cross-file `param_to_gate_filters` propagation.
//!
//! A wrapper function whose two parameters target distinct gated-sink
//! classes on a single inner call (here, `fetch`'s SSRF gate on the URL
//! arg vs the DATA_EXFIL gate on the body arg) must keep cap attribution
//! per-position when callers reach it across a file boundary.  Without
//! [`SsaFuncSummary::param_to_gate_filters`], the wrapper's summary
//! collapses both params into a single `SSRF | DATA_EXFIL` mask, and
//! every caller incorrectly fires both classes regardless of which
//! argument was tainted.
//!
//! The fixture pairs the wrapper with two callers, each tainting one
//! parameter and asserting only the cap class corresponding to that
//! parameter's gate fires.

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
fn cross_file_data_exfil_split() {
    let dir = fixture_path("cross_file_data_exfil_split");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
