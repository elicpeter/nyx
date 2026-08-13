//! Integration test for multi-sink-per-param de-masking.
//!
//! A helper whose single parameter flows to two distinct-capability sinks
//! — an SSRF sink (`new HttpGet(url)`, routed to `taint-unsanitised-flow`)
//! and a HEADER_INJECTION sink (`req.addHeader(name, url)`, routed to
//! `taint-header-injection`) — must surface BOTH classes at its callers.
//!
//! Before the fix, the cross-function/cross-file summary unioned both caps
//! into one sink event and the cap->rule routing in `ast.rs` collapsed the
//! union to the single most-specific rule id (`taint-header-injection`),
//! silently MASKING the SSRF flow.  The
//! `collect_block_events` per-cap `filter_iter` split now emits one event
//! per distinct site capability so each flow surfaces under its own rule
//! id and deep sink line.

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
fn multi_sink_param_demask_surfaces_both_classes() {
    let dir = fixture_path("multi_sink_param_demask");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
