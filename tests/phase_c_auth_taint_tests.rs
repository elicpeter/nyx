//! Phase C — auth-as-taint integration tests.
//!
//! Verifies the end-to-end flow of `Cap::UNAUTHORIZED_ID` folded into the
//! SSA/taint engine:
//!
//! * a request-bound handler parameter is tainted with `UNAUTHORIZED_ID`,
//! * a `realtime::publish_to_group` call is a Phase C sink requiring that cap,
//! * an `authz::require_group_member(...)?` call is a Phase C sanitizer that
//!   strips the cap from its argument SSA values.
//!
//! The feature is gated by `config.scanner.enable_auth_as_taint`; these
//! tests flip the flag on explicitly so the rest of the test suite continues
//! to exercise the baseline (flag-off) behaviour.

mod common;

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("phase_c_auth_taint")
}

fn phase_c_config() -> Config {
    let mut cfg = common::test_config(AnalysisMode::Full);
    cfg.scanner.enable_auth_as_taint = true;
    cfg
}

fn scan_with_phase_c() -> Vec<Diag> {
    let cfg = phase_c_config();
    nyx_scanner::scan_no_index(&fixture_dir(), &cfg).expect("scan should succeed")
}

fn diags_for(diags: &[Diag], filename: &str) -> Vec<Diag> {
    diags
        .iter()
        .filter(|d| d.path.contains(filename))
        .cloned()
        .collect()
}

#[test]
fn phase_c_flag_off_emits_no_auth_taint_finding() {
    // Baseline: flag default (off) — no `rs.auth.missing_ownership_check.taint`
    // diag should appear.  This guards against the Phase C rules leaking when
    // the flag is not flipped.
    let cfg = common::test_config(AnalysisMode::Full);
    let diags = nyx_scanner::scan_no_index(&fixture_dir(), &cfg).expect("scan");
    let auth_taint = diags
        .iter()
        .filter(|d| d.id == "rs.auth.missing_ownership_check.taint")
        .count();
    assert_eq!(
        auth_taint, 0,
        "flag-off scan must not emit auth-taint rule; got {auth_taint} diags",
    );
}

#[test]
fn phase_c_unsanitized_handler_emits_auth_taint_finding() {
    let diags = scan_with_phase_c();
    let file_diags = diags_for(&diags, "handler_unsanitized.rs");
    let has_auth_taint = file_diags
        .iter()
        .any(|d| d.id == "rs.auth.missing_ownership_check.taint");
    assert!(
        has_auth_taint,
        "expected rs.auth.missing_ownership_check.taint on handler_unsanitized.rs; \
         got: {:#?}",
        file_diags.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

#[test]
fn phase_c_sanitized_handler_suppresses_auth_taint_finding() {
    let diags = scan_with_phase_c();
    let file_diags = diags_for(&diags, "handler_sanitized.rs");
    let has_auth_taint = file_diags
        .iter()
        .any(|d| d.id == "rs.auth.missing_ownership_check.taint");
    assert!(
        !has_auth_taint,
        "expected NO rs.auth.missing_ownership_check.taint on handler_sanitized.rs \
         (the authz::require_group_member call should strip UNAUTHORIZED_ID); \
         got: {:#?}",
        file_diags.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}
