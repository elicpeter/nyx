//! Cross-file caller-scope IPA (Phase 2 of the caller-scope fix).
//!
//! Distilled from the sentry / saleor / airflow `route in api/, helper in
//! services/` cross-file delegation shape: an authorized route handler in
//! one file delegates the actual datastore sink to a private helper in
//! another file.
//!
//! Pre-fix: `apply_caller_scope_propagation` is scoped per file, so it
//! refused to lift onto a helper with no in-file caller — every
//! `session.add(...)` in the helper file fired
//! `missing_ownership_check` / `token_override_without_validation`.
//!
//! Post-fix: pass 1 folds per-callee-leaf caller-auth facts into
//! `GlobalSummaries.caller_scope_by_callee` (every caller across the
//! index must be an authorized route handler); pass 2's
//! `apply_cross_file_caller_scope` lifts the route-level checks onto the
//! helper.
//!
//! Recall guard: `services/dag_run_ops.py` is reached only from the
//! UNauthorized `purge_dag_run` route (bare `APIRouter()`), so the
//! accumulator's `all_authorized` conjunction is false, the lift is
//! refused, and `missing_ownership_check` must still fire.  Without this
//! guard, an over-broad cross-file lift would silently suppress real
//! findings.

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
fn cross_file_caller_scope_lifts_route_auth_onto_private_helper() {
    let dir = fixture_path("auth_analysis_cross_file_caller_scope");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_caller_scope_clears_authorized_helper_but_keeps_unauthorized() {
    let dir = fixture_path("auth_analysis_cross_file_caller_scope");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Safe side: the helper reached only from the authorized route must
    // be clean of both auth findings.
    let safe_hits: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.path.ends_with("services/state.py")
                && (d.id == "py.auth.missing_ownership_check"
                    || d.id == "py.auth.token_override_without_validation")
        })
        .collect();
    assert!(
        safe_hits.is_empty(),
        "cross-file caller-scope must lift route auth onto services/state.py, \
         but found: {safe_hits:#?}"
    );

    // Recall side: the helper reached only from the UNauthorized route
    // must still fire.
    let vuln_hits = diags
        .iter()
        .filter(|d| {
            d.path.ends_with("services/dag_run_ops.py") && d.id == "py.auth.missing_ownership_check"
        })
        .count();
    assert!(
        vuln_hits >= 1,
        "recall guard: services/dag_run_ops.py (reached only from an \
         unauthorized route) must still fire missing_ownership_check"
    );
}
