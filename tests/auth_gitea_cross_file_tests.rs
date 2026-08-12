//! Gitea `web.Router` cross-file route→handler authorization lift.
//!
//! Gitea registers handlers cross-package
//! (`r.Get(path, container.GetBlobsUpload)`) inside closure groups whose
//! trailing ownership-guard middleware (`reqPackageAccess`) is colocated
//! with the registration in `routers/api.go`.  The handler unit lives in
//! `container/container.go`, so the same-file `attach_route_handler`
//! injection cannot reach it.
//!
//! `gitea::extract_route_handler_auth_edges` harvests one caller-scope
//! edge per route (keyed by the handler leaf, `caller_authorized` iff the
//! enclosing group is an ownership guard); the existing cross-file
//! caller-scope plumbing folds these into `GlobalSummaries` and
//! `apply_cross_file_caller_scope` lifts the route-level `Ownership`
//! check onto the (other-file) handler unit.
//!
//! Recall guard: `public.ListByID` is registered under a BARE group (no
//! ownership middleware), so its edge is unauthorized, the lift is
//! refused, and `missing_ownership_check` must still fire.

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
fn gitea_cross_file_lifts_ownership_guard_onto_other_file_handler() {
    let dir = fixture_path("auth_analysis_gitea_cross_file");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn gitea_cross_file_clears_guarded_handler_keeps_unguarded() {
    let dir = fixture_path("auth_analysis_gitea_cross_file");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Guarded side: container.GetBlobsUpload reached only through the
    // reqPackageAccess ownership group must be clean.
    let guarded_hits: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.path.ends_with("container/container.go") && d.id == "go.auth.missing_ownership_check"
        })
        .collect();
    assert!(
        guarded_hits.is_empty(),
        "guarded cross-file handler must be authorized by the lift, got: {guarded_hits:?}"
    );

    // Unguarded side: public.ListByID under a bare group must still fire.
    let unguarded_hits: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.path.ends_with("public/public.go") && d.id == "go.auth.missing_ownership_check"
        })
        .collect();
    assert!(
        !unguarded_hits.is_empty(),
        "unguarded cross-file handler must still fire missing_ownership_check"
    );
}
