mod common;

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;
use std::sync::OnceLock;

fn auth_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("auth_analysis")
}

fn scan_all_fixtures() -> &'static Vec<Diag> {
    static DIAGS: OnceLock<Vec<Diag>> = OnceLock::new();
    DIAGS.get_or_init(|| {
        let cfg = common::test_config(AnalysisMode::Full);
        nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed")
    })
}

fn auth_diags_for(filename: &str) -> Vec<&'static Diag> {
    scan_all_fixtures()
        .iter()
        .filter(|d| d.path.contains(filename) && d.id.starts_with("js.auth."))
        .collect()
}

fn auth_ids_for(filename: &str) -> Vec<String> {
    auth_diags_for(filename)
        .iter()
        .map(|diag| diag.id.clone())
        .collect()
}

fn assert_has(filename: &str, rule_id: &str) {
    assert!(
        auth_diags_for(filename)
            .iter()
            .any(|diag| diag.id == rule_id),
        "Expected {rule_id} in {filename}.\n  Got: {:?}",
        auth_ids_for(filename)
    );
}

fn assert_absent(filename: &str, rule_id: &str) {
    assert!(
        auth_diags_for(filename)
            .iter()
            .all(|diag| diag.id != rule_id),
        "Did not expect {rule_id} in {filename}.\n  Got: {:?}",
        auth_ids_for(filename)
    );
}

#[test]
fn admin_route_missing_admin_check() {
    assert_has(
        "admin_route_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "admin_route_clean.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn support_impersonation_requires_admin_guard() {
    assert_has(
        "support_impersonation_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn debug_session_requires_admin_guard() {
    assert_has(
        "debug_session_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn scoped_read_without_membership_check() {
    assert_has("scoped_read_missing.js", "js.auth.missing_ownership_check");
}

#[test]
fn scoped_write_without_membership_check() {
    assert_has("scoped_write_missing.js", "js.auth.missing_ownership_check");
}

#[test]
fn self_profile_read_is_clean() {
    assert_absent("self_profile_read.js", "js.auth.missing_ownership_check");
}

#[test]
fn self_profile_update_is_clean() {
    assert_absent("self_profile_update.js", "js.auth.missing_ownership_check");
    assert_absent("self_profile_update.js", "js.auth.stale_authorization");
}

#[test]
fn current_user_listing_is_clean() {
    assert_absent(
        "dashboard_self_listing.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn auth_helper_lookup_is_clean() {
    assert_absent("membership_helper.js", "js.auth.missing_ownership_check");
}

#[test]
fn delegated_service_read_is_clean() {
    assert_absent(
        "delegated_service_read.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn related_membership_check_covers_child_reads() {
    assert_absent(
        "related_membership_check.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn workspace_job_body_id_without_check() {
    assert_has(
        "workspace_job_missing.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn service_function_without_auth_context_or_check() {
    assert_has(
        "service_missing_context.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn service_function_with_ownership_check_is_clean() {
    assert_absent("service_with_check.js", "js.auth.missing_ownership_check");
}

#[test]
fn stale_session_backed_mutation() {
    assert_has("stale_session_mutation.js", "js.auth.stale_authorization");
}

#[test]
fn partial_batch_authorization_detected() {
    assert_has("partial_batch.js", "js.auth.partial_batch_authorization");
}

#[test]
fn token_flow_missing_expiry_check() {
    assert_has(
        "token_missing_expiry.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn token_flow_missing_recipient_check() {
    assert_has(
        "token_missing_recipient.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn token_flow_workspace_override_detected() {
    assert_has(
        "token_workspace_override.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn token_flow_role_override_detected() {
    assert_has(
        "token_role_override.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn clean_token_acceptance_is_clean() {
    assert_absent(
        "token_clean.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn auth_analysis_runs_in_ast_mode() {
    let cfg = common::test_config(AnalysisMode::Ast);
    let diags = nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed");
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("scoped_write_missing.js")
                && diag.id == "js.auth.missing_ownership_check"
        }),
        "expected AST mode to emit js.auth findings"
    );
}

#[test]
fn auth_analysis_does_not_run_in_cfg_mode() {
    let cfg = common::test_config(AnalysisMode::Cfg);
    let diags = nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed");
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("js.auth.")),
        "CFG mode should not emit js.auth findings"
    );
}
