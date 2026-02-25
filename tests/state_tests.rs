mod common;

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::PathBuf;
use std::sync::OnceLock;

fn state_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("state")
}

fn state_config() -> Config {
    let mut cfg = common::test_config(AnalysisMode::Full);
    cfg.scanner.enable_state_analysis = true;
    cfg
}

/// Scan the fixtures directory once and cache the result for all tests.
/// Every test in this module filters the shared result by filename.
fn scan_all_fixtures() -> &'static Vec<Diag> {
    static DIAGS: OnceLock<Vec<Diag>> = OnceLock::new();
    DIAGS.get_or_init(|| {
        let cfg = state_config();
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed")
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn state_diags_for(filename: &str) -> Vec<&'static Diag> {
    scan_all_fixtures()
        .iter()
        .filter(|d| d.path.contains(filename) && d.id.starts_with("state-"))
        .collect()
}

fn state_ids_for(filename: &str) -> Vec<String> {
    state_diags_for(filename)
        .iter()
        .map(|d| d.id.clone())
        .collect()
}

fn has_rule(filename: &str, rule_id: &str) -> bool {
    state_diags_for(filename).iter().any(|d| d.id == rule_id)
}

fn has_rule_prefix(filename: &str, prefix: &str) -> bool {
    state_diags_for(filename)
        .iter()
        .any(|d| d.id.starts_with(prefix))
}

fn assert_has(filename: &str, rule_id: &str) {
    assert!(
        has_rule(filename, rule_id),
        "Expected {rule_id} in {filename}.\n  Got: {:?}",
        state_ids_for(filename)
    );
}

fn assert_has_prefix(filename: &str, prefix: &str) {
    assert!(
        has_rule_prefix(filename, prefix),
        "Expected finding starting with `{prefix}` in {filename}.\n  Got: {:?}",
        state_ids_for(filename)
    );
}

fn assert_absent(filename: &str, rule_id: &str) {
    assert!(
        !has_rule(filename, rule_id),
        "Did NOT expect {rule_id} in {filename}.\n  Got: {:?}",
        state_ids_for(filename)
    );
}

fn assert_no_state_findings(filename: &str) {
    let found = state_ids_for(filename);
    assert!(
        found.is_empty(),
        "Expected zero state findings in {filename}.\n  Got: {:?}",
        found
    );
}

fn assert_message_contains(filename: &str, rule_id: &str, substr: &str) {
    let matching: Vec<_> = state_diags_for(filename)
        .into_iter()
        .filter(|d| d.id == rule_id)
        .collect();
    assert!(
        matching
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains(substr)),
        "Expected {rule_id} in {filename} with message containing `{substr}`.\n  Messages: {:?}",
        matching
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Original basic tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn detects_use_after_close() {
    assert_has("use_after_close.c", "state-use-after-close");
}

#[test]
fn detects_double_close() {
    assert_has("double_close.c", "state-double-close");
}

#[test]
fn detects_resource_leak() {
    assert_has_prefix("resource_leak.c", "state-resource-leak");
}

#[test]
fn clean_usage_no_state_findings() {
    assert_no_state_findings("clean.c");
}

#[test]
fn state_analysis_off_by_default() {
    let cfg = common::test_config(AnalysisMode::Full);
    let diags =
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed");
    let state: Vec<_> = diags.iter().filter(|d| d.id.starts_with("state-")).collect();
    assert!(
        state.is_empty(),
        "State findings should not appear when enable_state_analysis is false.\n  Got: {:?}",
        state.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (1) May-leak vs must-leak (branch semantics)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn may_leak_branch_emits_possible_not_definite() {
    // Only the true branch closes → OPEN|CLOSED at exit → may-leak.
    assert_has("may_leak_branch.c", "state-resource-leak-possible");
    assert_absent("may_leak_branch.c", "state-resource-leak");
}

#[test]
fn early_return_may_leak() {
    // Early return leaks; normal path closes → OPEN|CLOSED at exit → may-leak.
    assert_has("early_return_may_leak.c", "state-resource-leak-possible");
    assert_absent("early_return_may_leak.c", "state-resource-leak");
}

#[test]
fn nested_branch_may_leak() {
    // Only innermost branch closes → OPEN|CLOSED at exit → may-leak.
    assert_has("nested_branch_leak.c", "state-resource-leak-possible");
    assert_absent("nested_branch_leak.c", "state-resource-leak");
}

#[test]
fn both_branches_close_no_leak() {
    // Both branches close f → CLOSED at exit → no leak.
    assert_no_state_findings("both_branches_close.c");
}

// ═══════════════════════════════════════════════════════════════════════
// (2) Loop / back-edge convergence
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn loop_clean_converges_no_findings() {
    // Open → loop { read } → close.  Back-edge should not prevent convergence.
    assert_no_state_findings("loop_clean.c");
}

#[test]
fn loop_use_after_close() {
    // Close before loop → read inside loop on converged CLOSED state.
    assert_has("loop_use_after_close.c", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (3) Handle reassignment / overwrite semantics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn handle_overwrite_silent_per_variable() {
    // f = fopen("a"); f = fopen("b"); fclose(f).
    // The first handle leaks silently because per-variable tracking
    // overwrites the old state.  No findings because at exit f = CLOSED.
    assert_no_state_findings("handle_overwrite.c");
}

#[test]
fn reopen_after_close_is_clean() {
    // fopen → fclose → fopen → fclose.  Each lifecycle is independent.
    assert_no_state_findings("reopen_after_close.c");
}

#[test]
fn multiple_handles_leaks_only_unclosed() {
    // f1 closed, f2 leaked.
    assert_has("multiple_handles.c", "state-resource-leak");
    assert_message_contains("multiple_handles.c", "state-resource-leak", "f2");
    // Must NOT blame f1.
    let f1_findings: Vec<_> = state_diags_for("multiple_handles.c")
        .into_iter()
        .filter(|d| {
            d.id == "state-resource-leak"
                && d.message.as_deref().unwrap_or("").contains("f1")
        })
        .collect();
    assert!(
        f1_findings.is_empty(),
        "f1 is properly closed — should not be reported as leaked.\n  Got: {:?}",
        f1_findings
            .iter()
            .map(|d| d.message.as_deref().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (4) Conservative join behaviour (branch masks path-specific bugs)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn double_close_branch_conservative_no_event() {
    // if (cond) fclose(f); fclose(f);
    // True path is double-close, false path is single-close.
    // Joined state at the second fclose is OPEN|CLOSED → NOT CLOSED-only.
    // Engine correctly refuses to flag when it's ambiguous.
    assert_absent("double_close_branch.c", "state-double-close");
}

#[test]
fn use_closed_branch_conservative_no_event() {
    // if (cond) fclose(f); fread(f);
    // True path is use-after-close, false path is clean use.
    // Joined state at fread is OPEN|CLOSED → NOT CLOSED-only.
    assert_absent("use_closed_branch.c", "state-use-after-close");
    // However, the false path never closes → may-leak at exit.
    assert_has("use_closed_branch.c", "state-resource-leak-possible");
}

// ═══════════════════════════════════════════════════════════════════════
// (5) Additional edge cases
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn chain_ops_clean() {
    // fopen → fread → fwrite → fread → fclose.  Multiple uses do not
    // corrupt lifecycle state.
    assert_no_state_findings("chain_ops.c");
}

#[test]
fn malloc_free_clean() {
    // Tests the memory resource pair (malloc→free).
    assert_no_state_findings("malloc_free_clean.c");
}

#[test]
fn malloc_leak() {
    // malloc without free.
    assert_has("malloc_leak.c", "state-resource-leak");
}

#[test]
fn double_close_straight_fires() {
    // Straight-line fclose → fclose (no branching). Converged state is
    // definitely CLOSED at the second fclose.
    assert_has("double_close_straight.c", "state-double-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (6) Cross-cutting: message field populated
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn findings_carry_messages() {
    // Every state finding should have a non-empty message.
    for d in scan_all_fixtures() {
        if d.id.starts_with("state-") {
            assert!(
                d.message.as_ref().is_some_and(|m| !m.is_empty()),
                "State finding {} at {}:{} has no message",
                d.id,
                d.path,
                d.line
            );
        }
    }
}
