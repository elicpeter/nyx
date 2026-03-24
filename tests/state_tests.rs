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
    let mut cfg = common::test_config(AnalysisMode::Full);
    cfg.scanner.enable_state_analysis = false;
    let diags =
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed");
    let state: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with("state-"))
        .collect();
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
            d.id == "state-resource-leak" && d.message.as_deref().unwrap_or("").contains("f1")
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

// ═══════════════════════════════════════════════════════════════════════
// (7) Python resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn python_file_leak() {
    assert_has_prefix("python_file_open_no_close.py", "state-resource-leak");
}

#[test]
fn python_file_clean() {
    assert_no_state_findings("python_file_open_close.py");
}

#[test]
fn python_double_close() {
    assert_has("python_double_close.py", "state-double-close");
}

#[test]
fn python_use_after_close() {
    assert_has("python_use_after_close.py", "state-use-after-close");
}

#[test]
fn python_with_statement_suppressed() {
    // Python `with` context manager guarantees cleanup via __exit__.
    // The managed_resource flag on the acquire node suppresses false leaks.
    assert_no_state_findings("python_with_statement.py");
}

#[test]
fn python_with_nested_safe_and_leak() {
    let findings = state_diags_for("python_with_nested.py");
    let leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak"))
        .collect();
    // The bare open() in outside_leak should still produce a leak.
    assert!(!leaks.is_empty(), "Expected leak for bare open()");
    // with-block resources should not appear in leak findings.
    for leak in &leaks {
        let msg = leak.message.as_deref().unwrap_or("");
        assert!(
            !msg.contains("reader") && !msg.contains("writer"),
            "with-block resources should be suppressed, got: {msg}",
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// (8) JavaScript resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn js_fs_open_no_close() {
    assert_has_prefix("js_fs_open_no_close.js", "state-resource-leak");
}

#[test]
fn js_fs_open_close() {
    assert_no_state_findings("js_fs_open_close.js");
}

// ═══════════════════════════════════════════════════════════════════════
// (8b) Java resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_twr_no_false_leak() {
    // Java try-with-resources guarantees AutoCloseable.close() is called.
    // The managed_resource flag on the acquire node suppresses false leaks.
    // Note: the state engine does not currently recognise Java constructor
    // callees (e.g. "FileInputStream") against the resource pair patterns
    // (which use "new FileInputStream"), so manual opens also don't fire.
    // This test locks down that TWR resources produce zero false positives.
    let findings = state_diags_for("java_try_with_resources.java");
    let leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak"))
        .collect();
    assert!(
        leaks.is_empty(),
        "Expected zero resource-leak findings in TWR fixture, got: {:?}",
        leaks.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (8c) Go resource lifecycle — defer
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn go_defer_close_no_findings() {
    // Go `defer f.Close()` guarantees cleanup at function exit.
    // Should produce zero state findings (no use-after-close, no leak).
    assert_no_state_findings("go_defer_close.go");
}

#[test]
fn go_defer_missing_leak() {
    // No close at all — should produce resource leak.
    assert_has_prefix("go_defer_missing.go", "state-resource-leak");
}

#[test]
fn go_no_defer_manual_close_clean() {
    // Manual close at end of function — no leak.
    assert_no_state_findings("go_no_defer_manual_close.go");
}

// ═══════════════════════════════════════════════════════════════════════
// (9) Auth — unauthed access detection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn auth_unprotected_handler_fires() {
    assert_has("auth_unprotected_handler.js", "state-unauthed-access");
}

#[test]
fn auth_protected_handler_clean() {
    assert_absent("auth_protected_handler.js", "state-unauthed-access");
}

#[test]
fn auth_not_a_handler_no_finding() {
    // process_data() is not a web handler (process_* demoted to weak,
    // param "batch" is not a web param).
    assert_no_state_findings("auth_not_a_handler.py");
}

#[test]
fn auth_negated_condition_does_not_elevate() {
    // if (!is_authenticated) { exec(...) } — negated condition.
    // True branch is the unauthenticated path; auth must NOT be elevated.
    assert_has("auth_negated_condition.js", "state-unauthed-access");
}

#[test]
fn auth_main_not_handler() {
    // main() is explicitly excluded from web entrypoint detection.
    assert_no_state_findings("auth_main_not_handler.js");
}

#[test]
fn auth_api_version_not_handler() {
    // api_version_string() matches api_* but has no web params (demoted
    // from strong name). No privileged sink either.
    assert_no_state_findings("auth_api_version_not_handler.js");
}

#[test]
fn auth_substring_in_condition_no_false_elevate() {
    // "not_is_authenticated_cache" must NOT match "is_authenticated".
    // Handler + sink + no real auth = finding fires (regression lock).
    assert_has("auth_substring_false_match.js", "state-unauthed-access");
}
