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

#[test]
fn js_fs_use_after_close() {
    assert_has("js_fs_use_after_close.js", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (8b) Java resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_twr_no_false_leak() {
    // Java try-with-resources guarantees AutoCloseable.close() is called.
    // The managed_resource flag on the acquire node suppresses false leaks.
    // The fixture also contains unsafeManual() which genuinely leaks —
    // only verify that the TWR function's acquire (line 5) doesn't leak.
    let findings = state_diags_for("java_try_with_resources.java");
    let twr_leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak") && d.line <= 8)
        .collect();
    assert!(
        twr_leaks.is_empty(),
        "Expected zero resource-leak findings in TWR function (lines 1-8), got: {:?}",
        twr_leaks.iter().map(|d| (&d.id, d.line)).collect::<Vec<_>>()
    );
    // unsafeManual (lines 10-13) is a genuine leak — verify it's detected
    assert!(
        findings.iter().any(|d| d.id == "state-resource-leak" && d.line > 8),
        "Expected state-resource-leak for unsafeManual"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (8b-2) Java constructor callee fix (Phase 8)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_file_stream_leak() {
    assert_has_prefix("java_file_stream_leak.java", "state-resource-leak");
}

#[test]
fn java_file_stream_clean() {
    assert_no_state_findings("java_file_stream_clean.java");
}

#[test]
fn java_double_close_constructor() {
    assert_has("java_double_close.java", "state-double-close");
}

#[test]
fn java_db_connection_leak() {
    assert_has_prefix("java_db_connection_leak.java", "state-resource-leak");
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

// ═══════════════════════════════════════════════════════════════════════
// (10) Rust RAII suppression
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rust_raii_file_no_leak() {
    // File::open uses RAII drop — managed_resource suppresses leak.
    assert_no_state_findings("rust_raii_file_no_leak.rs");
}

#[test]
fn rust_box_owned_no_leak() {
    // Box::new owns the value, RAII cleans up.
    assert_no_state_findings("rust_box_owned.rs");
}

#[test]
fn rust_explicit_drop_no_leak() {
    // drop(f) is an explicit release — no leak.
    assert_no_state_findings("rust_explicit_drop.rs");
}

#[test]
fn rust_unsafe_alloc_clean() {
    // alloc + dealloc — properly paired, no findings.
    assert_no_state_findings("rust_unsafe_alloc_clean.rs");
}

#[test]
fn rust_unsafe_alloc_leak() {
    // alloc without dealloc — NOT RAII-managed, leak expected.
    assert_has_prefix("rust_unsafe_alloc_leak.rs", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// (11) C++ new/delete lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cpp_new_leak() {
    // new without delete → leak.
    assert_has_prefix("cpp_new_delete_leak.cpp", "state-resource-leak");
}

#[test]
fn cpp_new_delete_clean() {
    // new + delete → no findings.
    assert_no_state_findings("cpp_new_delete_clean.cpp");
}

#[test]
fn cpp_smart_ptr_no_leak() {
    // make_unique → managed_resource, no leak.
    assert_no_state_findings("cpp_smart_ptr_no_leak.cpp");
}

#[test]
fn cpp_smart_ptr_scope_exit() {
    // make_unique with return — RAII cleanup at scope exit.
    assert_no_state_findings("cpp_smart_ptr_scope_exit.cpp");
}

#[test]
fn cpp_unique_ptr_from_raw() {
    // unique_ptr(new int(42)) — the constructor wraps a raw new.
    // The unique_ptr constructor is not a tracked acquire, so no leak
    // from the outer call.  The inner `new` might or might not be visible
    // depending on callee extraction depth.  At minimum: no false alarm.
    let findings = state_diags_for("cpp_unique_ptr_from_raw.cpp");
    let leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak"))
        .collect();
    // We accept zero or one leak finding.  If the inner `new` is
    // extracted, a leak is tolerable (the engine cannot see the
    // unique_ptr ownership wrapper).  No double-count or crash.
    assert!(
        leaks.len() <= 1,
        "Expected at most 1 leak finding, got {:?}",
        leaks.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

#[test]
fn cpp_alias_before_delete() {
    // p = new; q = p; delete q — tests ownership transfer semantics.
    // The assignment transfer moves lifecycle from p to q.
    // After delete q, the resource is closed.
    // At exit: q = CLOSED, p = MOVED → no leak.
    let findings = state_diags_for("cpp_alias_before_delete.cpp");
    // Should not produce a definite leak for p (it was moved to q).
    let definite_leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id == "state-resource-leak")
        .collect();
    assert!(
        definite_leaks.is_empty(),
        "Alias-then-delete should not produce definite leak, got {:?}",
        definite_leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

#[test]
fn cpp_new_double_delete() {
    // new + delete + delete → double-close.
    assert_has("cpp_new_double_delete.cpp", "state-double-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (12) PHP resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn php_fopen_leak() {
    assert_has_prefix("php_fopen_no_close.php", "state-resource-leak");
}

#[test]
fn php_fopen_close() {
    assert_no_state_findings("php_fopen_close.php");
}

// ═══════════════════════════════════════════════════════════════════════
// (12b) PHP OOP constructor fix (Phase 8)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn php_mysqli_leak() {
    assert_has_prefix("php_mysqli_leak.php", "state-resource-leak");
}

#[test]
fn php_mysqli_clean() {
    assert_no_state_findings("php_mysqli_clean.php");
}

#[test]
fn php_curl_use_after_close() {
    assert_has("php_curl_use_after_close.php", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (13) Ruby resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ruby_file_open_leak() {
    assert_has_prefix("ruby_file_open_no_close.rb", "state-resource-leak");
}

#[test]
fn ruby_file_open_close() {
    assert_no_state_findings("ruby_file_open_close.rb");
}

#[test]
fn ruby_double_close() {
    assert_has("ruby_double_close.rb", "state-double-close");
}

#[test]
fn ruby_use_after_close() {
    assert_has("ruby_use_after_close.rb", "state-use-after-close");
}

#[test]
fn ruby_pg_connection_leak() {
    assert_has_prefix("ruby_pg_connection_leak.rb", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// (14) TypeScript resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ts_fs_open_no_close() {
    assert_has_prefix("ts_fs_open_no_close.ts", "state-resource-leak");
}

#[test]
fn ts_fs_open_close() {
    assert_no_state_findings("ts_fs_open_close.ts");
}

#[test]
fn ts_stream_use_after_destroy() {
    assert_has("ts_stream_use_after_destroy.ts", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (15) Edge-case regression tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn variable_shadowing_known_limitation() {
    // Inner-scope fclose(f) masks outer-scope f within the same function.
    // Known limitation: SymbolInterner scopes by enclosing function, not
    // lexical block.  Block-level shadowing is out of scope for Phase 11.
    assert_no_state_findings("variable_shadowing.c");
}

#[test]
fn multi_function_isolation_c() {
    // funcA opens f and never closes it (leak).
    // funcB opens f and closes it (clean).
    // With function-scoped interning, funcB's close must NOT mask funcA's leak.
    let ids = state_ids_for("multi_function_isolation.c");

    // funcA's leak must be detected
    assert!(
        ids.iter().any(|id| id.starts_with("state-resource-leak")),
        "expected state-resource-leak for funcA, got: {ids:?}"
    );

    // funcB must NOT produce false positives (no double-close, no use-after-close)
    assert!(
        !ids.iter().any(|id| id == "state-double-close"),
        "funcB must not produce state-double-close: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "state-use-after-close"),
        "funcB must not produce state-use-after-close: {ids:?}"
    );
}

#[test]
fn multi_function_isolation_rb() {
    // func_a opens f and never closes it (leak).
    // func_b opens f and closes it (clean).
    let ids = state_ids_for("multi_function_isolation.rb");

    assert!(
        ids.iter().any(|id| id.starts_with("state-resource-leak")),
        "expected state-resource-leak for func_a, got: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "state-double-close"),
        "func_b must not produce state-double-close: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "state-use-after-close"),
        "func_b must not produce state-use-after-close: {ids:?}"
    );
}

#[test]
fn resource_as_function_arg_still_leaks() {
    // f is opened in caller() and passed to helper() but never closed.
    // State analysis is intra-function, so caller() sees fopen without fclose.
    assert_has_prefix("resource_as_arg.c", "state-resource-leak");
}

#[test]
fn resource_returned_from_factory() {
    // Factory function: fopen without fclose, resource is returned to caller.
    // Known false positive — cross-function ownership not tracked.
    assert_has_prefix("resource_returned.c", "state-resource-leak");
}

#[test]
fn loop_reopen_clean() {
    // Each loop iteration opens and closes the file — clean at exit.
    assert_no_state_findings("loop_reopen.c");
}
