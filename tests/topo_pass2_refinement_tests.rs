//! Regression tests for cross-batch summary refinement in
//! [`run_topo_batches`]'s non-recursive branch.
//!
//! Pass 2 sequences files in callee-first topological order (see
//! `scc_file_batches_with_metadata`).  Before this wiring landed, the
//! non-recursive batch path called `run_rules_on_file`, which discards
//! refined SSA / body / auth artifacts.  Caller-most batches (run
//! later in topo order) saw only pass-1 summaries, the refined cross-
//! file context produced by callee batches in pass 2 was lost.
//!
//! These tests pin the new contract:
//!
//!   1. Non-recursive batches use `analyse_file_fused` and persist
//!      every refined artifact to `global_summaries`.
//!   2. The observable counter
//!      [`last_topo_nonrecursive_refinements`] reflects that.
//!   3. The opt-out env var `NYX_TOPO_REFINE=0` restores the legacy
//!      `run_rules_on_file` path with no behavioural regression on
//!      required findings.
//!   4. The fixture's expectations.json is met under both modes ,
//!      proving that refinement is a precision-positive optimisation
//!      and not a soundness change.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::last_topo_nonrecursive_refinements;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serialise tests that read the process-wide
/// `LAST_TOPO_NONRECURSIVE_REFINEMENTS` counter or set
/// `NYX_TOPO_REFINE`.  `cargo test` runs tests in parallel by default;
/// without this guard, one test's env or counter read can leak into
/// another's scan.
static TOPO_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Helper: run a closure with `NYX_TOPO_REFINE` set to a specific
/// value, restoring the prior state on drop.  We do not use
/// `temp_env` here to avoid a new dev-dep; `unsafe { set_var }` is
/// fine inside the test guard.
struct EnvScope {
    key: &'static str,
    prior: Option<String>,
}

impl EnvScope {
    fn set(key: &'static str, value: &str) -> Self {
        let prior = std::env::var(key).ok();
        // SAFETY: tests are serialised by `TOPO_TEST_GUARD` so no
        // concurrent access; `set_var` is sound under that guard.
        unsafe {
            std::env::set_var(key, value);
        }
        EnvScope { key, prior }
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        // SAFETY: see EnvScope::set.
        unsafe {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  D1, Refinement is enabled by default and is observable
// ─────────────────────────────────────────────────────────────────────

/// On a 2-file linear-chain fixture (caller → callee, no recursion),
/// the non-recursive branch must:
///   1. produce the expected findings (correctness baseline);
///   2. record at least one refinement on the observability counter,
///      proving refined artifacts were persisted into
///      `global_summaries` between batches.
///
/// `cross_file_alias_returned_alias` is a clean 2-file linear chain
/// (`app.js` calls `passthrough` from `helper.js`) that exercises the
/// non-recursive batch path in pass 2.
#[test]
fn nonrecursive_batches_persist_refinements_by_default() {
    let _guard = TOPO_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // Make sure we're testing the default-on path, not an inherited override.
    let _scope = EnvScope::set("NYX_TOPO_REFINE", "1");

    let dir = fixture_path("cross_file_alias_returned_alias");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    // Observability: at least one refinement must have been persisted.
    // The exact count depends on summary detail (FuncSummary +
    // SsaFuncSummary + body + auth per function), so a tight upper
    // bound would be brittle; the lower bound is what matters.
    let n = last_topo_nonrecursive_refinements();
    assert!(
        n > 0,
        "Expected the non-recursive batch path to persist > 0 refinements \
         to global_summaries on a multi-file fixture; got {n}.  This usually \
         means run_topo_batches' non-recursive branch reverted to \
         run_rules_on_file or analyse_file_fused stopped emitting \
         ssa_summaries / ssa_bodies / auth_summaries."
    );
}

// ─────────────────────────────────────────────────────────────────────
//  D2, Opt-out via NYX_TOPO_REFINE=0 restores legacy behaviour
// ─────────────────────────────────────────────────────────────────────

/// With `NYX_TOPO_REFINE=0`, the legacy non-recursive branch runs:
/// `run_rules_on_file` is called and refined artifacts are NOT
/// persisted, so the observability counter stays at zero.  The fixture's
/// required findings must STILL be detected, confirming that the
/// refinement is precision-positive but not soundness-load-bearing.
#[test]
fn nonrecursive_batches_legacy_path_when_disabled() {
    let _guard = TOPO_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _scope = EnvScope::set("NYX_TOPO_REFINE", "0");

    let dir = fixture_path("cross_file_alias_returned_alias");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    let n = last_topo_nonrecursive_refinements();
    assert_eq!(
        n, 0,
        "With NYX_TOPO_REFINE=0, the legacy run_rules_on_file branch is \
         expected to persist 0 refinements; got {n}.  If this fires, the \
         topo_refine_enabled() gate is being ignored by run_topo_batches."
    );
}

// ─────────────────────────────────────────────────────────────────────
//  D3, Refinement does not regress findings vs the legacy path
// ─────────────────────────────────────────────────────────────────────

/// Run the same fixture twice (refine on / off) and assert the set of
/// finding rule IDs is the same.  Refinement is precision-positive, so
/// the refine-on set is a *superset* of the legacy set; in practice
/// the fixtures exercised here are small enough that the two should be
/// equal.  This test guards against the regression where refinement
/// silently *loses* findings, e.g. a refined summary masking a real
/// finding via accidental sanitiser inference.
#[test]
fn refinement_does_not_lose_required_findings_vs_legacy() {
    let _guard = TOPO_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("cross_file_alias_returned_alias");

    // Run with refinement OFF first.
    let off = {
        let _scope = EnvScope::set("NYX_TOPO_REFINE", "0");
        scan_fixture_dir(&dir, AnalysisMode::Full)
    };
    let off_ids: std::collections::BTreeSet<String> = off.iter().map(|d| d.id.clone()).collect();

    // Run with refinement ON.
    let on = {
        let _scope = EnvScope::set("NYX_TOPO_REFINE", "1");
        scan_fixture_dir(&dir, AnalysisMode::Full)
    };
    let on_ids: std::collections::BTreeSet<String> = on.iter().map(|d| d.id.clone()).collect();

    // Refinement must be a superset of legacy findings.  Strict
    // equality is too tight (refinement may legitimately surface
    // additional findings).
    let lost: Vec<&String> = off_ids.difference(&on_ids).collect();
    assert!(
        lost.is_empty(),
        "Refinement-on lost findings present in refinement-off run: {lost:?}.  \
         This indicates a precision regression — a refined summary is \
         erroneously suppressing a finding the legacy path detected."
    );
}

// ─────────────────────────────────────────────────────────────────────
//  D4, Counter resets between scans
// ─────────────────────────────────────────────────────────────────────

/// `last_topo_nonrecursive_refinements()` is reset to zero at the
/// start of every `run_topo_batches` invocation.  Run two scans
/// back-to-back and confirm the counter reflects only the most-recent
/// invocation (not cumulative across scans).
#[test]
fn refinements_counter_resets_per_scan() {
    let _guard = TOPO_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _scope = EnvScope::set("NYX_TOPO_REFINE", "1");

    let dir = fixture_path("cross_file_alias_returned_alias");

    // First scan: counter should rise above zero.
    let _ = scan_fixture_dir(&dir, AnalysisMode::Full);
    let first = last_topo_nonrecursive_refinements();
    assert!(first > 0, "first scan must record refinements, got {first}");

    // Second scan on the same fixture.  Counter must reset to first
    // scan's value (or close to it, the fixture is deterministic so
    // it should match), NOT accumulate to ~2 × first.
    let _ = scan_fixture_dir(&dir, AnalysisMode::Full);
    let second = last_topo_nonrecursive_refinements();
    assert!(
        second > 0,
        "second scan must record refinements, got {second}"
    );
    assert!(
        second <= first.saturating_mul(2).saturating_sub(first / 4),
        "counter accumulated across scans (first={first}, second={second}); \
         it must be reset at the start of each run_topo_batches invocation"
    );
}
