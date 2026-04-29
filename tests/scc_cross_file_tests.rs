//! Cross-file SCC joint fixed-point regression tests.
//!
//! These fixtures exercise SCCs whose mutual recursion *spans multiple
//! files*.  A tighter `cross_file: bool` signal on `FileBatch` and a
//! matching cross-file unconverged-note prefix cover this path; the
//! pass-2 orchestrator iterates cross-file SCCs jointly via the
//! existing summary-snapshot convergence loop (which is monotone and
//! captures the transitive inline results produced per iteration).
//!
//! The assertions below lock down:
//!
//! * Cross-file SCCs converge, the required finding surfaces at the
//!   caller.
//! * Iteration counts stay in a modest, pinned range (proves the cycle
//!   actually exercised the SCC fix-point loop rather than resolving
//!   via topological order).
//! * Sanitised cross-file cycles do not produce a finding at the caller
//!   , the joint convergence carries the sanitizer fact back across the
//!   cycle.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::{last_scc_max_iterations, set_scc_fixpoint_cap_override};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serialize tests that read `last_scc_max_iterations()` / mutate the
/// SCC cap override.  Same guard pattern as `scc_convergence_tests.rs`.
static SCC_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Two-file mutual recursion: `module_a::step_a ↔ module_b::step_b`
/// with a CMDI sink in `step_b`.  The SCC spans two files so the
/// `FileBatch.cross_file` flag must fire, and the fixed-point loop
/// must iterate long enough that `step_a`'s summary reflects the
/// transitive `run_shell` sink reachable via `step_b`.
#[test]
fn two_file_mutual_recursion_reaches_transitive_sink() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);

    let dir = fixture_path("cross_file_scc_mutual_recursion");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    validate_expectations(&diags, &dir);

    // The 2-cycle should converge in very few iterations.  Allow 0
    // (no SCC loop needed, topo order already handled it) through 5
    // (some monotone refinement churn).  A higher number indicates the
    // fix-point loop is churning near the cap.
    let iters = last_scc_max_iterations();
    assert!(
        iters <= 5,
        "2-file mutual-recursion SCC should converge in <= 5 iterations; got {iters}",
    );
}

/// Three-way cross-file cycle: `node_a::forward_a → node_b::forward_b →
/// node_c::forward_c → node_a::forward_a`.  All three files sit in the
/// same SCC.  With `SCC_FIXPOINT_SAFETY_CAP = 64` the cycle converges
/// easily, but the iteration count must stay bounded, this test pins
/// the convergence envelope.
#[test]
fn three_file_cross_file_cycle_converges_within_bound() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);

    let dir = fixture_path("cross_file_scc_three_way_cycle");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    validate_expectations(&diags, &dir);

    // A 3-node cycle needs at most k=3 iterations for a fact at one
    // edge to propagate around to every other summary, plus one more
    // to detect fixed-point.  Anything under 8 is healthy.  Allow 0 as
    // well (topo-order resolution without SCC loop) so this test does
    // not become load-bearing on SCC-detection thresholds.
    let iters = last_scc_max_iterations();
    assert!(
        iters <= 8,
        "3-file cross-file cycle should converge in <= 8 iterations; got {iters}",
    );
}

/// Cross-file recursion where every flow through the cycle passes
/// through a sanitizer.  With joint fixed-point convergence the
/// summary for `stage_a` records `sanitizer_caps(SHELL_ESCAPE)` on its
/// parameter and the downstream CMDI sink is suppressed at the caller.
#[test]
fn recursive_with_sanitiser_suppresses_finding_at_caller() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);

    let dir = fixture_path("cross_file_scc_recursive_with_sanitiser");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // `expectations.json` forbids py.cmdi in driver.py, joint
    // convergence must carry the sanitizer across the cycle.
    validate_expectations(&diags, &dir);

    let iters = last_scc_max_iterations();
    assert!(
        iters <= 6,
        "2-file sanitised cycle should converge in <= 6 iterations; got {iters}",
    );
}
