//! Regression tests for JS/TS in-file pass-2 convergence.
//!
//! Pass 2 is the Jacobi-style iteration that combines each non-toplevel
//! body's exit state (filtered to top-level keys) back into the shared
//! seed and re-runs non-toplevel bodies with the enlarged seed.  The
//! hardcoded cap of `3` that used to live in `analyse_file` silently
//! truncated any file whose convergence required 4+ rounds, this
//! phase lifts the cap to [`JS_TS_PASS2_SAFETY_CAP`] (64), adds an
//! observability counter, and tags cap-hit findings with
//! [`EngineNote::InFileFixpointCapped`].
//!
//! Mirrors `tests/scc_convergence_tests.rs` in structure and intent.
//!
//! If you raise or lower the cap in `taint::JS_TS_PASS2_SAFETY_CAP`,
//! update the iteration-count assertions accordingly.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::taint::{last_js_ts_pass2_iterations, set_js_ts_pass2_cap_override};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serialize any test that mutates the pass-2 cap override or reads
/// `last_js_ts_pass2_iterations()`. The override is a process-wide
/// `AtomicUsize` and `cargo test` runs tests in parallel by default ,
/// without this guard, one test's override leaks into another's scan.
static PASS2_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Five top-level `const` bindings threaded through four helper
/// functions.  With the default cap of 64 this converges and the
/// `child_process.exec(stage4)` sink sees the transitive taint flow.
///
/// The test asserts both that the finding is reported and that the
/// observability counter surfaces a sensible value so future
/// regressions in the pass-2 plumbing (e.g. the counter being reset
/// or the cap being bypassed) are caught.
#[test]
fn js_ts_pass2_deep_chain_emits_transitive_finding() {
    let _guard = PASS2_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_js_ts_pass2_cap_override(0); // ensure no stale override from a prior test
    let dir = fixture_path("js_ts_pass2_deep_chain");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Hard assertion: the transitive taint must be detected.
    validate_expectations(&diags, &dir);

    // Observability + load-bearing assertion.  The fixture's
    // cross-body global publishing means pass-2 has to do real work:
    // at least two rounds are needed for `seed_handler`'s
    // `globalG1` to reach `finalize_handler`'s sink, then one more
    // round to confirm convergence.  A drop to `1` means the pass-2
    // loop is short-circuiting and this fixture is no longer
    // load-bearing.  An upper bound of `8` catches summary-monotonicity
    // regressions that would churn near the safety cap of 64.
    let iters = last_js_ts_pass2_iterations();
    assert!(
        (2..=8).contains(&iters),
        "expected 2..=8 pass-2 iterations for the deep-chain fixture; \
         got {iters}. Lower bound guards against pass-2 becoming a \
         no-op on this fixture; upper bound guards against \
         summary-monotonicity regressions.",
    );
}

/// Override plumbing: verify that `set_js_ts_pass2_cap_override` binds
/// the effective cap and that restoring the default clears cleanly.
///
/// We use a cap of 1 (meaning `rounds == 0`, the pass-2 loop does not
/// enter).  This is the sharpest possible override and exercises the
/// "cap bound to minimum" code path.  The counter must then fall back
/// to the pass-1-only value of `1`.
#[test]
fn js_ts_pass2_cap_override_binds_effective_cap() {
    let _guard = PASS2_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("js_ts_pass2_deep_chain");

    // First scan with the cap forced to 1, the pass-2 loop does not
    // enter at all (`max_iterations.saturating_sub(1) == 0`).  The
    // counter must report exactly `1` (the sentinel for "pass-1
    // containment ran, no pass-2 iterations").
    set_js_ts_pass2_cap_override(1);
    let _ = scan_fixture_dir(&dir, AnalysisMode::Full);
    let iters_capped = last_js_ts_pass2_iterations();
    assert_eq!(
        iters_capped, 1,
        "cap=1 must short-circuit pass-2 to zero rounds; got {iters_capped} \
         iterations. Check js_ts_pass2_cap() is wired into max_iterations.",
    );

    // Restore default and scan again.  On this fixture pass-2 needs
    // several rounds to converge, so the counter must now report a
    // value strictly greater than the cap=1 short-circuit reading.
    // This guards against the override "sticking" (e.g. if the
    // override were stored into the cap const instead of a distinct
    // atomic).
    set_js_ts_pass2_cap_override(0);
    let _ = scan_fixture_dir(&dir, AnalysisMode::Full);
    let iters_default = last_js_ts_pass2_iterations();
    assert!(
        iters_default > iters_capped && iters_default <= 64,
        "after clearing the override the counter must report a value \
         strictly greater than the cap=1 reading ({iters_capped}); \
         got {iters_default}",
    );
}

/// Cap-hit engine-note emission.
///
/// When pass-2 exhausts its budget without detecting convergence,
/// every finding from the file must carry
/// [`EngineNote::InFileFixpointCapped`] so downstream reviewers can
/// identify potentially-imprecise results.  The deep-chain fixture's
/// pass-2 seed actually grows between rounds (`seed_handler` publishes
/// `globalG1` to other bodies), so forcing the cap to `2` binds the
/// loop at a single round, the seed grew, no convergence was
/// detected, and the note path fires.
#[test]
fn js_ts_pass2_cap_hit_emits_engine_note() {
    use nyx_scanner::engine_notes::EngineNote;
    let _guard = PASS2_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("js_ts_pass2_deep_chain");

    // cap=2 → max_iterations=2, rounds=1.  Round 0 combines
    // `seed_handler`'s exit (which includes `globalG1`) into the
    // seed, the seed grows from empty to 1 entry, so the
    // convergence-equality branch does not fire.  Loop exits with
    // `converged_early = false`, note emission triggers.
    set_js_ts_pass2_cap_override(2);
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    set_js_ts_pass2_cap_override(0);

    let iters = last_js_ts_pass2_iterations();
    assert_eq!(
        iters, 1,
        "expected cap-override (2) to bind the pass-2 loop at 1 round; \
         got {iters} iterations",
    );

    // Every finding produced from the capped file must carry the note.
    // Strict assertion: if *any* finding lacks the note, pass-2's
    // per-finding note merging regressed.
    assert!(
        !diags.is_empty(),
        "cap-hit scan must still emit diagnostics (truncation is not silent drop); \
         got none",
    );
    for d in &diags {
        let has_note = d
            .evidence
            .as_ref()
            .map(|e| {
                e.engine_notes
                    .iter()
                    .any(|n| matches!(n, EngineNote::InFileFixpointCapped { .. }))
            })
            .unwrap_or(false);
        assert!(
            has_note,
            "every diag from a cap-hit pass-2 scan must carry \
             EngineNote::InFileFixpointCapped; missing on {}:{}:{} id={} \
             notes={:?}",
            d.path,
            d.line,
            d.col,
            d.id,
            d.evidence
                .as_ref()
                .map(|e| e.engine_notes.clone())
                .unwrap_or_default(),
        );
    }
}
