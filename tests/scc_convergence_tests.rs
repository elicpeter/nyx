//! Regression tests for SCC fixed-point convergence in pass 2.
//!
//! Pass 2 uses Jacobi iteration — each file in a mutually-recursive SCC
//! is re-analysed against the *pre-iteration* `GlobalSummaries` snapshot,
//! and updates are only visible on the next iteration.  In a cross-file
//! SCC with `k` functions arranged in a chain, facts introduced at one
//! end of the chain need up to `k` iterations to propagate back to the
//! other end.
//!
//! Before this test was written, the hard cap was 3 — so any SCC with
//! 4+ cross-file functions silently lost precision.  These fixtures
//! exercise a 4-cycle and assert both that the transitive finding is
//! reported and that the engine actually needed more than 3 iterations
//! to converge (proving the test is load-bearing, not incidental).
//!
//! If you raise or lower the cap in `scan::SCC_FIXPOINT_SAFETY_CAP`,
//! update the iteration-count assertions accordingly.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::{
    SCC_UNCONVERGED_NOTE_PREFIX, last_scc_max_iterations, set_scc_fixpoint_cap_override,
};
use nyx_scanner::evidence::Confidence;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serialize any test that mutates the global SCC fix-point cap override
/// or reads `last_scc_max_iterations()`. The override is a process-wide
/// `AtomicUsize` and `cargo test` runs tests in parallel by default —
/// without this guard, one test's override leaks into another's scan and
/// both the iteration count and the findings tag shift non-deterministically.
static SCC_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Adversarial 4-cycle: `step_a → step_b → step_c → step_d → step_a`
/// across four separate files, with the only sink in `step_d`.  The
/// `param_to_sink` fact has to travel back through three cross-file
/// summary-update iterations before `step_a`'s summary reflects the
/// transitive flow — without that, the caller in `server.py` never
/// sees the XSS/CMDI.
///
/// With the old `MAX_SCC_FIXPOINT_ITERS = 3` this test's required
/// finding silently disappeared.  With the current
/// `SCC_FIXPOINT_SAFETY_CAP = 64` it converges naturally.
#[test]
fn scc_deep_cycle_requires_multi_iter_convergence() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0); // ensure no stale override from a prior test
    let dir = fixture_path("cross_file_scc_deep_cycle");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Hard assertion: the transitive taint must be detected.
    validate_expectations(&diags, &dir);

    // Observability assertion: prove the SCC actually exercised more
    // than three iterations — otherwise this fixture would pass even
    // under the old bound and give false confidence.
    let iters = last_scc_max_iterations();
    assert!(
        iters >= 4,
        "Expected >= 4 SCC fix-point iterations for the 4-cycle fixture \
         to prove the pre-fix bound of 3 was unsafe; got {iters}. \
         If this drops to <= 3, either the analyser started resolving \
         cross-file summaries without iteration (great — but update this \
         test), or the fixture has stopped forming a real 4-cycle.",
    );

    // Sanity: the safety cap is large but finite. We should never come
    // anywhere near it on this tiny fixture.
    assert!(
        iters < 32,
        "4-cycle fixture should converge quickly; taking {iters} \
         iterations suggests non-monotone summary refinement.",
    );
}

/// Existing 3-file Python SCC — lighter smoke test, verifies the
/// iteration count stays in a sensible range.  If this starts requiring
/// many iterations something regressed in summary extraction.
#[test]
fn scc_small_cycle_converges_quickly() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("cross_file_scc_convergence");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    let iters = last_scc_max_iterations();
    assert!(
        iters <= 8,
        "Small 3-file SCC should converge in under 8 iterations; got {iters}",
    );
}

/// Phase 2a Task 2a.3 regression guard: when an SCC batch exhausts the
/// fix-point safety cap without converging, findings must still surface,
/// each tagged with `confidence = Low` and a `scc_unconverged:` note so
/// downstream reviewers can identify potentially-imprecise results.
///
/// Uses `set_scc_fixpoint_cap_override` to force cap-hit on the same
/// 4-cycle fixture as `scc_deep_cycle_requires_multi_iter_convergence`
/// (which normally takes ~4 iterations). Setting the cap to 1 guarantees
/// non-convergence while keeping the test cheap and deterministic.
#[test]
fn scc_cap_hit_still_emits_tagged_low_confidence_findings() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("cross_file_scc_deep_cycle");

    // Force the SCC fix-point loop to bail after 3 iterations. The
    // 4-cycle fixture needs >=4 iterations to fully propagate taint, so
    // the 3rd iteration's diags do contain the transitive taint finding
    // but convergence has not been detected — this is the exact cap-hit
    // scenario users would see in production on a larger SCC.
    set_scc_fixpoint_cap_override(3);
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    set_scc_fixpoint_cap_override(0);

    // Scan must not panic, hang, or silently drop results.
    assert!(
        !diags.is_empty(),
        "scan with cap-hit must still produce diagnostics"
    );

    // The scan must have exercised the cap (not converged early).
    let iters = last_scc_max_iterations();
    assert_eq!(
        iters, 3,
        "expected cap-override (3) to bind the fix-point loop; got {iters} iterations"
    );

    // (a) Taint findings must still be emitted — truncation is not
    // silent drop.
    let taint: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .collect();
    assert!(
        !taint.is_empty(),
        "unconverged SCC batch must still emit taint findings (truncated != dropped). \
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{}:{} {}", d.path, d.line, d.col, d.id))
            .collect::<Vec<_>>()
    );

    // (b) At least one finding from the unconverged SCC batch carries
    // the tag. Tagging is scoped to diags produced by the SCC fix-point
    // loop itself — findings from non-recursive batches or orphan files
    // that happen to flow through SCC-internal summaries are
    // intentionally not re-tagged (they came from a batch that did
    // converge, modulo the referenced summary).
    let tagged: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.evidence
                .as_ref()
                .map(|e| {
                    e.notes
                        .iter()
                        .any(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
                })
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !tagged.is_empty(),
        "at least one diag in an unconverged SCC batch must carry the \
         scc_unconverged note; got none. Tagging must fire on the SCC \
         batch's own iteration_diags. All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!(
                "{}:{}:{} {} conf={:?}",
                d.path, d.line, d.col, d.id, d.confidence
            ))
            .collect::<Vec<_>>()
    );

    // (c) Every tagged finding has confidence capped at Low.
    for d in &tagged {
        assert_eq!(
            d.confidence,
            Some(Confidence::Low),
            "scc_unconverged-tagged finding must be Low confidence: \
             {}:{}:{} id={} conf={:?}",
            d.path,
            d.line,
            d.col,
            d.id,
            d.confidence,
        );
    }
}
