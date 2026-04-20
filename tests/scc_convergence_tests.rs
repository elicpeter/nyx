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
use nyx_scanner::commands::scan::last_scc_max_iterations;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

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
    let dir = fixture_path("cross_file_scc_convergence");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    let iters = last_scc_max_iterations();
    assert!(
        iters <= 8,
        "Small 3-file SCC should converge in under 8 iterations; got {iters}",
    );
}
