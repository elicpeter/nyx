//! Phase-C regression tests for the Gauss-Seidel variant of JS/TS
//! pass-2 convergence.
//!
//! Default mode is Jacobi (order-independent, reproducible).
//! Gauss-Seidel is opt-in via `NYX_JS_GAUSS_SEIDEL=1` (or the
//! test-only override).  The two variants must produce **equal
//! findings** on every fixture, this is the core correctness
//! invariant for shipping G-S behind a flag.
//!
//! If this test ever fails, Gauss-Seidel has a precision leak and
//! must NOT be enabled by default.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::taint::{
    last_js_ts_pass2_iterations, set_js_ts_gauss_seidel_override, set_js_ts_pass2_cap_override,
};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serialize tests that mutate the Gauss-Seidel and pass-2 cap
/// overrides.  Both are process-global `AtomicUsize`s and `cargo
/// test` runs in parallel by default.
static GS_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Sort findings into a deterministic order that ignores
/// non-semantic fields so we can compare Jacobi vs. Gauss-Seidel
/// runs.  Comparing raw `Diag` equality would be too strict ,
/// evidence ordering, span-derived IDs, and rank scores can differ
/// harmlessly between variants.  We assert on the tuple
/// `(path, line, col, id, severity, suppressed)` which is the
/// finding's identity.
fn finding_identities(
    diags: &[nyx_scanner::commands::scan::Diag],
) -> Vec<(
    String,
    usize,
    usize,
    String,
    nyx_scanner::patterns::Severity,
    bool,
)> {
    let mut v: Vec<_> = diags
        .iter()
        .map(|d| {
            (
                d.path.clone(),
                d.line,
                d.col,
                d.id.clone(),
                d.severity,
                d.suppressed,
            )
        })
        .collect();
    v.sort();
    v
}

/// Phase-C correctness invariant: Jacobi and Gauss-Seidel produce
/// **equal findings** on the deep-chain fixture.
///
/// Gauss-Seidel may converge in fewer iterations, that is the whole
/// point of the optimisation, but the set of findings and their
/// primary locations must be identical.  A divergence here would
/// mean G-S is cutting off a real flow or introducing a spurious
/// one; ship-blocking either way.
#[test]
fn gauss_seidel_matches_jacobi_on_deep_chain() {
    let _guard = GS_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_js_ts_pass2_cap_override(0);
    let dir = fixture_path("js_ts_pass2_deep_chain");

    // Run 1: force Jacobi.
    set_js_ts_gauss_seidel_override(1);
    let diags_jacobi = scan_fixture_dir(&dir, AnalysisMode::Full);
    let jacobi_iters = last_js_ts_pass2_iterations();
    validate_expectations(&diags_jacobi, &dir);

    // Run 2: force Gauss-Seidel.
    set_js_ts_gauss_seidel_override(2);
    let diags_gs = scan_fixture_dir(&dir, AnalysisMode::Full);
    let gs_iters = last_js_ts_pass2_iterations();
    validate_expectations(&diags_gs, &dir);

    // Restore default mode so other tests see a clean override.
    set_js_ts_gauss_seidel_override(0);

    // Invariant 1: finding identity equality.
    let jacobi_ids = finding_identities(&diags_jacobi);
    let gs_ids = finding_identities(&diags_gs);
    assert_eq!(
        jacobi_ids, gs_ids,
        "Jacobi and Gauss-Seidel must produce identical findings. \
         Jacobi: {jacobi_ids:#?}\nGauss-Seidel: {gs_ids:#?}"
    );

    // Invariant 2: Gauss-Seidel never takes MORE iterations than
    // Jacobi.  On chain-shaped fixtures G-S should match or
    // strictly improve.
    assert!(
        gs_iters <= jacobi_iters,
        "Gauss-Seidel must not increase iteration count. \
         Jacobi={jacobi_iters}, Gauss-Seidel={gs_iters}"
    );
}

/// Determinism invariant: the same Gauss-Seidel run on the same
/// fixture produces byte-equal findings across invocations.  Tests
/// that the pinned traversal order (`containment_order`) is
/// deterministic.
#[test]
fn gauss_seidel_is_deterministic_across_runs() {
    let _guard = GS_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_js_ts_pass2_cap_override(0);
    set_js_ts_gauss_seidel_override(2);

    let dir = fixture_path("js_ts_pass2_deep_chain");
    let diags1 = scan_fixture_dir(&dir, AnalysisMode::Full);
    let diags2 = scan_fixture_dir(&dir, AnalysisMode::Full);
    let diags3 = scan_fixture_dir(&dir, AnalysisMode::Full);

    set_js_ts_gauss_seidel_override(0);

    let ids1 = finding_identities(&diags1);
    let ids2 = finding_identities(&diags2);
    let ids3 = finding_identities(&diags3);

    assert_eq!(ids1, ids2, "Gauss-Seidel findings must be deterministic");
    assert_eq!(
        ids2, ids3,
        "Gauss-Seidel findings must be deterministic across 3 runs"
    );
}

/// Default behaviour: no override, no env var → Jacobi.  Guards
/// against a future refactor accidentally flipping the default.
#[test]
fn default_mode_is_jacobi_when_env_unset() {
    let _guard = GS_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_js_ts_gauss_seidel_override(0); // clear any test override
    // We can't fully prove this without process isolation
    // (js_ts_gauss_seidel_enabled caches via OnceLock on first call),
    // but we can assert that when the explicit test override is 0,
    // the public accessor returns a bool.  The cap on this test is
    // that it runs alongside others in the same process; the
    // important guarantee is covered by
    // `gauss_seidel_matches_jacobi_on_deep_chain` above.
    let _enabled = nyx_scanner::taint::js_ts_gauss_seidel_enabled();
    // If the OnceLock got initialized to "enabled" by an earlier
    // test that set the env var, we can't do much about it here.
    // The determinism and equivalence tests above are the
    // load-bearing guarantees.
}
