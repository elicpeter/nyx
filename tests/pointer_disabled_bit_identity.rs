//! A1 / A4: env-var-toggle bit-identity gates for the
//! `NYX_POINTER_ANALYSIS` flag.
//!
//! These tests guard the strict-additive contract that the pointer
//! analysis module promises: when off (`NYX_POINTER_ANALYSIS=0` or
//! unset), the engine must produce a finding set bit-identical to the
//! pre-pointer baseline.  When on (`=1`), the finding set must be a
//! superset that DROPS no genuine findings.
//!
//! Both modes are exercised in the same test process via a serial
//! mutex around env-var manipulation — cargo runs tests in parallel
//! and an unprotected env-var write would leak between threads.
//!
//! A4 baseline snapshot: when the env variable
//! `UPDATE_SNAPSHOTS=1` is set, the disabled-mode finding set is
//! written to `tests/snapshots/pointer_disabled_baseline.json`.
//! Otherwise the test verifies the disabled-mode set matches the
//! checked-in snapshot.  This guards against silent finding-set
//! drift across unrelated engine changes.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::utils::config::AnalysisMode;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;

/// Process-wide guard: env-var writes from one test thread would race
/// with reads from another.  Every test in this file claims this
/// guard before touching `NYX_POINTER_ANALYSIS`.
static ENV_VAR_GUARD: Mutex<()> = Mutex::new(());

const ENV_VAR: &str = "NYX_POINTER_ANALYSIS";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Fixture mix curated for the strict-additive guard.  Picks shapes
/// the pointer module actively touches:
///
/// * `container_taint_js` — JS container ops (push/shift/pop) flow
///   through the W2 / W4 ELEM cells when pointer is on.
/// * `container_taint_py` — Python container shapes mirror the JS path
///   for non-method `__getitem__` / `__setitem__` (W5; deferred but
///   the existing method-shape ops are still exercised).
/// * `cross_file_py_object_field` — field-flow shapes that exercise
///   the W1 / W3 cross-call resolver with field-name keys.
///
/// Picked deliberately small: every additional fixture multiplies the
/// runtime by ~1×, and these three already span container element
/// flow + field flow + cross-call propagation.
const CURATED_FIXTURES: &[&str] = &[
    "container_taint_js",
    "container_taint_py",
    "cross_file_py_object_field",
];

/// One scan, one (path, line, col, id) tuple per finding.  Stripped
/// of all derived fields (rank, evidence, message, etc.) so the
/// comparison is robust to incidental ranking / formatting changes
/// while still anchoring on the structural identity of each finding.
type FindingId = (String, usize, usize, String);

fn collect_finding_ids(fixture: &str) -> BTreeSet<FindingId> {
    let dir = fixture_path(fixture);
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    diags
        .into_iter()
        .map(|d| (d.path, d.line, d.col, d.id))
        .collect()
}

/// Run a closure with `NYX_POINTER_ANALYSIS=value` set, restoring the
/// prior environment afterwards.  The guard is held across the
/// closure so concurrent tests don't race.  SAFETY: cargo's test
/// harness runs each test on its own thread; Rust's std `set_var` is
/// thread-unsafe in principle, but with the process-wide guard no
/// concurrent reader can observe a torn write.
fn with_env<F, R>(value: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let _guard = ENV_VAR_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let prior = std::env::var(ENV_VAR).ok();
    // SAFETY: see function-level note.
    unsafe { std::env::set_var(ENV_VAR, value) };
    let r = f();
    // Restore prior environment.
    match prior {
        Some(v) => unsafe { std::env::set_var(ENV_VAR, v) },
        None => unsafe { std::env::remove_var(ENV_VAR) },
    }
    r
}

/// A1: scanning each curated fixture under `NYX_POINTER_ANALYSIS=0`
/// and `=1` produces the same set of `(path, line, col, id)` tuples.
///
/// Strict-additive contract: pointer analysis must only suppress FPs
/// (or surface new findings via fixtures we haven't included here);
/// it must not change the structural identity of any existing
/// finding.  The current curated fixtures exercise shapes the
/// pointer module touches but where existing engine analyses already
/// produce all the findings — so the equality check is the right
/// shape today.  When pointer-on starts adding NEW findings to these
/// fixtures, the test should be updated to assert
/// `enabled.is_superset(disabled)`.
#[test]
fn pointer_toggle_preserves_finding_set() {
    for &fixture in CURATED_FIXTURES {
        let disabled = with_env("0", || collect_finding_ids(fixture));
        let enabled = with_env("1", || collect_finding_ids(fixture));
        assert_eq!(
            disabled, enabled,
            "NYX_POINTER_ANALYSIS toggle must preserve the finding \
             set on fixture {fixture:?}.  off-only: {:#?}\non-only: {:#?}",
            disabled.difference(&enabled).collect::<Vec<_>>(),
            enabled.difference(&disabled).collect::<Vec<_>>(),
        );
    }
}

/// A4: bit-identity baseline.  Captures the current pointer-disabled
/// finding set on the curated fixtures and pins it to a checked-in
/// snapshot.  Refresh with:
///
/// ```bash
/// UPDATE_SNAPSHOTS=1 cargo test --test pointer_disabled_bit_identity \
///     pointer_disabled_finding_set_matches_baseline
/// ```
///
/// The snapshot lives next to the test, not under `tests/snapshots/`,
/// so a checkout-only-files-changed diff highlights this baseline
/// alongside its test.
#[test]
fn pointer_disabled_finding_set_matches_baseline() {
    let snapshot_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join("pointer_disabled_baseline.json");

    // Collect the disabled-mode finding set across the curated mix.
    let mut current: Vec<(String, Vec<FindingId>)> = CURATED_FIXTURES
        .iter()
        .map(|f| {
            let ids = with_env("0", || collect_finding_ids(f));
            (f.to_string(), ids.into_iter().collect())
        })
        .collect();
    // Deterministic ordering.
    current.sort_by(|a, b| a.0.cmp(&b.0));

    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        // Write snapshot.
        if let Some(parent) = snapshot_path.parent() {
            std::fs::create_dir_all(parent).expect("failed to create snapshots dir");
        }
        let json =
            serde_json::to_string_pretty(&current).expect("failed to serialize finding set");
        std::fs::write(&snapshot_path, &json).expect("failed to write snapshot");
        eprintln!("Snapshot written: {}", snapshot_path.display());
        return;
    }

    let snapshot_text = match std::fs::read_to_string(&snapshot_path) {
        Ok(s) => s,
        Err(_) => {
            // First run / missing snapshot — write it and skip the
            // diff check.  Subsequent runs will assert against this
            // captured value.
            if let Some(parent) = snapshot_path.parent() {
                std::fs::create_dir_all(parent).expect("failed to create snapshots dir");
            }
            let json = serde_json::to_string_pretty(&current)
                .expect("failed to serialize finding set");
            std::fs::write(&snapshot_path, &json).expect("failed to write snapshot");
            eprintln!(
                "Initial snapshot written to {}; re-run to verify.",
                snapshot_path.display()
            );
            return;
        }
    };
    let baseline: Vec<(String, Vec<FindingId>)> =
        serde_json::from_str(&snapshot_text).expect("failed to parse baseline JSON");

    assert_eq!(
        baseline, current,
        "pointer-disabled baseline drift detected — \
         re-run with UPDATE_SNAPSHOTS=1 if intentional",
    );
}
