//! Regression tests for the `EngineNote` provenance system.  Each
//! test forces a specific cap-site to fire on a tiny fixture by
//! overriding the engine's safety cap, then asserts either that the
//! corresponding observability counter moved *or* that the note
//! propagated to a produced finding, whichever is the more stable
//! signal for that cap.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::commands::scan::set_scc_fixpoint_cap_override;
use nyx_scanner::engine_notes::EngineNote;
use nyx_scanner::taint::ssa_transfer::{
    origins_truncation_count, reset_origins_observability, reset_worklist_observability,
    set_max_origins_override, set_worklist_cap_override, worklist_cap_hit_count,
};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

/// Process-wide atomics for cap overrides mean tests that fiddle with
/// them must run serially, cargo test defaults to parallel.
static CAP_GUARD: Mutex<()> = Mutex::new(());

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn worklist_cap_trips_observability_counter() {
    let _guard = CAP_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // Force a very tight worklist budget so every body with > 0 blocks
    // trips the cap.  The observability counter is the stable signal ,
    // note attribution to a specific finding may be lost on bodies that
    // capped *before* emitting their sink event.
    reset_worklist_observability();
    set_worklist_cap_override(1);
    set_max_origins_override(0);
    set_scc_fixpoint_cap_override(0);

    let dir = fixture("cross_file_context_deep_chain");
    let _ = scan_fixture_dir(&dir, AnalysisMode::Full);

    set_worklist_cap_override(0);

    assert!(
        worklist_cap_hit_count() > 0,
        "Expected worklist_cap_hit_count() > 0 when cap is forced to 1; got 0. \
         Either the override is not wired into run_ssa_taint_full or the \
         scan path no longer exercises the worklist."
    );
}

#[test]
fn origins_cap_trips_observability_on_multi_source_fixture() {
    let _guard = CAP_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // Set origins to 1 and scan a fixture with multiple top-level
    // sources flowing into the same sink.  Any non-trivial taint flow
    // will produce at least one tainted value whose origin list hit the
    // cap, detected by the post-hoc saturation scan at the end of
    // `run_ssa_taint_internal`.
    reset_origins_observability();
    set_max_origins_override(1);
    set_worklist_cap_override(0);
    set_scc_fixpoint_cap_override(0);

    // Scan a larger fixture so taint flows through several blocks.
    let dir = fixture("cross_file_scc_deep_cycle");
    let _ = scan_fixture_dir(&dir, AnalysisMode::Full);

    set_max_origins_override(0);

    assert!(
        origins_truncation_count() > 0,
        "Expected origins_truncation_count() > 0 with MAX_ORIGINS forced \
         to 1; got 0. The override is not wired or the fixture never \
         exercises a block state with tainted values."
    );
}

#[test]
fn scc_cap_attaches_cross_file_fixpoint_note() {
    let _guard = CAP_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // Force SCC to fail to converge: cap=1 means no refinement round
    // runs, so any batch with mutual recursion is unconverged and
    // `tag_unconverged_findings` runs.
    reset_worklist_observability();
    set_scc_fixpoint_cap_override(1);
    set_worklist_cap_override(0);
    set_max_origins_override(0);

    let dir = fixture("cross_file_scc_deep_cycle");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    set_scc_fixpoint_cap_override(0);

    let has_cross_file_capped = diags.iter().any(|d| {
        d.evidence
            .as_ref()
            .map(|ev| {
                ev.engine_notes
                    .iter()
                    .any(|n| matches!(n, EngineNote::CrossFileFixpointCapped { .. }))
            })
            .unwrap_or(false)
    });
    assert!(
        has_cross_file_capped,
        "Expected at least one CrossFileFixpointCapped engine note \
         when SCC cap is forced to 1.",
    );
}

#[test]
fn engine_note_serializes_with_snake_case_tag() {
    // Sanity check the SARIF / JSON shape that downstream consumers
    // rely on: `{ "kind": "worklist_capped", "iterations": N }`.
    let note = EngineNote::WorklistCapped { iterations: 42 };
    let json = serde_json::to_string(&note).expect("serialize");
    assert!(json.contains("\"kind\":\"worklist_capped\""));
    assert!(json.contains("\"iterations\":42"));
}

#[test]
fn lowers_confidence_distinguishes_informational_notes() {
    assert!(EngineNote::WorklistCapped { iterations: 10 }.lowers_confidence());
    assert!(EngineNote::ParseTimeout { timeout_ms: 1000 }.lowers_confidence());
    assert!(!EngineNote::InlineCacheReused.lowers_confidence());
}
