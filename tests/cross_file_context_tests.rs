//! Cross-file k=1 context-sensitive inline taint integration tests.
//! These tests exercise the `resolve_callee` -> cross-file inline
//! path that consults [`GlobalSummaries::bodies_by_key`] before falling
//! through to summary-based resolution.
//!
//! The four fixtures under `tests/fixtures/cross_file_context_*` cover
//! the documented precision wins and guardrails:
//!
//! * `cross_file_context_two_call_sites` (Python) — two calls to the same
//!   cross-file helper, one tainted and one with a constant literal.
//!   Asserts the tainted call still produces a finding.
//! * `cross_file_context_callback` (JS) — cross-file helper invokes a
//!   caller-side function passed as a callback.  Inline re-analysis of
//!   the helper must resolve the callback binding and surface the
//!   flow through `child_process.exec`.
//! * `cross_file_context_sanitizer` (JS) — cross-file sanitizer applied
//!   before an HTML sink.  Regression guard: cross-file inline must not
//!   introduce a taint finding when the sanitiser is recognised.
//! * `cross_file_context_deep_chain` (Python) — A -> B -> C chain with
//!   the sink in C.  k=1 means B->C resolves via summary; the end-to-end
//!   finding must still surface so callers cannot lose recall on deep
//!   chains.
//!
//! The `bodies_by_key_populated_for_cross_file_fixtures` test is a
//! direct `GlobalSummaries`-level assertion that pass 1 loaded cross-file
//! SSA bodies for each fixture — i.e. the cross-file inline path has
//! something to consult.  If this assertion flips to zero, cross-file
//! inline would silently fall back to summary resolution and every
//! expectations.json check above would be driven by the less precise
//! summary path, which is what the companion
//! `cross_file_context_off_tests.rs` binary verifies.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::ast::analyse_file_fused;
use nyx_scanner::commands::index::build_index;
use nyx_scanner::commands::scan::{Diag, scan_with_index_parallel};
use nyx_scanner::database::index::Indexer;
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

/// Walk a fixture directory and replay the pass-1 body collection that
/// `scan_filesystem` does, returning the merged `GlobalSummaries`.
///
/// This is used purely for the availability assertion — the actual
/// scans under test go through the regular `scan_no_index` entry point.
fn pass1_bodies(root: &Path) -> GlobalSummaries {
    let cfg = test_config();
    let root_str = root.to_string_lossy();
    let mut gs = GlobalSummaries::new();

    let entries: Vec<PathBuf> = std::fs::read_dir(root)
        .expect("fixture dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();

    for path in &entries {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(r) = analyse_file_fused(&bytes, path, &cfg, None, Some(root)) else {
            continue;
        };
        for s in r.summaries {
            let key = s.func_key(Some(&root_str));
            gs.insert(key, s);
        }
        for (key, ssa) in r.ssa_summaries {
            gs.insert_ssa(key, ssa);
        }
        for (key, body) in r.ssa_bodies {
            gs.insert_body(key, body);
        }
    }
    gs
}

// ── Fixture-backed tests ────────────────────────────────────────────────────

/// Two cross-file call sites: one tainted, one constant.  The tainted
/// call still reaches the sink; the constant call does not produce an
/// additional false-positive beyond the noise budget.
#[test]
fn cross_file_context_two_call_sites() {
    let dir = fixture_path("cross_file_context_two_call_sites");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Cross-file helper invokes a caller-side callback that internally
/// sinks the argument.  Inline re-analysis of the helper must resolve
/// the callback binding and surface the flow.
#[test]
fn cross_file_context_callback() {
    let dir = fixture_path("cross_file_context_callback");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Cross-file sanitiser applied before a sink.  Regression guard:
/// cross-file inline must not introduce a finding that the summary
/// path already suppresses.
#[test]
fn cross_file_context_sanitizer() {
    let dir = fixture_path("cross_file_context_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Three-file deep chain (A -> B -> C) with the sink in C.  The
/// end-to-end flow must still surface — k=1 depth cap on inline does
/// not drop recall because B -> C resolves via summary.
#[test]
fn cross_file_context_deep_chain() {
    let dir = fixture_path("cross_file_context_deep_chain");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Indexed-scan variants ───────────────────────────────────────────────────
//
// Each fixture above drives the in-memory scan path (`scan_no_index`).
// The indexed-scan path loads pre-lowered `CalleeSsaBody`s from SQLite
// where `body_graph` is `#[serde(skip)]` and comes back `None`.  Earlier
// the taint engine's cross-file inline early-returned on that case, so
// indexed and no-index scans could diverge on these fixtures.  The
// indexed path now rehydrates a proxy `Cfg` from `node_meta` at load
// time, restoring parity.
//
// These tests run the same fixtures through `scan_with_index_parallel` and
// assert the same `validate_expectations` outcome.  A regression to the
// early-return (or to the node_meta → body_graph rebuild) would cause the
// tainted-call fixtures to lose their finding on the indexed path while
// keeping it on the in-memory path.

fn scan_indexed(fixture_dir: &Path, mode: AnalysisMode) -> Vec<Diag> {
    let mut cfg = Config::default();
    cfg.scanner.mode = mode;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;

    let td = tempfile::tempdir().expect("tempdir");
    let db_path = td.path().join("cf3.sqlite");

    build_index("cf3", fixture_dir, &db_path, &cfg, false).expect("build_index");
    let pool = Indexer::init(&db_path).expect("init pool");
    let diags = scan_with_index_parallel("cf3", Arc::clone(&pool), &cfg, false, fixture_dir)
        .expect("indexed scan");
    std::mem::drop(td);
    diags
}

#[test]
fn cross_file_context_two_call_sites_indexed() {
    let dir = fixture_path("cross_file_context_two_call_sites");
    let diags = scan_indexed(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_context_callback_indexed() {
    let dir = fixture_path("cross_file_context_callback");
    let diags = scan_indexed(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_context_sanitizer_indexed() {
    let dir = fixture_path("cross_file_context_sanitizer");
    let diags = scan_indexed(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_context_deep_chain_indexed() {
    let dir = fixture_path("cross_file_context_deep_chain");
    let diags = scan_indexed(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Direct GlobalSummaries assertions ───────────────────────────────────────

/// Each fixture must populate `GlobalSummaries.bodies_by_key` via the
/// pass-1 pipeline.  If this assertion fails, the fixture-level
/// expectations above are being satisfied by the summary path alone
/// (i.e. cross-file inline is not actually firing) and a future
/// regression to the cross-file inline resolver would go unnoticed.
#[test]
fn bodies_by_key_populated_for_cross_file_fixtures() {
    let fixtures = [
        "cross_file_context_two_call_sites",
        "cross_file_context_callback",
        "cross_file_context_sanitizer",
        "cross_file_context_deep_chain",
    ];

    for name in &fixtures {
        let dir = fixture_path(name);
        let gs = pass1_bodies(&dir);
        assert!(
            gs.bodies_len() >= 1,
            "fixture `{}` produced zero cross-file SSA bodies — cross-file \
             inline has nothing to consult and every test in this file is \
             falling through to summary resolution. Check that \
             `cross_file_symex_enabled()` is on and that \
             `analyse_file_fused` still returns `ssa_bodies`.",
            name
        );
    }
}
