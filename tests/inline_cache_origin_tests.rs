//! Regression guard: inline-analysis cache origin attribution.
//!
//! Two call sites to the same helper function share an `ArgTaintSig`
//! (caps-only cache key) but carry different taint sources.  The engine
//! must re-attribute origins at each cache hit so the two resulting
//! findings point to distinct source lines.  An earlier implementation
//! baked in whichever caller first populated the cached
//! `VarTaint.origins`, causing the second caller's finding to
//! mis-attribute its source.
//!
//! A failure of this test implies a `taint-unsanitised-flow` finding is
//! naming the wrong source file/line, a credibility-killer for users
//! who then dismiss the tool as producing false positives.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Source line reported on a taint finding (from `evidence.source.line`).
fn source_line_of(d: &Diag) -> Option<u32> {
    d.evidence
        .as_ref()
        .and_then(|e| e.source.as_ref())
        .map(|s| s.line)
}

/// Sink snippet (e.g. `child_process.exec`) reported on a taint finding.
fn sink_snippet_of(d: &Diag) -> Option<String> {
    d.evidence
        .as_ref()
        .and_then(|e| e.sink.as_ref())
        .and_then(|s| s.snippet.clone())
}

#[test]
fn two_call_sites_get_distinct_source_attributions() {
    let dir = fixture_path("inline_cache_origin_attribution");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Collect taint findings; group by sink snippet so the two call sites
    // are distinguishable.  Sink-snippet grouping is deliberate: the
    // sink-line/cap-based dedup in `commands::scan::deduplicate_taint_flows`
    // merges same-sink duplicates, but the two fixture call sites land on
    // different sinks (child_process.exec vs fs.writeFileSync) and survive.
    let taint: Vec<&Diag> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .collect();

    assert!(
        taint.len() >= 2,
        "expected at least 2 taint findings (one per call site), got {}.\n\
         Diagnostics:\n{:#?}",
        taint.len(),
        diags.iter().map(|d| &d.id).collect::<Vec<_>>()
    );

    let exec_finding = taint
        .iter()
        .find(|d| {
            sink_snippet_of(d)
                .unwrap_or_default()
                .contains("child_process.exec")
        })
        .expect("missing child_process.exec finding for call site 1");
    let write_finding = taint
        .iter()
        .find(|d| {
            sink_snippet_of(d)
                .unwrap_or_default()
                .contains("fs.writeFileSync")
        })
        .expect("missing fs.writeFileSync finding for call site 2");

    let exec_src = source_line_of(exec_finding).expect("exec finding missing source line");
    let write_src = source_line_of(write_finding).expect("write finding missing source line");

    // Lines come from app.js:
    //   16: const sourceA = process.env.USER_INPUT;   (call site 1 source)
    //   21: const sourceB = process.env.OTHER_INPUT;  (call site 2 source)
    //
    // The critical assertion is inequality, a naive cache would report
    // the FIRST-cached caller's source line on both findings (baking in
    // `VarTaint.origins` from whichever call fired first during
    // traversal).  We also pin the exact expected lines so a silent
    // shift in attribution logic doesn't quietly pass.
    assert_ne!(
        exec_src, write_src,
        "origin attribution was conflated: both findings point to the same source line {}.\n\
         exec  finding: {:#?}\n\
         write finding: {:#?}",
        exec_src, exec_finding, write_finding
    );
    assert_eq!(
        exec_src, 16,
        "expected exec call site source at line 16 (process.env.USER_INPUT); got {}",
        exec_src
    );
    assert_eq!(
        write_src, 21,
        "expected write call site source at line 21 (process.env.OTHER_INPUT); got {}",
        write_src
    );
}

#[test]
fn inline_cache_reused_note_fires_on_second_call() {
    // Observability: the `InlineCacheReused` engine note is recorded
    // on cache-hit apply.  At least one of the two call sites must
    // carry it, whichever call loses the miss/hit race.
    //
    // The note is informational only: `EngineNote::InlineCacheReused`
    // returns `false` from `lowers_confidence()`, so its presence never
    // alters finding severity.  This test guards against a silent drop
    // of the note (e.g. if the cache path refactors without preserving
    // the call to `record_engine_note`).
    let dir = fixture_path("inline_cache_origin_attribution");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    let has_inline_cache_reused = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .any(|d| {
            d.evidence
                .as_ref()
                .map(|e| {
                    e.engine_notes.iter().any(|n| {
                        matches!(n, nyx_scanner::engine_notes::EngineNote::InlineCacheReused)
                    })
                })
                .unwrap_or(false)
        });

    assert!(
        has_inline_cache_reused,
        "expected at least one taint finding carrying the \
         `InlineCacheReused` engine note — either inline cache was never \
         consulted (a regression in the context-sensitive path) or the \
         note is no longer being recorded on cache-hit apply."
    );
}
