//! Regression guard: per-thread-count determinism.
//!
//! The scanner's two-pass pipeline runs rayon `par_iter` over files in
//! both pass-1 (summary extraction) and pass-2 (rule evaluation), and
//! merges summaries via `try_reduce`.  A latent ordering bug, a
//! shared mutable state hit unprotected from multiple threads, or a
//! `HashMap` iteration order leaking into a finding identity, can
//! surface as a diagnostic that appears with 4 workers but not with 1.
//!
//! This test runs the same fixture under worker-thread counts of 1,
//! 2, 4, and 8, then asserts the normalised finding set matches the
//! single-threaded baseline.  The normalisation strips volatile bits
//! (rank_score ordering ties, suppression book-keeping, etc.) so the
//! assertion fires only on real output divergence.
//!
//! If this test ever flakes, prefer investigating the engine over
//! weakening the normaliser, engine-level determinism across thread
//! counts is load-bearing for reproducible CI runs.
mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::scan_no_index;
use nyx_scanner::utils::config::AnalysisMode;
use rayon::ThreadPoolBuilder;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Canonicalised fingerprint of a finding used for cross-thread
/// equality.  Includes the structural fields that should be
/// deterministic across thread counts and excludes volatile
/// bookkeeping (rank_score float ties, suppression metadata with
/// pointer-derived content).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingKey {
    path: String,
    line: usize,
    col: usize,
    rule_id: String,
    severity: String,
    path_validated: bool,
    finding_id: String,
    alternative_finding_ids: Vec<String>,
}

fn project(diags: &[Diag]) -> Vec<FindingKey> {
    let mut keys: Vec<FindingKey> = diags
        .iter()
        .map(|d| {
            let mut alts = d.alternative_finding_ids.clone();
            alts.sort();
            FindingKey {
                path: d.path.clone(),
                line: d.line,
                col: d.col,
                rule_id: d.id.clone(),
                severity: d.severity.as_db_str().to_string(),
                path_validated: d.path_validated,
                finding_id: d.finding_id.clone(),
                alternative_finding_ids: alts,
            }
        })
        .collect();
    keys.sort();
    keys
}

/// Run a scan pinned to `threads` worker threads for both the file
/// walker and the rayon pass-1/2 parallel iterators.
fn run_scan_with_threads(fixture: &Path, threads: usize) -> Vec<Diag> {
    let mut cfg = test_config(AnalysisMode::Full);
    cfg.performance.worker_threads = Some(threads);

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("build rayon thread pool");

    pool.install(|| scan_no_index(fixture, &cfg).expect("scan_no_index should succeed"))
}

#[test]
fn scan_is_deterministic_across_thread_counts() {
    // A small cross-file fixture is enough to exercise the merge paths
    // that most often flake under thread contention.  `cross_file_js_sqli`
    // has both pass-1 summaries and a cross-file taint finding.
    let fixture = fixture_path("cross_file_js_sqli");

    let mut findings_by_threads: Vec<(usize, Vec<Diag>)> = Vec::new();
    for &threads in &[1usize, 2, 4, 8] {
        let diags = run_scan_with_threads(&fixture, threads);
        findings_by_threads.push((threads, diags));
    }

    let baseline = project(&findings_by_threads[0].1);
    assert!(
        !baseline.is_empty(),
        "baseline produced no findings — the determinism test relies on \
         a non-empty finding set to be meaningful. Check the fixture \
         still trips the engine."
    );

    for (threads, diags) in &findings_by_threads[1..] {
        let candidate = project(diags);
        assert_eq!(
            candidate,
            baseline,
            "worker_threads={} produced a different normalised finding \
             set than the 1-thread baseline. This indicates a \
             nondeterministic path in scan_filesystem — most likely a \
             shared mutable state accessed without synchronisation, or \
             a HashMap iteration order leaking into a finding \
             identity.\n\n\
             baseline ({} findings): {:#?}\n\n\
             candidate ({} findings): {:#?}",
            threads,
            baseline.len(),
            baseline,
            candidate.len(),
            candidate,
        );
    }
}
