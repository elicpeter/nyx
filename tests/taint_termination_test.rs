//! Regression tests for taint BFS termination.
//!
//! Before the fix in taint/mod.rs (MAX_BFS_ITERATIONS / MAX_SEEN_STATES),
//! files with many tainted variables and loops caused the BFS to run
//! forever because each loop iteration produced a distinct taint-map hash,
//! bypassing the `(node, taint_hash)` seen-state dedup.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::Config;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Shared result so we only run the scan once across all assertions.
fn scan_fixture() -> &'static Vec<Diag> {
    static DIAGS: OnceLock<Vec<Diag>> = OnceLock::new();
    DIAGS.get_or_init(|| {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/taint_termination");
        let cfg = Config::default();
        nyx_scanner::scan_no_index(&fixture, &cfg).expect("scan should succeed")
    })
}

/// The scan must complete in a reasonable time.  The old code hung forever
/// on this fixture; with the BFS limit it should finish in well under 10s.
#[test]
fn taint_bfs_terminates_within_timeout() {
    let start = Instant::now();
    let _diags = scan_fixture();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "Taint BFS took {:?} — should complete in <10s (was infinite before fix)",
        elapsed
    );
}

/// The scan should still produce meaningful findings even after bail-out.
#[test]
fn taint_bfs_produces_findings_after_bailout() {
    let diags = scan_fixture();
    // We should get at least *some* findings (cfg-unguarded-sink at minimum,
    // possibly taint findings depending on how far the BFS got).
    assert!(
        !diags.is_empty(),
        "Expected at least some findings from heavy_loop.js fixture"
    );
}

/// Scan a single-file fixture directory via --no-index path.  This is the
/// exact code path that hung: `scan_filesystem` → `par_iter().fold().reduce()`.
#[test]
fn scan_no_index_completes() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/taint_termination");
    let cfg = Config::default();

    let start = Instant::now();
    let result = nyx_scanner::scan_no_index(&fixture, &cfg);
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "scan should not error");
    assert!(
        elapsed < Duration::from_secs(10),
        "scan took {:?} on small fixture",
        elapsed
    );
}

/// Indexed path: build_index + scan_with_index_parallel must also complete.
#[test]
fn scan_with_index_completes() {
    use nyx_scanner::commands::scan::scan_with_index_parallel;
    use nyx_scanner::database::index::Indexer;
    use std::sync::Arc;

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/taint_termination");
    let td = tempfile::tempdir().unwrap();
    let db_path = td.path().join("test.sqlite");
    let cfg = Config::default();

    let start = Instant::now();

    // Build index
    nyx_scanner::commands::index::build_index("test", &fixture, &db_path, &cfg, false)
        .expect("build_index should succeed");

    // Scan with index
    let pool = Indexer::init(&db_path).unwrap();
    let diags = scan_with_index_parallel("test", Arc::clone(&pool), &cfg, false)
        .expect("indexed scan should succeed");

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "Indexed scan took {:?} on small fixture",
        elapsed
    );
    // Should produce findings just like the no-index path
    assert!(!diags.is_empty(), "Expected findings from indexed scan");
}
