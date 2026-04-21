//! Parse-timeout integration test (isolated in its own binary so the
//! installed analysis-options runtime cannot race with other tests).
//!
//! Tree-sitter parsing is normally fast, but adversarial inputs can drive
//! it into much slower parses.  The scanner enforces a per-file timeout via
//! a progress callback; this test verifies the wiring end-to-end by setting
//! the timeout to 1 ms and confirming that a moderately-sized file is
//! *skipped* rather than parsed.
//!
//! The timeout is configured via `analysis.engine.parse_timeout_ms` (or
//! `--parse-timeout-ms` on the CLI); this test drives it by installing a
//! custom `AnalysisOptions` at process start.

use nyx_scanner::ast::run_rules_on_bytes;
use nyx_scanner::utils::AnalysisOptions;
use nyx_scanner::utils::analysis_options;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::Path;
use std::time::{Duration, Instant};

fn hostile_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 8;
    cfg.performance.channel_multiplier = 1;
    cfg
}

/// Generate a large but valid JS source: many short statements on one line.
/// O(n) in size so the test harness itself is not a bottleneck.
fn build_bulk_source(bytes_target: usize) -> String {
    let mut s = String::with_capacity(bytes_target + 64);
    let mut i: usize = 0;
    while s.len() < bytes_target {
        use std::fmt::Write;
        let _ = write!(s, "var a{i}=1;");
        i += 1;
    }
    s.push('\n');
    s
}

#[test]
fn parse_timeout_config_short_circuits_parse() {
    // ~1 MiB of valid JS — plenty of real parser work to observe the
    // timeout.  Still well under MAX_PARSE_BYTES.
    let source = build_bulk_source(1_000_000);

    // Install a 1 ms timeout via the analysis-options runtime.  This test
    // runs in its own integration-test binary (separate process), so the
    // `OnceLock` install cannot collide with other tests.
    analysis_options::install(AnalysisOptions {
        parse_timeout_ms: 1,
        ..AnalysisOptions::default()
    });

    let path = Path::new("slow.js");
    let cfg = hostile_cfg();

    let start = Instant::now();
    let diags = run_rules_on_bytes(source.as_bytes(), path, &cfg, None, None)
        .expect("timeout should yield Ok(empty), not error");
    let elapsed = start.elapsed();

    assert!(
        diags.is_empty(),
        "timed-out parse should produce no findings, got {diags:?}",
    );
    // With a 1 ms cap, tree-sitter should be cancelled and the file
    // skipped long before a cold full-analysis run would finish.  A
    // 2 s budget is a generous bound even for slow debug builds.
    assert!(
        elapsed < Duration::from_secs(2),
        "parse-timeout cancellation did not short-circuit; call took {elapsed:?}",
    );
}
