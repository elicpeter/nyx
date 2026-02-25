#[allow(dead_code)]
mod common;

use common::{load_expectations, test_config};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn is_ci_bench() -> bool {
    std::env::var("NYX_CI_BENCH").as_deref() == Ok("1")
        || std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
}

/// Run `scan_no_index` N times and return the median duration in ms.
fn bench_no_index(fixture_dir: &PathBuf, iterations: usize) -> u64 {
    let cfg = test_config(AnalysisMode::Full);
    let mut durations: Vec<u64> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = nyx_scanner::scan_no_index(fixture_dir, &cfg);
        durations.push(start.elapsed().as_millis() as u64);
    }

    durations.sort();
    durations[iterations / 2]
}

/// Run indexed scan (cold = new tempdir with fresh index, warm = second run).
fn bench_indexed(fixture_dir: &PathBuf, iterations: usize) -> (u64, u64) {
    use nyx_scanner::commands::index::build_index;
    use nyx_scanner::commands::scan::scan_with_index_parallel;
    use nyx_scanner::database::index::Indexer;

    let cfg = test_config(AnalysisMode::Full);
    let mut cold_durations: Vec<u64> = Vec::with_capacity(iterations);
    let mut warm_durations: Vec<u64> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let td = tempfile::tempdir().expect("tempdir");
        let db_path = td.path().join("bench.db");

        // Cold: build index + scan
        let start = Instant::now();
        build_index("bench", fixture_dir, &db_path, &cfg).expect("build_index");
        let pool = Indexer::init(&db_path).expect("db init");
        let _ = scan_with_index_parallel("bench", Arc::clone(&pool), &cfg);
        cold_durations.push(start.elapsed().as_millis() as u64);

        // Warm: second scan on same index — files unchanged
        let start = Instant::now();
        let _ = scan_with_index_parallel("bench", Arc::clone(&pool), &cfg);
        warm_durations.push(start.elapsed().as_millis() as u64);
    }

    cold_durations.sort();
    warm_durations.sort();
    (
        cold_durations[iterations / 2],
        warm_durations[iterations / 2],
    )
}

fn run_fixture_bench(name: &str) {
    let dir = fixture_path(name);
    let exp = load_expectations(&dir);
    let perf = &exp.performance_expectations;
    let iterations = 5;

    let no_index_ms = bench_no_index(&dir, iterations);
    println!(
        "[{name}] no-index: {no_index_ms}ms (threshold: {}ms)",
        perf.max_ms_no_index
    );

    let (cold_ms, warm_ms) = bench_indexed(&dir, iterations);
    println!(
        "[{name}] index-cold: {cold_ms}ms (threshold: {}ms)",
        perf.max_ms_index_cold
    );
    println!(
        "[{name}] index-warm: {warm_ms}ms (threshold: {}ms)",
        perf.max_ms_index_warm
    );

    if is_ci_bench() {
        let multiplier = if perf.ci_mode == "lenient" { 1.5 } else { 1.0 };
        let max_no_index = (perf.max_ms_no_index as f64 * multiplier) as u64;
        let max_cold = (perf.max_ms_index_cold as f64 * multiplier) as u64;
        let max_warm = (perf.max_ms_index_warm as f64 * multiplier) as u64;

        assert!(
            no_index_ms <= max_no_index,
            "[{name}] no-index exceeded threshold: {no_index_ms}ms > {max_no_index}ms"
        );
        assert!(
            cold_ms <= max_cold,
            "[{name}] index-cold exceeded threshold: {cold_ms}ms > {max_cold}ms"
        );
        assert!(
            warm_ms <= max_warm,
            "[{name}] index-warm exceeded threshold: {warm_ms}ms > {max_warm}ms"
        );
    }
}

#[test]
fn perf_rust_web_app() {
    run_fixture_bench("rust_web_app");
}

#[test]
fn perf_express_app() {
    run_fixture_bench("express_app");
}

#[test]
fn perf_flask_app() {
    run_fixture_bench("flask_app");
}

#[test]
fn perf_go_server() {
    run_fixture_bench("go_server");
}

#[test]
fn perf_c_utils() {
    run_fixture_bench("c_utils");
}

#[test]
fn perf_java_service() {
    run_fixture_bench("java_service");
}

#[test]
fn perf_mixed_project() {
    run_fixture_bench("mixed_project");
}
