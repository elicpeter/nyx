use criterion::{Criterion, criterion_group, criterion_main};
use nyx_scanner::utils::Config;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

const FIXTURES: &str = "benches/fixtures";

fn bench_ast_only_scan(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Ast;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("ast_only_scan", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, None, Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_full_scan(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("full_scan", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();

            // Pass 1: extract summaries
            let mut all_sums = Vec::new();
            for path in &paths {
                if let Ok(sums) = nyx_scanner::ast::extract_summaries_from_file(path, &cfg) {
                    all_sums.extend(sums);
                }
            }
            let root_str = fixtures.to_string_lossy();
            let global = nyx_scanner::summary::merge_summaries(all_sums, Some(&root_str));

            // Pass 2: full analysis
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, Some(&global), Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_single_file_parse_and_cfg(c: &mut Criterion) {
    let fixture = Path::new(FIXTURES).join("sample.rs");
    let fixture = fixture.canonicalize().expect("sample.rs fixture");
    let cfg = Config::default();

    c.bench_function("single_file_parse_cfg", |b| {
        b.iter(|| {
            nyx_scanner::ast::extract_summaries_from_file(&fixture, &cfg)
                .expect("extract summaries")
        });
    });
}

fn bench_classify(c: &mut Criterion) {
    c.bench_function("classify_hit", |b| {
        b.iter(|| nyx_scanner::labels::classify("rust", "std::env::var", None));
    });

    c.bench_function("classify_miss", |b| {
        b.iter(|| nyx_scanner::labels::classify("rust", "some_random_function", None));
    });
}

criterion_group!(
    benches,
    bench_ast_only_scan,
    bench_full_scan,
    bench_single_file_parse_and_cfg,
    bench_classify,
);
criterion_main!(benches);
