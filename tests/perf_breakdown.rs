//! Hand-instrumented per-stage timing of the bench full_scan pipeline.
//!
//! Run with: cargo test --test perf_breakdown --release -- --nocapture stage_breakdown
//!
//! Not a regression test — prints µs/file for each pipeline stage so we can
//! locate hot stages without a sampling profiler.

use nyx_scanner::ast;
use nyx_scanner::utils::Config;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::time::Instant;

const FIXTURES: &str = "benches/fixtures";
const ITERATIONS: usize = 30;

fn pct(samples: &mut Vec<u128>, p: f64) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let idx = ((samples.len() as f64 - 1.0) * p) as usize;
    samples[idx]
}

/// Mirrors the production `scan_filesystem` pass-1 + pass-2 shape: both
/// passes call `analyse_file_fused` (pass 1 with `global=None`, pass 2 with
/// `global=Some`).  This is the path the perf fix targets — the bench
/// `full_scan` benchmark instead uses `extract_summaries_from_file` +
/// `run_rules_on_file`, which doesn't exercise the
/// `lower_all_functions_from_bodies` redundancy fixed below.
#[test]
fn fused_walltime() {
    use nyx_scanner::ast::analyse_file_fused;
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;

    let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
    handle.join().unwrap();
    let paths: Vec<_> = rx.into_iter().flatten().collect();
    let bytes_per: Vec<Vec<u8>> = paths
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    eprintln!("=== fused_walltime: {} files", paths.len());

    let mut t_total = vec![];
    let mut t_pass1 = vec![];
    let mut t_pass2 = vec![];
    let mut per_file_pass1: Vec<Vec<u128>> = (0..paths.len()).map(|_| Vec::new()).collect();
    let mut per_file_pass2: Vec<Vec<u128>> = (0..paths.len()).map(|_| Vec::new()).collect();

    for _iter in 0..ITERATIONS {
        let t0 = Instant::now();

        // Pass 1: analyse_file_fused with global=None, collect summaries.
        let p1_start = Instant::now();
        let mut local_gs = nyx_scanner::summary::GlobalSummaries::new();
        let root_str = fixtures.to_string_lossy();
        for (i, path) in paths.iter().enumerate() {
            let s = Instant::now();
            if let Ok(r) = analyse_file_fused(&bytes_per[i], path, &cfg, None, Some(&fixtures)) {
                for s in r.summaries {
                    let key = s.func_key(Some(&root_str));
                    local_gs.insert(key, s);
                }
                for (key, ssa_sum) in r.ssa_summaries {
                    local_gs.insert_ssa(key, ssa_sum);
                }
                for (key, body) in r.ssa_bodies {
                    local_gs.insert_body(key, body);
                }
                for (key, auth_sum) in r.auth_summaries {
                    local_gs.insert_auth(key, auth_sum);
                }
            }
            per_file_pass1[i].push(s.elapsed().as_micros());
        }
        t_pass1.push(p1_start.elapsed().as_micros());
        local_gs.install_hierarchy();

        // Pass 2: analyse_file_fused with global=Some.
        let p2_start = Instant::now();
        for (i, path) in paths.iter().enumerate() {
            let s = Instant::now();
            let _ = analyse_file_fused(
                &bytes_per[i],
                path,
                &cfg,
                Some(&local_gs),
                Some(&fixtures),
            );
            per_file_pass2[i].push(s.elapsed().as_micros());
        }
        t_pass2.push(p2_start.elapsed().as_micros());
        t_total.push(t0.elapsed().as_micros());
    }

    eprintln!();
    eprintln!("=== Wall-clock totals (µs, n={ITERATIONS}) ===");
    let p50 = pct(&mut t_total.clone(), 0.5);
    eprintln!(
        "total      p50={:>8}  p90={:>8}  p99={:>8}",
        p50,
        pct(&mut t_total.clone(), 0.9),
        pct(&mut t_total.clone(), 0.99)
    );
    eprintln!(
        "pass1      p50={:>8}  p90={:>8}  p99={:>8}",
        pct(&mut t_pass1.clone(), 0.5),
        pct(&mut t_pass1.clone(), 0.9),
        pct(&mut t_pass1.clone(), 0.99),
    );
    eprintln!(
        "pass2      p50={:>8}  p90={:>8}  p99={:>8}",
        pct(&mut t_pass2.clone(), 0.5),
        pct(&mut t_pass2.clone(), 0.9),
        pct(&mut t_pass2.clone(), 0.99),
    );
    eprintln!();
    eprintln!("=== Per-file µs (median across iterations) ===");
    eprintln!("{:<22} | {:>9} | {:>9} | {:>9}", "fixture", "pass1", "pass2", "p1+p2");
    let mut tot1 = 0u128;
    let mut tot2 = 0u128;
    for (i, path) in paths.iter().enumerate() {
        let m1 = pct(&mut per_file_pass1[i].clone(), 0.5);
        let m2 = pct(&mut per_file_pass2[i].clone(), 0.5);
        tot1 += m1;
        tot2 += m2;
        let name = path.file_name().unwrap().to_string_lossy();
        eprintln!("{:<22} | {:>9} | {:>9} | {:>9}", name, m1, m2, m1 + m2);
    }
    eprintln!(
        "{:<22} | {:>9} | {:>9} | {:>9}",
        "TOTAL", tot1, tot2, tot1 + tot2
    );
}

#[test]
fn stage_breakdown() {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;

    let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
    handle.join().unwrap();
    let paths: Vec<_> = rx.into_iter().flatten().collect();
    eprintln!("=== perf_breakdown: {} files in {:?}", paths.len(), fixtures);

    // Stage timings: [parse+CFG, taint+SSA, suppression, ast queries, auth, extract_ssa_artifacts]
    let mut stage: [Vec<Vec<u128>>; 6] = std::array::from_fn(|_| {
        (0..paths.len()).map(|_| Vec::new()).collect()
    });
    let mut t_pass1_total = vec![];
    let mut t_pass2_total = vec![];

    for _iter in 0..ITERATIONS {
        // Pass 1
        let p1_start = Instant::now();
        let mut all_sums = Vec::new();
        for path in &paths {
            if let Ok(sums) = ast::extract_summaries_from_file(path, &cfg) {
                all_sums.extend(sums);
            }
        }
        t_pass1_total.push(p1_start.elapsed().as_micros());

        let root_str = fixtures.to_string_lossy();
        let global = nyx_scanner::summary::merge_summaries(all_sums, Some(&root_str));

        // Pass 2 with stage breakdown
        let p2_start = Instant::now();
        for (i, path) in paths.iter().enumerate() {
            let bytes = std::fs::read(path).unwrap();
            if let Some(timings) = ast::perf_stage_breakdown(
                &bytes, path, &cfg, Some(&global), Some(&fixtures),
            ) {
                for (s, t) in timings.iter().enumerate() {
                    stage[s][i].push(*t);
                }
            }
        }
        t_pass2_total.push(p2_start.elapsed().as_micros());
    }

    let stage_names = [
        "parse+CFG",
        "taint+SSA",
        "suppression",
        "ast queries",
        "auth",
        "ssa-artifacts (extract)",
    ];

    eprintln!();
    eprintln!("=== Stage totals (sum of medians, µs) ===");
    let mut tot_per_stage = [0u128; 6];
    for s in 0..6 {
        let mut sum = 0u128;
        for i in 0..paths.len() {
            sum += pct(&mut stage[s][i].clone(), 0.5);
        }
        tot_per_stage[s] = sum;
    }
    let stage_total: u128 = tot_per_stage.iter().sum();
    let pass1_p50 = pct(&mut t_pass1_total.clone(), 0.5);
    let pass2_p50 = pct(&mut t_pass2_total.clone(), 0.5);
    eprintln!("  pass1 wallclock p50   : {pass1_p50:>8} µs");
    eprintln!(
        "  pass2 wallclock p50   : {pass2_p50:>8} µs   (this includes the extra perf-helper overhead)"
    );
    eprintln!("  stage sum             : {stage_total:>8} µs");
    eprintln!();
    for (s, n) in stage_names.iter().enumerate() {
        let pct_of_stage = 100.0 * tot_per_stage[s] as f64 / stage_total.max(1) as f64;
        eprintln!(
            "  {:<26} {:>8} µs   {:>5.1}% of stage sum",
            n, tot_per_stage[s], pct_of_stage
        );
    }
    eprintln!();
    eprintln!("=== Per-file µs (median across iterations) ===");
    eprintln!(
        "{:<22} | {:>9} | {:>9} | {:>11} | {:>11} | {:>9} | {:>11}",
        "fixture", "parseCFG", "taint", "suppress", "astQ", "auth", "ssa-art"
    );
    for (i, path) in paths.iter().enumerate() {
        let med: Vec<u128> = (0..6).map(|s| pct(&mut stage[s][i].clone(), 0.5)).collect();
        let name = path.file_name().unwrap().to_string_lossy();
        eprintln!(
            "{:<22} | {:>9} | {:>9} | {:>11} | {:>11} | {:>9} | {:>11}",
            name, med[0], med[1], med[2], med[3], med[4], med[5]
        );
    }
}
