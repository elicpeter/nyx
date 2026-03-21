//! Nyx Benchmark Evaluation Framework
//!
//! Run with: `cargo test benchmark_evaluation -- --ignored --nocapture`
//!
//! Filter with env vars:
//!   NYX_BENCH_LANG=python
//!   NYX_BENCH_CLASS=sqli
//!   NYX_BENCH_CASE=js-sqli-001
//!   NYX_BENCH_POSITIVE_ONLY=1
//!   NYX_BENCH_NEGATIVE_ONLY=1
//!   NYX_BENCH_TAG=express

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::patterns::FindingCategory;
use nyx_scanner::utils::config::AnalysisMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── Ground-truth schema ──────────────────────────────────────────────

#[derive(Deserialize)]
struct GroundTruth {
    #[allow(dead_code)]
    schema_version: String,
    #[allow(dead_code)]
    metadata: Metadata,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Metadata {
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    created: String,
    #[allow(dead_code)]
    corpus_size: usize,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    file: String,
    language: String,
    is_vulnerable: bool,
    vuln_class: String,
    #[allow(dead_code)]
    cwe: String,
    #[allow(dead_code)]
    provenance: String,
    #[allow(dead_code)]
    equivalence_tier: String,
    #[allow(dead_code)]
    match_mode: String,
    expected_rule_ids: Vec<String>,
    allowed_alternative_rule_ids: Vec<String>,
    forbidden_rule_ids: Vec<String>,
    #[allow(dead_code)]
    expected_severity: Option<String>,
    #[allow(dead_code)]
    expected_category: Option<String>,
    expected_sink_lines: Option<Vec<[usize; 2]>>,
    #[allow(dead_code)]
    expected_source_lines: Option<Vec<[usize; 2]>>,
    #[allow(dead_code)]
    tags: Vec<String>,
    #[serde(default)]
    disabled: bool,
    #[allow(dead_code)]
    notes: String,
}

// ── Result types ─────────────────────────────────────────────────────

#[derive(Clone, Serialize)]
enum Outcome {
    TP,
    FP,
    FN,
    TN,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::TP => write!(f, "TP"),
            Outcome::FP => write!(f, "FP"),
            Outcome::FN => write!(f, "FN"),
            Outcome::TN => write!(f, "TN"),
        }
    }
}

#[derive(Serialize)]
struct CaseOutcome {
    case_id: String,
    file: String,
    language: String,
    vuln_class: String,
    is_vulnerable: bool,
    outcome_file_level: Outcome,
    outcome_rule_level: Outcome,
    outcome_location_level: Option<Outcome>,
    matched_rule_ids: Vec<String>,
    unexpected_rule_ids: Vec<String>,
    all_finding_ids: Vec<String>,
    security_finding_count: usize,
    non_security_finding_count: usize,
}

#[derive(Serialize)]
struct Metrics {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
    precision: f64,
    recall: f64,
    f1: f64,
}

impl Metrics {
    fn compute(tp: usize, fp: usize, fn_: usize, tn: usize) -> Self {
        let precision = if tp + fp == 0 {
            1.0
        } else {
            tp as f64 / (tp + fp) as f64
        };
        let recall = if tp + fn_ == 0 {
            1.0
        } else {
            tp as f64 / (tp + fn_) as f64
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        Metrics {
            tp,
            fp,
            fn_,
            tn,
            precision,
            recall,
            f1,
        }
    }
}

#[derive(Serialize)]
struct ScannerConfig {
    analysis_mode: String,
    taint_enabled: bool,
    ast_patterns_enabled: bool,
    state_analysis_enabled: bool,
    worker_threads: usize,
}

#[derive(Serialize)]
struct BenchmarkResults {
    benchmark_version: String,
    timestamp: String,
    scanner_version: String,
    scanner_config: ScannerConfig,
    ground_truth_hash: String,
    corpus_size: usize,
    cases_run: usize,
    cases_skipped: usize,
    outcomes: Vec<CaseOutcome>,
    aggregate_file_level: Metrics,
    aggregate_rule_level: Metrics,
    by_language: BTreeMap<String, Metrics>,
    by_vuln_class: BTreeMap<String, Metrics>,
}

// ── Scanning ─────────────────────────────────────────────────────────

fn scan_corpus_file(corpus_root: &Path, relative_path: &str) -> Vec<Diag> {
    let source = corpus_root.join(relative_path);
    assert!(source.exists(), "Corpus file not found: {}", source.display());

    let tmp = tempfile::TempDir::with_prefix("nyx_bench_").expect("tempdir");
    let dest = tmp.path().join(source.file_name().unwrap());
    std::fs::copy(&source, &dest).expect("copy corpus file");

    let cfg = test_config(AnalysisMode::Full);
    let mut diags =
        nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed");

    // Normalize paths to filename only.
    for d in &mut diags {
        if let Some(fname) = Path::new(&d.path).file_name() {
            d.path = fname.to_string_lossy().to_string();
        }
    }

    // Sort deterministically.
    diags.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then(a.id.cmp(&b.id))
            .then(a.col.cmp(&b.col))
    });

    diags
}

// ── Scoring helpers ──────────────────────────────────────────────────

fn is_security(d: &Diag) -> bool {
    d.category == FindingCategory::Security
}

fn rule_matches(finding_id: &str, expected_id: &str) -> bool {
    if finding_id == expected_id {
        return true;
    }
    // Substring fallback: the expected id is contained in the finding id.
    finding_id.contains(expected_id)
}

fn score_file_level(case: &Case, diags: &[Diag]) -> Outcome {
    let has_security = diags.iter().any(is_security);
    match (case.is_vulnerable, has_security) {
        (true, true) => Outcome::TP,
        (true, false) => Outcome::FN,
        (false, true) => Outcome::FP,
        (false, false) => Outcome::TN,
    }
}

fn score_rule_level(case: &Case, diags: &[Diag]) -> (Outcome, Vec<String>, Vec<String>) {
    let security_diags: Vec<&Diag> = diags.iter().filter(|d| is_security(d)).collect();

    // Check forbidden rules.
    if case.is_vulnerable {
        for d in &security_diags {
            for forbidden in &case.forbidden_rule_ids {
                if rule_matches(&d.id, forbidden) {
                    // Wrong-reason detection counts as FP.
                    let matched = vec![];
                    let unexpected = security_diags.iter().map(|d| d.id.clone()).collect();
                    return (Outcome::FP, matched, unexpected);
                }
            }
        }
    }

    if !case.is_vulnerable {
        if security_diags.is_empty() {
            return (Outcome::TN, vec![], vec![]);
        } else {
            let unexpected = security_diags.iter().map(|d| d.id.clone()).collect();
            return (Outcome::FP, vec![], unexpected);
        }
    }

    // Positive case: check expected + alternative rule matches.
    let all_acceptable: Vec<&str> = case
        .expected_rule_ids
        .iter()
        .chain(case.allowed_alternative_rule_ids.iter())
        .map(|s| s.as_str())
        .collect();

    let mut matched = Vec::new();
    let mut unexpected = Vec::new();

    for d in &security_diags {
        let is_expected = all_acceptable.iter().any(|exp| rule_matches(&d.id, exp));
        if is_expected {
            matched.push(d.id.clone());
        } else {
            unexpected.push(d.id.clone());
        }
    }

    if matched.is_empty() {
        (Outcome::FN, matched, unexpected)
    } else {
        (Outcome::TP, matched, unexpected)
    }
}

fn score_location_level(
    case: &Case,
    diags: &[Diag],
    matched_rule_ids: &[String],
) -> Option<Outcome> {
    let expected_sinks = case.expected_sink_lines.as_ref()?;
    if expected_sinks.is_empty() {
        return None;
    }

    if !case.is_vulnerable {
        let has_security = diags.iter().any(is_security);
        return Some(if has_security {
            Outcome::FP
        } else {
            Outcome::TN
        });
    }

    // Check if any matched finding has a line within tolerance of expected sinks.
    let all_acceptable: Vec<&str> = case
        .expected_rule_ids
        .iter()
        .chain(case.allowed_alternative_rule_ids.iter())
        .map(|s| s.as_str())
        .collect();

    let security_diags: Vec<&Diag> = diags.iter().filter(|d| is_security(d)).collect();

    if matched_rule_ids.is_empty() {
        return Some(Outcome::FN);
    }

    for d in &security_diags {
        let is_expected = all_acceptable.iter().any(|exp| rule_matches(&d.id, exp));
        if !is_expected {
            continue;
        }
        for sink_range in expected_sinks {
            let lo = sink_range[0].saturating_sub(2);
            let hi = sink_range[1] + 2;
            if d.line >= lo && d.line <= hi {
                return Some(Outcome::TP);
            }
        }
    }

    // Rule matched but location didn't.
    Some(Outcome::FN)
}

// ── Filtering ────────────────────────────────────────────────────────

fn should_run(case: &Case) -> bool {
    if case.disabled {
        return false;
    }

    if let Ok(lang) = std::env::var("NYX_BENCH_LANG") {
        if case.language != lang {
            return false;
        }
    }
    if let Ok(class) = std::env::var("NYX_BENCH_CLASS") {
        if case.vuln_class != class {
            return false;
        }
    }
    if let Ok(id) = std::env::var("NYX_BENCH_CASE") {
        if case.case_id != id {
            return false;
        }
    }
    if std::env::var("NYX_BENCH_POSITIVE_ONLY").is_ok() {
        if !case.is_vulnerable {
            return false;
        }
    }
    if std::env::var("NYX_BENCH_NEGATIVE_ONLY").is_ok() {
        if case.is_vulnerable {
            return false;
        }
    }
    if let Ok(tag) = std::env::var("NYX_BENCH_TAG") {
        if !case.tags.iter().any(|t| t == &tag) {
            return false;
        }
    }

    true
}

// ── Aggregation ──────────────────────────────────────────────────────

fn aggregate(outcomes: &[CaseOutcome], level: &str) -> Metrics {
    let (mut tp, mut fp, mut fn_, mut tn) = (0, 0, 0, 0);
    for o in outcomes {
        let outcome = match level {
            "file" => &o.outcome_file_level,
            "rule" => &o.outcome_rule_level,
            _ => &o.outcome_file_level,
        };
        match outcome {
            Outcome::TP => tp += 1,
            Outcome::FP => fp += 1,
            Outcome::FN => fn_ += 1,
            Outcome::TN => tn += 1,
        }
    }
    Metrics::compute(tp, fp, fn_, tn)
}

fn aggregate_by_key(
    outcomes: &[CaseOutcome],
    key_fn: impl Fn(&CaseOutcome) -> &str,
) -> BTreeMap<String, Metrics> {
    let mut groups: BTreeMap<String, Vec<&CaseOutcome>> = BTreeMap::new();
    for o in outcomes {
        groups
            .entry(key_fn(o).to_string())
            .or_default()
            .push(o);
    }
    groups
        .into_iter()
        .map(|(k, cases)| {
            let (mut tp, mut fp, mut fn_, mut tn) = (0, 0, 0, 0);
            for o in &cases {
                match &o.outcome_rule_level {
                    Outcome::TP => tp += 1,
                    Outcome::FP => fp += 1,
                    Outcome::FN => fn_ += 1,
                    Outcome::TN => tn += 1,
                }
            }
            (k, Metrics::compute(tp, fp, fn_, tn))
        })
        .collect()
}

// ── Printing ─────────────────────────────────────────────────────────

fn print_case_table(outcomes: &[CaseOutcome]) {
    println!("\n{:<25} {:<40} {:<6} {:<6} {:<6} {:<4} {:<4}",
        "CASE_ID", "FILE", "FILE", "RULE", "LOC", "SEC", "OTH");
    println!("{}", "-".repeat(100));
    for o in outcomes {
        let loc = match &o.outcome_location_level {
            Some(out) => format!("{}", out),
            None => "-".to_string(),
        };
        println!(
            "{:<25} {:<40} {:<6} {:<6} {:<6} {:<4} {:<4}",
            o.case_id,
            truncate(&o.file, 39),
            o.outcome_file_level,
            o.outcome_rule_level,
            loc,
            o.security_finding_count,
            o.non_security_finding_count,
        );
    }
}

fn print_metrics_table(label: &str, metrics: &Metrics) {
    println!(
        "  {:<20} TP={:<4} FP={:<4} FN={:<4} TN={:<4}  P={:.3} R={:.3} F1={:.3}",
        label, metrics.tp, metrics.fp, metrics.fn_, metrics.tn,
        metrics.precision, metrics.recall, metrics.f1
    );
}

fn print_map_table(title: &str, map: &BTreeMap<String, Metrics>) {
    println!("\n  {}:", title);
    for (k, m) in map {
        print_metrics_table(k, m);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - max + 3..])
    }
}

// ── Main test ────────────────────────────────────────────────────────

#[test]
#[ignore]
fn benchmark_evaluation() {
    let benchmark_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/benchmark");
    let corpus_root = benchmark_dir.join("corpus");
    let gt_path = benchmark_dir.join("ground_truth.json");
    let results_dir = benchmark_dir.join("results");

    // Load ground truth.
    let gt_bytes = std::fs::read(&gt_path).expect("read ground_truth.json");
    let gt: GroundTruth = serde_json::from_slice(&gt_bytes).expect("parse ground_truth.json");

    // Compute ground truth hash for provenance.
    let gt_hash = format!("sha256:{}", sha256_hex(&gt_bytes));

    // Filter cases.
    let mut cases_skipped = 0usize;
    let cases_to_run: Vec<&Case> = gt
        .cases
        .iter()
        .filter(|c| {
            if !should_run(c) {
                cases_skipped += 1;
                false
            } else {
                true
            }
        })
        .collect();

    println!("\n=== Nyx Benchmark Evaluation ===");
    println!("Corpus: {} total, {} to run, {} skipped",
        gt.cases.len(), cases_to_run.len(), cases_skipped);

    // Run each case.
    let mut outcomes: Vec<CaseOutcome> = Vec::with_capacity(cases_to_run.len());

    for case in &cases_to_run {
        let diags = scan_corpus_file(&corpus_root, &case.file);

        let security_count = diags.iter().filter(|d| is_security(d)).count();
        let non_security_count = diags.len() - security_count;
        let all_finding_ids: Vec<String> = diags.iter().map(|d| d.id.clone()).collect();

        let file_outcome = score_file_level(case, &diags);
        let (rule_outcome, matched, unexpected) = score_rule_level(case, &diags);
        let loc_outcome = score_location_level(case, &diags, &matched);

        outcomes.push(CaseOutcome {
            case_id: case.case_id.clone(),
            file: case.file.clone(),
            language: case.language.clone(),
            vuln_class: case.vuln_class.clone(),
            is_vulnerable: case.is_vulnerable,
            outcome_file_level: file_outcome,
            outcome_rule_level: rule_outcome,
            outcome_location_level: loc_outcome,
            matched_rule_ids: matched,
            unexpected_rule_ids: unexpected,
            all_finding_ids,
            security_finding_count: security_count,
            non_security_finding_count: non_security_count,
        });
    }

    // Sort outcomes by case_id for deterministic output.
    outcomes.sort_by(|a, b| a.case_id.cmp(&b.case_id));

    // Print per-case table.
    print_case_table(&outcomes);

    // Compute aggregates.
    let agg_file = aggregate(&outcomes, "file");
    let agg_rule = aggregate(&outcomes, "rule");
    let by_language = aggregate_by_key(&outcomes, |o| &o.language);
    let by_class = aggregate_by_key(&outcomes, |o| &o.vuln_class);

    // Print summary.
    println!("\n=== Aggregate Metrics ===");
    print_metrics_table("File-level", &agg_file);
    print_metrics_table("Rule-level", &agg_rule);
    print_map_table("By language (rule-level)", &by_language);
    print_map_table("By vuln class (rule-level)", &by_class);

    // Write results JSON.
    std::fs::create_dir_all(&results_dir).ok();
    let results = BenchmarkResults {
        benchmark_version: "1.0".to_string(),
        timestamp: chrono_now(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        scanner_config: ScannerConfig {
            analysis_mode: "Full".to_string(),
            taint_enabled: true,
            ast_patterns_enabled: true,
            state_analysis_enabled: true,
            worker_threads: 1,
        },
        ground_truth_hash: gt_hash,
        corpus_size: gt.cases.len(),
        cases_run: outcomes.len(),
        cases_skipped,
        outcomes,
        aggregate_file_level: agg_file,
        aggregate_rule_level: agg_rule,
        by_language,
        by_vuln_class: by_class,
    };

    let results_path = results_dir.join("latest.json");
    let json = serde_json::to_string_pretty(&results).expect("serialize results");
    std::fs::write(&results_path, &json).expect("write results/latest.json");

    println!("\nResults written to: {}", results_path.display());
    println!("=== Benchmark complete ===\n");

    // ── Regression thresholds (Phase 22 baseline minus 5pp) ─────────
    // Baseline (2026-03-21): P=0.620 R=0.891 F1=0.731
    let rule = &results.aggregate_rule_level;
    assert!(
        rule.precision >= 0.57,
        "Rule-level precision {:.3} fell below threshold 0.570 (baseline 0.620)",
        rule.precision,
    );
    assert!(
        rule.recall >= 0.841,
        "Rule-level recall {:.3} fell below threshold 0.841 (baseline 0.891)",
        rule.recall,
    );
    assert!(
        rule.f1 >= 0.681,
        "Rule-level F1 {:.3} fell below threshold 0.681 (baseline 0.731)",
        rule.f1,
    );
}

// ── Utilities ────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    use std::io::Write;
    // Simple SHA-256 via command — avoids adding a crypto dependency.
    let mut child = std::process::Command::new("shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("shasum");
    child.stdin.as_mut().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    s.split_whitespace().next().unwrap_or("unknown").to_string()
}

fn chrono_now() -> String {
    // ISO 8601 timestamp without chrono dependency.
    let out = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .expect("date");
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .to_string()
}
