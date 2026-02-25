// Shared test helpers for integration and perf tests.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use serde::Deserialize;
use std::path::Path;

// ── Deterministic test config ──────────────────────────────────────────────

pub fn test_config(mode: AnalysisMode) -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = mode;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

// ── Scan helpers ───────────────────────────────────────────────────────────

/// Full two-pass scan of a directory (filesystem only, no index).
pub fn scan_fixture_dir(path: &Path, mode: AnalysisMode) -> Vec<Diag> {
    let cfg = test_config(mode);
    nyx_scanner::scan_no_index(path, &cfg).expect("scan_no_index should succeed")
}

// ── Counting / assertion helpers ───────────────────────────────────────────

pub fn count_by_prefix(diags: &[Diag], prefix: &str) -> usize {
    diags.iter().filter(|d| d.id.starts_with(prefix)).count()
}

pub fn assert_min_findings(diags: &[Diag], prefix: &str, min: usize) {
    let count = count_by_prefix(diags, prefix);
    assert!(
        count >= min,
        "Expected >= {min} findings matching prefix '{prefix}', but found {count}.\n\
         All findings: {:#?}",
        diags
            .iter()
            .map(|d| format!(
                "  {}:{}:{} [{}] {}",
                d.path,
                d.line,
                d.col,
                d.severity.as_db_str(),
                d.id
            ))
            .collect::<Vec<_>>()
    );
}

pub fn assert_no_findings(diags: &[Diag], prefix: &str) {
    let matching: Vec<_> = diags.iter().filter(|d| d.id.starts_with(prefix)).collect();
    assert!(
        matching.is_empty(),
        "Expected 0 findings matching prefix '{prefix}', but found {}:\n{:#?}",
        matching.len(),
        matching
            .iter()
            .map(|d| format!("  {}:{}:{} {}", d.path, d.line, d.col, d.id))
            .collect::<Vec<_>>()
    );
}

pub fn assert_max_findings(diags: &[Diag], max_total: usize, max_high: usize) {
    let high_count = diags
        .iter()
        .filter(|d| d.severity.as_db_str() == "HIGH")
        .count();
    assert!(
        diags.len() <= max_total,
        "Noise budget exceeded: {}/{max_total} total findings.\n\
         All findings: {:?}",
        diags.len(),
        diags
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>()
    );
    assert!(
        high_count <= max_high,
        "Noise budget exceeded: {high_count}/{max_high} HIGH findings."
    );
}

// ── expectations.json schema ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Expectations {
    pub required_findings: Vec<RequiredFinding>,
    #[serde(default)]
    pub forbidden_findings: Vec<ForbiddenFinding>,
    pub noise_budget: NoiseBudget,
    pub performance_expectations: PerformanceExpectations,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RequiredFinding {
    pub id_prefix: String,
    pub min_count: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ForbiddenFinding {
    pub id_prefix: String,
    #[serde(default)]
    pub file_glob: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct NoiseBudget {
    pub max_total_findings: usize,
    pub max_high_findings: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PerformanceExpectations {
    pub max_ms_no_index: u64,
    pub max_ms_index_cold: u64,
    pub max_ms_index_warm: u64,
    pub ci_mode: String,
}

/// Load and parse `expectations.json` from a fixture directory.
pub fn load_expectations(fixture_dir: &Path) -> Expectations {
    let path = fixture_dir.join("expectations.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()))
}

/// Validate a set of diagnostics against a fixture's expectations.json.
pub fn validate_expectations(diags: &[Diag], fixture_dir: &Path) {
    let exp = load_expectations(fixture_dir);

    // Required findings
    for req in &exp.required_findings {
        assert_min_findings(diags, &req.id_prefix, req.min_count);
    }

    // Forbidden findings
    for forb in &exp.forbidden_findings {
        if let Some(glob) = &forb.file_glob {
            let pattern =
                glob::Pattern::new(glob).unwrap_or_else(|e| panic!("Invalid glob '{glob}': {e}"));
            let matching: Vec<_> = diags
                .iter()
                .filter(|d| d.id.starts_with(&forb.id_prefix) && pattern.matches(&d.path))
                .collect();
            assert!(
                matching.is_empty(),
                "Forbidden finding '{}' in files matching '{}': found {}",
                forb.id_prefix,
                glob,
                matching.len()
            );
        } else {
            assert_no_findings(diags, &forb.id_prefix);
        }
    }

    // Noise budget
    assert_max_findings(
        diags,
        exp.noise_budget.max_total_findings,
        exp.noise_budget.max_high_findings,
    );
}
