use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence};
use crate::patterns::{FindingCategory, Severity};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

/// Compact related-finding reference for the detail panel.
#[derive(Debug, Clone, Serialize)]
pub struct RelatedFindingView {
    pub index: usize,
    pub rule_id: String,
    pub path: String,
    pub line: usize,
    pub severity: Severity,
}

/// Serializable API representation of a Diag finding.
#[derive(Debug, Clone, Serialize)]
pub struct FindingView {
    pub index: usize,
    pub path: String,
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub rule_id: String,
    pub category: FindingCategory,
    pub confidence: Option<Confidence>,
    pub rank_score: Option<f64>,
    pub message: Option<String>,
    pub labels: Vec<(String, String)>,
    pub path_validated: bool,
    pub suppressed: bool,
    pub language: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_context: Option<CodeContextView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank_reason: Option<Vec<(String, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizer_status: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_findings: Vec<RelatedFindingView>,
}

/// Lines of source code around a finding for display.
#[derive(Debug, Clone, Serialize)]
pub struct CodeContextView {
    pub start_line: usize,
    pub lines: Vec<String>,
    pub highlight_line: usize,
}

/// Aggregate statistics for a set of findings.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FindingSummary {
    pub total: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_rule: HashMap<String, usize>,
    pub by_file: HashMap<String, usize>,
}

/// A scan job as seen by the API.
#[derive(Debug, Clone, Serialize)]
pub struct ScanView {
    pub id: String,
    pub status: String,
    pub scan_root: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_secs: Option<f64>,
    pub finding_count: Option<usize>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_scanned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<crate::server::progress::TimingBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::server::progress::ScanMetricsSnapshot>,
}

/// Custom rule view for the config API.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct RuleView {
    pub lang: String,
    pub matchers: Vec<String>,
    pub kind: String,
    pub cap: String,
}

/// Terminator view for the config API.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TerminatorView {
    pub lang: String,
    pub name: String,
}

/// Distinct filter values available in a set of findings.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FilterValues {
    pub severities: Vec<String>,
    pub categories: Vec<String>,
    pub confidences: Vec<String>,
    pub languages: Vec<String>,
    pub rules: Vec<String>,
    pub statuses: Vec<String>,
}

/// Collect distinct filter values from a slice of diagnostics.
pub fn collect_filter_values(findings: &[Diag]) -> FilterValues {
    let mut severities = BTreeSet::new();
    let mut categories = BTreeSet::new();
    let mut confidences = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut rules = BTreeSet::new();
    let mut statuses = BTreeSet::new();

    for d in findings {
        severities.insert(d.severity.as_db_str().to_string());
        categories.insert(d.category.to_string());
        if let Some(c) = d.confidence {
            confidences.insert(format!("{c:?}"));
        }
        if let Some(lang) = lang_for_finding_path(&d.path) {
            languages.insert(lang);
        }
        rules.insert(d.id.clone());
        statuses.insert(status_for_diag(d).to_string());
    }

    FilterValues {
        severities: severities.into_iter().collect(),
        categories: categories.into_iter().collect(),
        confidences: confidences.into_iter().collect(),
        languages: languages.into_iter().collect(),
        rules: rules.into_iter().collect(),
        statuses: statuses.into_iter().collect(),
    }
}

/// Map a finding file path extension to a human-readable language name.
pub fn lang_for_finding_path(path: &str) -> Option<String> {
    let ext = path.rsplit('.').next()?;
    match ext.to_ascii_lowercase().as_str() {
        "rs" => Some("Rust".into()),
        "c" => Some("C".into()),
        "cpp" => Some("C++".into()),
        "java" => Some("Java".into()),
        "go" => Some("Go".into()),
        "php" => Some("PHP".into()),
        "py" => Some("Python".into()),
        "ts" => Some("TypeScript".into()),
        "js" => Some("JavaScript".into()),
        "rb" => Some("Ruby".into()),
        _ => None,
    }
}

/// Compute the status string for a diagnostic.
fn status_for_diag(d: &Diag) -> &'static str {
    if d.suppressed {
        "suppressed"
    } else if d.path_validated {
        "validated"
    } else {
        "open"
    }
}

/// Convert a Diag to a FindingView at a given index.
pub fn finding_from_diag(index: usize, d: &Diag) -> FindingView {
    FindingView {
        index,
        path: d.path.clone(),
        line: d.line,
        col: d.col,
        severity: d.severity,
        rule_id: d.id.clone(),
        category: d.category,
        confidence: d.confidence,
        rank_score: d.rank_score,
        message: d.message.clone(),
        labels: d.labels.clone(),
        path_validated: d.path_validated,
        suppressed: d.suppressed,
        language: lang_for_finding_path(&d.path),
        status: status_for_diag(d).to_string(),
        code_context: None,
        evidence: None,
        guard_kind: None,
        rank_reason: None,
        sanitizer_status: None,
        related_findings: vec![],
    }
}

/// Convert a Diag to a FindingView with code context loaded from disk.
pub fn finding_from_diag_with_context(
    index: usize,
    d: &Diag,
    scan_root: &Path,
) -> FindingView {
    let mut view = finding_from_diag(index, d);
    view.code_context = load_code_context(&d.path, d.line, scan_root);
    view
}

/// Convert a Diag to a FindingView with full detail (evidence, related findings).
pub fn finding_from_diag_with_detail(
    index: usize,
    d: &Diag,
    scan_root: &Path,
    all_findings: &[Diag],
) -> FindingView {
    let mut view = finding_from_diag_with_context(index, d, scan_root);

    // Evidence (pass through the core type directly)
    view.evidence = d.evidence.clone();
    view.guard_kind = d.guard_kind.clone();
    view.rank_reason = d.rank_reason.clone();

    // Sanitizer status
    view.sanitizer_status = Some(compute_sanitizer_status(d));

    // Related findings: same rule_id OR same file, excluding self, capped at 10
    let mut related = Vec::new();
    for (i, other) in all_findings.iter().enumerate() {
        if i == index {
            continue;
        }
        if other.id == d.id || other.path == d.path {
            related.push(RelatedFindingView {
                index: i,
                rule_id: other.id.clone(),
                path: other.path.clone(),
                line: other.line,
                severity: other.severity,
            });
            if related.len() >= 10 {
                break;
            }
        }
    }
    view.related_findings = related;

    view
}

/// Compute the sanitizer status for a diagnostic based on its evidence.
fn compute_sanitizer_status(d: &Diag) -> String {
    match &d.evidence {
        Some(ev) if !ev.sanitizers.is_empty() => {
            if d.suppressed {
                "applied".into()
            } else {
                "bypassed".into()
            }
        }
        _ => "none".into(),
    }
}

/// Load surrounding lines of code for a finding.
fn load_code_context(path: &str, line: usize, scan_root: &Path) -> Option<CodeContextView> {
    let full_path = scan_root.join(path);
    let content = fs::read_to_string(&full_path).ok()?;
    let all_lines: Vec<&str> = content.lines().collect();

    if line == 0 || line > all_lines.len() {
        return None;
    }

    let context_radius = 5;
    let start = line.saturating_sub(context_radius).max(1);
    let end = (line + context_radius).min(all_lines.len());

    let lines: Vec<String> = all_lines[start - 1..end]
        .iter()
        .map(|l| (*l).to_string())
        .collect();

    Some(CodeContextView {
        start_line: start,
        lines,
        highlight_line: line,
    })
}

/// Build a summary from a slice of findings.
pub fn summarize_findings(findings: &[Diag]) -> FindingSummary {
    let mut summary = FindingSummary {
        total: findings.len(),
        ..Default::default()
    };

    for d in findings {
        let sev_key = d.severity.as_db_str().to_string();
        *summary.by_severity.entry(sev_key).or_insert(0) += 1;
        *summary
            .by_category
            .entry(d.category.to_string())
            .or_insert(0) += 1;
        *summary.by_rule.entry(d.id.clone()).or_insert(0) += 1;
        *summary.by_file.entry(d.path.clone()).or_insert(0) += 1;
    }

    summary
}
