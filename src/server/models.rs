use crate::commands::scan::Diag;
use crate::evidence::Confidence;
use crate::patterns::{FindingCategory, Severity};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_context: Option<CodeContextView>,
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
        code_context: None,
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
