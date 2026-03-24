//! Structured evidence and confidence types for scan diagnostics.
//!
//! These types capture the provenance of findings (source locations,
//! sanitizer/guard info, state-machine transitions) in a structured form
//! that can be serialized to JSON and consumed by ranking, filtering,
//! and downstream tooling.

use crate::commands::scan::Diag;
use crate::patterns::Severity;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// ─────────────────────────────────────────────────────────────────────────────
//  Confidence
// ─────────────────────────────────────────────────────────────────────────────

/// Confidence level for a diagnostic finding.
///
/// Ordered Low < Medium < High so that `>=` comparisons work naturally
/// for filtering (e.g. `--min-confidence medium` keeps Medium and High).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

impl FromStr for Confidence {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(format!(
                "unknown confidence level: {s:?} (expected low, medium, high)"
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Flow Steps
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of operation at a flow step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStepKind {
    Source,
    Assignment,
    Call,
    Phi,
    Sink,
}

impl fmt::Display for FlowStepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => write!(f, "source"),
            Self::Assignment => write!(f, "assignment"),
            Self::Call => write!(f, "call"),
            Self::Phi => write!(f, "phi"),
            Self::Sink => write!(f, "sink"),
        }
    }
}

/// A single step in a taint flow path (display-ready).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub step: u32,
    pub kind: FlowStepKind,
    pub file: String,
    pub line: u32,
    pub col: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_cross_file: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Symbolic verdict
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolic verification verdict for a taint path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Constraint solver confirmed the path is feasible.
    Confirmed,
    /// Constraint solver proved the path is infeasible.
    Infeasible,
    /// Constraint solver could not determine feasibility.
    Inconclusive,
    /// No symbolic analysis was attempted for this finding.
    NotAttempted,
}

/// Summary of symbolic constraint analysis for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicVerdict {
    /// The outcome of symbolic path feasibility analysis.
    pub verdict: Verdict,
    /// Number of path constraints checked during analysis.
    #[serde(default)]
    pub constraints_checked: u32,
    /// Number of distinct paths explored from source to sink.
    #[serde(default)]
    pub paths_explored: u32,
    /// Human-readable witness or proof sketch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
    /// Interprocedural call chains leading to callee-internal sinks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interproc_call_chains: Vec<Vec<String>>,
    /// Cutoff/fallback reasons that limited analysis precision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoff_notes: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Structured evidence for a diagnostic finding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// Where tainted data originated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SpanEvidence>,

    /// Where the dangerous operation happens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink: Option<SpanEvidence>,

    /// Validation guards protecting this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guards: Vec<SpanEvidence>,

    /// Sanitizers applied to this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sanitizers: Vec<SpanEvidence>,

    /// State-machine evidence (resource lifecycle / auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateEvidence>,

    /// Free-form notes for ranking and display.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,

    /// Kind of taint source (structured; replaces "source_kind:..." in notes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<crate::labels::SourceKind>,

    /// Number of SSA blocks between source and sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_count: Option<u16>,

    /// Whether this finding was resolved via a cross-function summary.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub uses_summary: bool,

    /// Number of matching capability bits between source and sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_specificity: Option<u8>,

    /// Step-by-step taint flow from source to sink.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_steps: Vec<FlowStep>,

    /// Human-readable explanation of the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// Reasons why confidence is not higher.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_limiters: Vec<String>,

    /// Symbolic constraint analysis verdict for this finding's taint path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbolic: Option<SymbolicVerdict>,
}

impl Evidence {
    /// Returns `true` if the evidence contains no useful data.
    pub fn is_empty(&self) -> bool {
        self.source.is_none()
            && self.sink.is_none()
            && self.guards.is_empty()
            && self.sanitizers.is_empty()
            && self.state.is_none()
            && self.notes.is_empty()
            && self.source_kind.is_none()
            && self.hop_count.is_none()
            && !self.uses_summary
            && self.cap_specificity.is_none()
            && self.flow_steps.is_empty()
            && self.explanation.is_none()
            && self.confidence_limiters.is_empty()
            && self.symbolic.is_none()
    }
}

/// A source-location evidence span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvidence {
    pub path: String,
    pub line: u32,
    pub col: u32,
    /// One of: `"source"`, `"sink"`, `"guard"`, `"sanitizer"`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Evidence from a state-machine analysis (resource lifecycle / auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvidence {
    /// The state machine: `"resource"` or `"auth"`.
    pub machine: String,
    /// Variable name if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// State before the event.
    pub from_state: String,
    /// State after the event.
    pub to_state: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  compute_confidence
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a confidence level for `diag` based on its rule ID, severity,
/// evidence, and analysis kind.
///
/// This is called as a post-pass after all findings are collected; findings
/// that already have a confidence set (e.g. from CFG analysis) are preserved.
pub fn compute_confidence(diag: &Diag) -> Confidence {
    // Degraded analysis caps confidence
    if let Some(ev) = &diag.evidence
        && ev.notes.iter().any(|n| n.starts_with("degraded:"))
    {
        return Confidence::Low;
    }

    let id = &diag.id;

    if id.starts_with("taint-") {
        return compute_taint_confidence(diag);
    }

    if id.starts_with("state-") {
        return match id.as_str() {
            "state-use-after-close" => Confidence::High,
            "state-double-close" => Confidence::High,
            "state-unauthed-access" => Confidence::High,
            "state-resource-leak" => Confidence::Medium,
            "state-resource-leak-possible" => Confidence::Low,
            _ => Confidence::Medium,
        };
    }

    if id.starts_with("cfg-") {
        // If CFG conversion already set confidence, preserve it
        return diag.confidence.unwrap_or(Confidence::Medium);
    }

    // AST patterns: High severity → Medium confidence, else Low
    if diag.severity == Severity::High {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Points-based confidence scoring for taint findings.
///
/// Uses evidence metadata (source kind, path length, validation, cap
/// specificity, summary resolution) to produce a nuanced confidence level
/// instead of the previous flat High assignment.
fn compute_taint_confidence(diag: &Diag) -> Confidence {
    let ev = match &diag.evidence {
        Some(e) => e,
        None => return Confidence::High, // no evidence struct → conservative High
    };

    let mut score: i32 = 0;

    // Source kind (prefer structured field, fall back to notes)
    score += match ev.source_kind {
        Some(kind) => structured_source_kind_score(kind),
        None => source_kind_score(&ev.notes),
    };

    // Evidence completeness
    let has_source = ev.source.is_some();
    let has_sink = ev.sink.is_some();
    let has_snippet = ev.source.as_ref().is_some_and(|s| s.snippet.is_some())
        || ev.sink.as_ref().is_some_and(|s| s.snippet.is_some());
    score += if has_source && has_sink && has_snippet {
        3
    } else if has_source && has_sink {
        2
    } else {
        1
    };

    // Hop count penalty (prefer structured field)
    score += match ev.hop_count {
        Some(count) => match count {
            0..=3 => 0,
            4..=8 => -1,
            _ => -2,
        },
        None => hop_count_score(&ev.notes),
    };

    // Path validation penalty (use Diag field directly)
    if diag.path_validated {
        score -= 3;
    }

    // Cap specificity bonus (prefer structured field)
    score += match ev.cap_specificity {
        Some(count) => if count == 1 { 1 } else { 0 },
        None => cap_specificity_score(&ev.notes),
    };

    // Summary resolution penalty (prefer structured field)
    if ev.uses_summary || ev.notes.iter().any(|n| n == "uses_summary") {
        score -= 1;
    }

    // Symbolic verdict adjustments
    if let Some(ref sv) = ev.symbolic {
        match sv.verdict {
            Verdict::Infeasible => score -= 5,
            Verdict::Confirmed => {
                // Stronger bonus when extract_witness produced a concrete payload
                // (contains "flows to" or "reaches"); raw Display-only fallback
                // from get_sink_witness does not contain these phrases.
                if sv.witness.as_ref().is_some_and(|w| w.contains("flows to") || w.contains("reaches")) {
                    score += 3;
                } else {
                    score += 2;
                }
            }
            Verdict::Inconclusive | Verdict::NotAttempted => {}
        }
    }

    match score {
        5.. => Confidence::High,
        2..=4 => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// Score a structured `SourceKind` value.
///
/// UserInput=+3, EnvironmentConfig=+2, Unknown/FileSystem=+1, Database/CaughtException=0.
fn structured_source_kind_score(kind: crate::labels::SourceKind) -> i32 {
    use crate::labels::SourceKind;
    match kind {
        SourceKind::UserInput => 3,
        SourceKind::EnvironmentConfig => 2,
        SourceKind::Unknown | SourceKind::FileSystem => 1,
        SourceKind::Database | SourceKind::CaughtException => 0,
    }
}

/// Extract source_kind from evidence notes and return points (legacy fallback).
///
/// UserInput=+3, EnvironmentConfig=+2, Unknown/FileSystem=+1, Database/CaughtException=0.
fn source_kind_score(notes: &[String]) -> i32 {
    for note in notes {
        if let Some(kind) = note.strip_prefix("source_kind:") {
            return match kind {
                "UserInput" => 3,
                "EnvironmentConfig" => 2,
                "Unknown" | "FileSystem" => 1,
                _ => 0, // Database, CaughtException, etc.
            };
        }
    }
    1 // conservative default if missing
}

/// Extract hop_count from evidence notes and return penalty.
///
/// 0–3 blocks = 0, 4–8 = −1, 9+ = −2.
fn hop_count_score(notes: &[String]) -> i32 {
    for note in notes {
        if let Some(count_str) = note.strip_prefix("hop_count:") {
            if let Ok(count) = count_str.parse::<u16>() {
                return match count {
                    0..=3 => 0,
                    4..=8 => -1,
                    _ => -2,
                };
            }
        }
    }
    0 // no hop info → no penalty
}

/// Extract cap_specificity from evidence notes and return bonus.
///
/// 1 bit (exact match) = +1, otherwise 0.
fn cap_specificity_score(notes: &[String]) -> i32 {
    for note in notes {
        if let Some(count_str) = note.strip_prefix("cap_specificity:") {
            if let Ok(count) = count_str.parse::<u8>() {
                return if count == 1 { 1 } else { 0 };
            }
        }
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
//  Explanation & Confidence Limiters
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a human-readable explanation of a taint finding from its evidence.
pub fn generate_explanation(diag: &Diag) -> Option<String> {
    let ev = diag.evidence.as_ref()?;
    let source = ev.source.as_ref()?;
    let sink = ev.sink.as_ref()?;

    let source_callee = source
        .snippet
        .as_deref()
        .unwrap_or("(unknown source)");
    let sink_callee = sink
        .snippet
        .as_deref()
        .unwrap_or("(unknown sink)");

    // Extract source kind label (prefer structured field)
    let source_kind_label = if let Some(kind) = ev.source_kind {
        use crate::labels::SourceKind;
        match kind {
            SourceKind::UserInput => "user input",
            SourceKind::EnvironmentConfig => "environment/config",
            SourceKind::Database => "database",
            SourceKind::FileSystem => "file system",
            SourceKind::CaughtException => "caught exception",
            SourceKind::Unknown => "unclassified",
        }
    } else {
        // Legacy fallback: parse from notes
        let kind_str = ev
            .notes
            .iter()
            .find_map(|n| n.strip_prefix("source_kind:"))
            .unwrap_or("unknown");
        match kind_str {
            "UserInput" => "user input",
            "EnvironmentConfig" => "environment/config",
            "Database" => "database",
            "FileSystem" => "file system",
            "CaughtException" => "caught exception",
            _ => "unclassified",
        }
    };

    // Extract category from rule ID
    let category = diag
        .id
        .strip_prefix("taint-unsanitised-flow")
        .map(|_| extract_category_from_id(&diag.id))
        .unwrap_or_else(|| "injection".to_string());

    let step_count = ev.flow_steps.len();
    let mut explanation = if step_count > 2 {
        format!(
            "Unsanitised {source_kind_label} data flows from {source_callee} (line {}) through {} steps to {sink_callee} (line {}), creating a potential {category} vulnerability.",
            source.line,
            step_count - 2, // exclude source and sink themselves
            sink.line,
        )
    } else {
        format!(
            "Unsanitised {source_kind_label} data flows from {source_callee} (line {}) to {sink_callee} (line {}), creating a potential {category} vulnerability.",
            source.line,
            sink.line,
        )
    };

    // Conditional addenda
    if diag.path_validated {
        if let Some(ref guard) = diag.guard_kind {
            explanation.push_str(&format!(
                " A {guard} guard was detected but may not be sufficient."
            ));
        }
    }
    if ev.uses_summary || ev.notes.iter().any(|n| n == "uses_summary") {
        explanation
            .push_str(" The flow crosses function boundaries via summary resolution.");
    }

    Some(explanation)
}

/// Extract a vulnerability category label from the Diag (used in explanation text).
fn extract_category_from_id(id: &str) -> String {
    // Rule IDs like "taint-unsanitised-flow (source 3:1)" — category comes
    // from the finding category field, but we approximate from the ID here.
    if id.contains("sql") || id.contains("SQL") {
        "SQL injection".to_string()
    } else if id.contains("xss") || id.contains("XSS") {
        "XSS".to_string()
    } else {
        "injection".to_string()
    }
}

/// Compute reasons why confidence is not higher.
pub fn compute_confidence_limiters(diag: &Diag) -> Vec<String> {
    let mut limiters = Vec::new();
    let ev = match &diag.evidence {
        Some(e) => e,
        None => return limiters,
    };

    // Hop count (prefer structured field)
    let hop = ev.hop_count.or_else(|| {
        ev.notes.iter().find_map(|n| {
            n.strip_prefix("hop_count:")?.parse::<u16>().ok()
        })
    });
    if let Some(count) = hop {
        if count >= 4 {
            limiters.push(format!(
                "Taint path spans {count} blocks, increasing chance of intermediate sanitization"
            ));
        }
    }

    // Summary resolution (prefer structured field)
    if ev.uses_summary || ev.notes.iter().any(|n| n == "uses_summary") {
        limiters.push(
            "Flow resolved via cross-function summary (may be imprecise)".into(),
        );
    }

    // Path validated (use Diag field directly)
    if diag.path_validated {
        limiters.push(
            "Validation guard detected on path (may provide protection)".into(),
        );
    }

    // Cap specificity (prefer structured field)
    let cap_spec = ev.cap_specificity.or_else(|| {
        ev.notes.iter().find_map(|n| {
            n.strip_prefix("cap_specificity:")?.parse::<u8>().ok()
        })
    });
    if cap_spec == Some(0) {
        limiters.push(
            "Source and sink capability types do not match specifically".into(),
        );
    }

    // Source kind unknown (prefer structured field)
    let is_unknown = ev.source_kind == Some(crate::labels::SourceKind::Unknown)
        || ev.notes.iter().any(|n| n == "source_kind:Unknown");
    if is_unknown {
        limiters.push(
            "Source type is unclassified (lower exploitation confidence)".into(),
        );
    }

    // Symbolic verdict
    if let Some(ref sv) = ev.symbolic {
        if sv.verdict == Verdict::Infeasible {
            limiters.push(
                "Symbolic analysis proved this path is infeasible".into(),
            );
        }
    }

    limiters
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_diag(id: &str, severity: Severity) -> Diag {
        Diag {
            path: "test.rs".into(),
            line: 1,
            col: 1,
            severity,
            id: id.into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
        }
    }

    #[test]
    fn compute_confidence_taint_strong_path() {
        // UserInput(+3) + source+sink+snippet(+3) + short path(0) + cap_specificity:1(+1) = 7 → High
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("env::var(\"X\")".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "source_kind:UserInput".into(),
                "hop_count:1".into(),
                "cap_specificity:1".into(),
            ],
            source_kind: Some(crate::labels::SourceKind::UserInput),
            hop_count: Some(1),
            cap_specificity: Some(1),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_taint_medium_path() {
        // EnvironmentConfig(+2) + source+sink no snippet(+2) + hop_count:5(−1) = 3 → Medium
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "source_kind:EnvironmentConfig".into(),
                "hop_count:5".into(),
            ],
            source_kind: Some(crate::labels::SourceKind::EnvironmentConfig),
            hop_count: Some(5),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn compute_confidence_taint_weak_path() {
        // Database(0) + source+sink no snippet(+2) + hop_count:12(−2) + uses_summary(−1) = −1 → Low
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 20,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "source_kind:Database".into(),
                "hop_count:12".into(),
                "uses_summary".into(),
            ],
            source_kind: Some(crate::labels::SourceKind::Database),
            hop_count: Some(12),
            uses_summary: true,
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_taint_validated_with_source() {
        // UserInput(+3) + source+sink+snippet(+3) + path_validated(−3) = 3 → Medium
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.path_validated = true;
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "path_validated".into(),
                "source_kind:UserInput".into(),
            ],
            source_kind: Some(crate::labels::SourceKind::UserInput),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn compute_confidence_taint_no_evidence() {
        // No Evidence struct → conservative High
        let d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_degraded_caps_to_low() {
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: None,
            sink: None,
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec!["degraded:budget_exceeded".into()],
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_state_rules() {
        assert_eq!(
            compute_confidence(&make_diag("state-use-after-close", Severity::High)),
            Confidence::High,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-double-close", Severity::Medium)),
            Confidence::High,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-unauthed-access", Severity::High)),
            Confidence::High,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-resource-leak", Severity::Medium)),
            Confidence::Medium,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-resource-leak-possible", Severity::Low)),
            Confidence::Low,
        );
    }

    #[test]
    fn compute_confidence_cfg_preserves_existing() {
        let mut d = make_diag("cfg-unguarded-sink", Severity::High);
        d.confidence = Some(Confidence::Low);
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_ast_low() {
        let d = make_diag("rs.code_exec.eval", Severity::Medium);
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_ast_high_severity_medium() {
        let d = make_diag("rs.code_exec.eval", Severity::High);
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn evidence_is_empty() {
        let ev = Evidence::default();
        assert!(ev.is_empty());

        let ev2 = Evidence {
            source: Some(SpanEvidence {
                path: "x.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            ..Default::default()
        };
        assert!(!ev2.is_empty());
    }

    #[test]
    fn confidence_ord() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
        assert!(Confidence::Low < Confidence::High);
    }

    #[test]
    fn confidence_display_and_parse() {
        assert_eq!(Confidence::Low.to_string(), "Low");
        assert_eq!(Confidence::Medium.to_string(), "Medium");
        assert_eq!(Confidence::High.to_string(), "High");

        assert_eq!("low".parse::<Confidence>().unwrap(), Confidence::Low);
        assert_eq!("MEDIUM".parse::<Confidence>().unwrap(), Confidence::Medium);
        assert_eq!("High".parse::<Confidence>().unwrap(), Confidence::High);
        assert!("invalid".parse::<Confidence>().is_err());
    }

    #[test]
    fn compute_confidence_does_not_override_preset() {
        // AST patterns set confidence directly; compute_confidence must not overwrite.
        let mut d = make_diag("rs.quality.expect", Severity::Low);
        d.confidence = Some(Confidence::High);
        // The post-pass only runs when confidence is None, but verify compute_confidence
        // itself would return something different (Low for AST + Low severity), proving
        // the guard in scan.rs is necessary.
        assert_eq!(compute_confidence(&d), Confidence::Low);
        // The actual guard: confidence is already Some, so scan.rs skips compute_confidence.
        assert_eq!(d.confidence, Some(Confidence::High));
    }

    #[test]
    fn json_omits_none_fields() {
        let ev = Evidence::default();
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn symbolic_verdict_serde_round_trip() {
        for verdict in [
            Verdict::Confirmed,
            Verdict::Infeasible,
            Verdict::Inconclusive,
            Verdict::NotAttempted,
        ] {
            let sv = SymbolicVerdict {
                verdict,
                constraints_checked: 42,
                paths_explored: 7,
                witness: Some("x=null forces false branch".into()),
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            };
            let json = serde_json::to_string(&sv).unwrap();
            let rt: SymbolicVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(rt.verdict, verdict);
            assert_eq!(rt.constraints_checked, 42);
            assert_eq!(rt.paths_explored, 7);
            assert_eq!(rt.witness.as_deref(), Some("x=null forces false branch"));
        }
        // Verify snake_case serialization
        let json = serde_json::to_string(&Verdict::NotAttempted).unwrap();
        assert_eq!(json, "\"not_attempted\"");
    }

    #[test]
    fn evidence_with_symbolic_not_empty() {
        let ev = Evidence {
            symbolic: Some(SymbolicVerdict {
                verdict: Verdict::Confirmed,
                constraints_checked: 1,
                paths_explored: 1,
                witness: None,
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            }),
            ..Default::default()
        };
        assert!(!ev.is_empty());
    }

    #[test]
    fn symbolic_witness_omitted_when_none() {
        let sv = SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 0,
            witness: None,
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        };
        let json = serde_json::to_string(&sv).unwrap();
        assert!(!json.contains("witness"));
    }

    #[test]
    fn compute_confidence_structured_fields_only() {
        // Structured fields without notes → same result as with notes
        // UserInput(+3) + source+sink+snippet(+3) + hop_count:1(0) + cap_specificity:1(+1) = 7 → High
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            source_kind: Some(crate::labels::SourceKind::UserInput),
            hop_count: Some(1),
            cap_specificity: Some(1),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_notes_only_backward_compat() {
        // Notes only (no structured fields) → backward compatible
        // EnvironmentConfig(+2) + source+sink(+2) + hop_count:5(−1) = 3 → Medium
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            notes: vec![
                "source_kind:EnvironmentConfig".into(),
                "hop_count:5".into(),
            ],
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn compute_confidence_symbolic_infeasible_demotes() {
        // UserInput(+3) + source+sink+snippet(+3) + Infeasible(−5) = 1 → Low
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            source_kind: Some(crate::labels::SourceKind::UserInput),
            symbolic: Some(SymbolicVerdict {
                verdict: Verdict::Infeasible,
                constraints_checked: 3,
                paths_explored: 1,
                witness: None,
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            }),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_symbolic_confirmed_boosts() {
        // EnvironmentConfig(+2) + source+sink(+2) + Confirmed(+2) = 6 → High
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            source_kind: Some(crate::labels::SourceKind::EnvironmentConfig),
            symbolic: Some(SymbolicVerdict {
                verdict: Verdict::Confirmed,
                constraints_checked: 2,
                paths_explored: 1,
                witness: None,
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            }),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn evidence_with_structured_fields_not_empty() {
        let ev = Evidence {
            source_kind: Some(crate::labels::SourceKind::UserInput),
            ..Default::default()
        };
        assert!(!ev.is_empty());

        let ev2 = Evidence {
            uses_summary: true,
            ..Default::default()
        };
        assert!(!ev2.is_empty());
    }

    #[test]
    fn source_kind_serde_round_trip() {
        use crate::labels::SourceKind;
        for kind in [
            SourceKind::UserInput,
            SourceKind::EnvironmentConfig,
            SourceKind::FileSystem,
            SourceKind::Database,
            SourceKind::CaughtException,
            SourceKind::Unknown,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let rt: SourceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, kind);
        }
        // Verify snake_case serialization
        let json = serde_json::to_string(&crate::labels::SourceKind::UserInput).unwrap();
        assert_eq!(json, "\"user_input\"");
    }
}
