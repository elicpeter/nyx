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
//  Evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Structured evidence for a diagnostic finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Where tainted data originated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SpanEvidence>,

    /// Where the dangerous operation happens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<SpanEvidence>,

    /// Validation guards protecting this path.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub guards: Vec<SpanEvidence>,

    /// Sanitizers applied to this path.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sanitizers: Vec<SpanEvidence>,

    /// State-machine evidence (resource lifecycle / auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<StateEvidence>,

    /// Free-form notes for ranking and display.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Evidence from a state-machine analysis (resource lifecycle / auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvidence {
    /// The state machine: `"resource"` or `"auth"`.
    pub machine: String,
    /// Variable name if available.
    #[serde(skip_serializing_if = "Option::is_none")]
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

    // Source kind
    score += source_kind_score(&ev.notes);

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

    // Hop count penalty
    score += hop_count_score(&ev.notes);

    // Path validation penalty
    if ev.notes.iter().any(|n| n == "path_validated") {
        score -= 3;
    }

    // Cap specificity bonus
    score += cap_specificity_score(&ev.notes);

    // Summary resolution penalty
    if ev.notes.iter().any(|n| n == "uses_summary") {
        score -= 1;
    }

    match score {
        5.. => Confidence::High,
        2..=4 => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// Extract source_kind from evidence notes and return points.
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
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_taint_validated_with_source() {
        // UserInput(+3) + source+sink+snippet(+3) + path_validated(−3) = 3 → Medium
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
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "path_validated".into(),
                "source_kind:UserInput".into(),
            ],
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
        let ev = Evidence {
            source: None,
            sink: None,
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![],
        };
        assert!(ev.is_empty());

        let ev2 = Evidence {
            source: Some(SpanEvidence {
                path: "x.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: None,
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![],
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
        let ev = Evidence {
            source: None,
            sink: None,
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![],
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(json, "{}");
    }
}
