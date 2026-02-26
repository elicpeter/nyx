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
        if let Some(ev) = &diag.evidence
            && ev.notes.iter().any(|n| n == "path_validated")
        {
            return Confidence::Medium;
        }
        // source+sink present = High
        if let Some(ev) = &diag.evidence
            && ev.source.is_some()
            && ev.sink.is_some()
        {
            return Confidence::High;
        }
        return Confidence::High; // default for taint
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
        }
    }

    #[test]
    fn compute_confidence_taint_high() {
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
            notes: vec![],
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_taint_validated() {
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
            notes: vec!["path_validated".into()],
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
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
