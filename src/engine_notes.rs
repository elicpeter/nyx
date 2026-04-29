//! Provenance notes attached to findings when the engine has hit an
//! internal budget, widening, or lowering cap.
//!
//! Each note carries a [`LossDirection`] classification.
//! [`crate::evidence::compute_confidence`] caps confidence at `Medium`
//! for `OverReport`/`Bail` notes, and [`crate::rank`] applies a
//! direction-aware completeness penalty.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Why a fix-point loop hit its safety cap. Distinguishes "raise the
/// cap" cases from non-monotonicity bugs in cap-hit telemetry.
/// Serialized as a tagged snake_case enum for SARIF/JSON consumers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapHitReason {
    /// Change-set still decreasing when the cap fired. Safe to raise
    /// the cap; the SCC is just larger than budget.
    MonotoneShrinking { trajectory: SmallVec<[u32; 4]> },
    /// Change-set held steady at a non-zero value for ≥2 iterations.
    /// Same keys updating back and forth — investigate.
    Plateau { delta: u32 },
    /// Period-2 oscillation detected. Non-monotone; raising the cap
    /// will not help. File a bug.
    SuspectedOscillation {
        period: u8,
        trajectory: SmallVec<[u32; 4]>,
    },
    /// No trajectory recorded (e.g. cap fired after a single iteration).
    #[default]
    Unknown,
}

impl CapHitReason {
    /// Classify a trajectory of per-iteration change-set sizes
    /// (most recent last). Rules: <2 samples → `Unknown`; a,b,a,b with
    /// a≠b → `SuspectedOscillation`; last two equal non-zero →
    /// `Plateau`; strictly decreasing tail → `MonotoneShrinking`;
    /// otherwise `Unknown`.
    pub fn classify(deltas: &[u32]) -> CapHitReason {
        if deltas.len() < 2 {
            return CapHitReason::Unknown;
        }

        // Detect period-2 oscillation: last 4 samples as (a,b,a,b) with a ≠ b.
        if deltas.len() >= 4 {
            let n = deltas.len();
            let (a0, b0, a1, b1) = (deltas[n - 4], deltas[n - 3], deltas[n - 2], deltas[n - 1]);
            if a0 == a1 && b0 == b1 && a0 != b0 {
                let tail = deltas
                    .iter()
                    .rev()
                    .take(4)
                    .rev()
                    .copied()
                    .collect::<SmallVec<[u32; 4]>>();
                return CapHitReason::SuspectedOscillation {
                    period: 2,
                    trajectory: tail,
                };
            }
        }

        let last = deltas[deltas.len() - 1];
        let prev = deltas[deltas.len() - 2];

        // Plateau: change-set size stuck at the same non-zero value.
        if last == prev && last > 0 {
            return CapHitReason::Plateau { delta: last };
        }

        // Monotone shrinking: strictly decreasing over the full
        // recorded tail.  (Equal-zero at the end would have meant
        // convergence, so the cap wouldn't have fired.)
        let mut monotone = true;
        for w in deltas.windows(2) {
            if w[1] > w[0] {
                monotone = false;
                break;
            }
        }
        if monotone {
            let tail = deltas
                .iter()
                .rev()
                .take(4)
                .rev()
                .copied()
                .collect::<SmallVec<[u32; 4]>>();
            return CapHitReason::MonotoneShrinking { trajectory: tail };
        }

        CapHitReason::Unknown
    }

    /// Stable snake-case tag for log/diag consumption.
    pub fn tag(&self) -> &'static str {
        match self {
            CapHitReason::MonotoneShrinking { .. } => "monotone_shrinking",
            CapHitReason::Plateau { .. } => "plateau",
            CapHitReason::SuspectedOscillation { .. } => "suspected_oscillation",
            CapHitReason::Unknown => "unknown",
        }
    }
}

/// Direction of precision loss encoded by an [`EngineNote`].
/// Variants are ordered by worsening credibility impact;
/// [`combine`](Self::combine) takes the max.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossDirection {
    /// Analysis converged; the note records a harmless event.
    Informational,
    /// Analysis may have missed findings (worklist was capped). Reported
    /// findings remain sound — the result set is a lower bound.
    UnderReport,
    /// Analysis may have reported a spurious finding (e.g. predicate
    /// state widened to top, dropping a guard). Likely FP.
    OverReport,
    /// Analysis aborted before producing a trustworthy result.
    /// Treat the finding as a starting point, not a confirmed flow.
    Bail,
}

impl LossDirection {
    /// Merge by taking the worse (later in `Ord`).
    pub fn combine(self, other: LossDirection) -> LossDirection {
        self.max(other)
    }

    /// Snake-case tag used in console output and JSON properties.
    pub fn tag(self) -> &'static str {
        match self {
            LossDirection::Informational => "informational",
            LossDirection::UnderReport => "under-report",
            LossDirection::OverReport => "over-report",
            LossDirection::Bail => "bail",
        }
    }
}

/// A single provenance event recorded during analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineNote {
    /// Taint worklist hit its iteration budget. UnderReport.
    WorklistCapped { iterations: u32 },
    /// Per-value origin set truncated to `analysis.engine.max_origins`
    /// (default 32). UnderReport — dropped origins correspond to real
    /// source flows whose findings won't emit.
    OriginsTruncated { dropped: u32 },
    /// JS/TS pass-2 in-file global propagation hit its cap. UnderReport.
    InFileFixpointCapped {
        iterations: u32,
        #[serde(default)]
        reason: CapHitReason,
    },
    /// Cross-file SCC fixpoint hit `SCC_FIXPOINT_SAFETY_CAP`. UnderReport.
    CrossFileFixpointCapped {
        iterations: u32,
        #[serde(default)]
        reason: CapHitReason,
    },
    /// SSA lowering produced an empty body. Bail.
    SsaLoweringBailed { reason: String },
    /// Tree-sitter parse exceeded the timeout. Bail.
    ParseTimeout { timeout_ms: u32 },
    /// Predicate state widened to top to keep the lattice monotone.
    /// OverReport — guards may have been lost.
    PredicateStateWidened,
    /// Path-environment constraints widened to top. OverReport.
    PathEnvCapped,
    /// Inline cache reused a cached body. Informational.
    InlineCacheReused,
    /// Points-to set truncated to `analysis.engine.max_pointsto`
    /// (default 32). UnderReport.
    PointsToTruncated { dropped: u32 },
}

impl EngineNote {
    /// Direction of precision loss for this note. New variants must
    /// declare one explicitly.
    pub fn direction(&self) -> LossDirection {
        match self {
            EngineNote::WorklistCapped { .. } => LossDirection::UnderReport,
            EngineNote::OriginsTruncated { .. } => LossDirection::UnderReport,
            EngineNote::InFileFixpointCapped { .. } => LossDirection::UnderReport,
            EngineNote::CrossFileFixpointCapped { .. } => LossDirection::UnderReport,
            EngineNote::SsaLoweringBailed { .. } => LossDirection::Bail,
            EngineNote::ParseTimeout { .. } => LossDirection::Bail,
            EngineNote::PredicateStateWidened => LossDirection::OverReport,
            EngineNote::PathEnvCapped => LossDirection::OverReport,
            EngineNote::InlineCacheReused => LossDirection::Informational,
            EngineNote::PointsToTruncated { .. } => LossDirection::UnderReport,
        }
    }

    /// True for any non-informational direction. Drives the
    /// `confidence_capped` SARIF property.
    pub fn lowers_confidence(&self) -> bool {
        self.direction() != LossDirection::Informational
    }
}

/// Worst non-informational direction across a slice of notes, or
/// `None` if the slice is empty or only carries informational notes.
pub fn worst_direction(notes: &[EngineNote]) -> Option<LossDirection> {
    let mut worst: Option<LossDirection> = None;
    for note in notes {
        let dir = note.direction();
        if dir == LossDirection::Informational {
            continue;
        }
        worst = Some(match worst {
            Some(w) => w.combine(dir),
            None => dir,
        });
    }
    worst
}

/// Push-if-not-present.
pub fn push_unique(notes: &mut smallvec::SmallVec<[EngineNote; 2]>, note: EngineNote) {
    if !notes.iter().any(|n| n == &note) {
        notes.push(note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worklist_capped_lowers_confidence() {
        assert!(EngineNote::WorklistCapped { iterations: 10 }.lowers_confidence());
    }

    #[test]
    fn inline_cache_reused_does_not_lower_confidence() {
        assert!(!EngineNote::InlineCacheReused.lowers_confidence());
    }

    #[test]
    fn serialization_uses_snake_case_tag() {
        let note = EngineNote::WorklistCapped { iterations: 7 };
        let s = serde_json::to_string(&note).unwrap();
        assert!(s.contains("\"kind\":\"worklist_capped\""));
        assert!(s.contains("\"iterations\":7"));
    }

    #[test]
    fn push_unique_deduplicates() {
        let mut v = smallvec::SmallVec::<[EngineNote; 2]>::new();
        push_unique(&mut v, EngineNote::WorklistCapped { iterations: 1 });
        push_unique(&mut v, EngineNote::WorklistCapped { iterations: 1 });
        push_unique(&mut v, EngineNote::OriginsTruncated { dropped: 2 });
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn direction_classification_is_exhaustive() {
        // Budget caps ⇒ under-report: fixpoint aborted, results still sound.
        assert_eq!(
            EngineNote::WorklistCapped { iterations: 1 }.direction(),
            LossDirection::UnderReport
        );
        assert_eq!(
            EngineNote::OriginsTruncated { dropped: 1 }.direction(),
            LossDirection::UnderReport
        );
        assert_eq!(
            EngineNote::InFileFixpointCapped {
                iterations: 1,
                reason: CapHitReason::Unknown,
            }
            .direction(),
            LossDirection::UnderReport
        );
        assert_eq!(
            EngineNote::CrossFileFixpointCapped {
                iterations: 1,
                reason: CapHitReason::Unknown,
            }
            .direction(),
            LossDirection::UnderReport
        );
        assert_eq!(
            EngineNote::PointsToTruncated { dropped: 1 }.direction(),
            LossDirection::UnderReport
        );

        // Widening ⇒ over-report: validation guards may have been lost.
        assert_eq!(
            EngineNote::PredicateStateWidened.direction(),
            LossDirection::OverReport
        );
        assert_eq!(
            EngineNote::PathEnvCapped.direction(),
            LossDirection::OverReport
        );

        // Hard aborts ⇒ bail: IR or parse failed.
        assert_eq!(
            EngineNote::SsaLoweringBailed { reason: "x".into() }.direction(),
            LossDirection::Bail
        );
        assert_eq!(
            EngineNote::ParseTimeout { timeout_ms: 1 }.direction(),
            LossDirection::Bail
        );

        // Informational ⇒ no credibility impact.
        assert_eq!(
            EngineNote::InlineCacheReused.direction(),
            LossDirection::Informational
        );
    }

    #[test]
    fn loss_direction_order_is_worst_last() {
        // combine() takes the max, so Bail must dominate OverReport must
        // dominate UnderReport must dominate Informational.
        assert!(LossDirection::Bail > LossDirection::OverReport);
        assert!(LossDirection::OverReport > LossDirection::UnderReport);
        assert!(LossDirection::UnderReport > LossDirection::Informational);
    }

    #[test]
    fn combine_takes_the_worse_direction() {
        assert_eq!(
            LossDirection::UnderReport.combine(LossDirection::OverReport),
            LossDirection::OverReport
        );
        assert_eq!(
            LossDirection::OverReport.combine(LossDirection::UnderReport),
            LossDirection::OverReport
        );
        assert_eq!(
            LossDirection::Bail.combine(LossDirection::OverReport),
            LossDirection::Bail
        );
        assert_eq!(
            LossDirection::Informational.combine(LossDirection::Informational),
            LossDirection::Informational
        );
    }

    #[test]
    fn worst_direction_empty_is_none() {
        let notes: Vec<EngineNote> = vec![];
        assert_eq!(worst_direction(&notes), None);
    }

    #[test]
    fn worst_direction_informational_only_is_none() {
        let notes = vec![EngineNote::InlineCacheReused, EngineNote::InlineCacheReused];
        assert_eq!(worst_direction(&notes), None);
    }

    #[test]
    fn worst_direction_mixed_picks_worst() {
        let notes = vec![
            EngineNote::InlineCacheReused,
            EngineNote::WorklistCapped { iterations: 1 },
            EngineNote::PredicateStateWidened,
        ];
        assert_eq!(worst_direction(&notes), Some(LossDirection::OverReport));
    }

    #[test]
    fn worst_direction_bail_dominates() {
        let notes = vec![
            EngineNote::PredicateStateWidened,
            EngineNote::ParseTimeout { timeout_ms: 100 },
        ];
        assert_eq!(worst_direction(&notes), Some(LossDirection::Bail));
    }

    #[test]
    fn cap_hit_reason_too_few_samples_unknown() {
        assert_eq!(CapHitReason::classify(&[]), CapHitReason::Unknown);
        assert_eq!(CapHitReason::classify(&[5]), CapHitReason::Unknown);
    }

    #[test]
    fn cap_hit_reason_detects_period_2_oscillation() {
        let result = CapHitReason::classify(&[3, 7, 3, 7]);
        match result {
            CapHitReason::SuspectedOscillation { period, .. } => assert_eq!(period, 2),
            other => panic!("expected SuspectedOscillation; got {other:?}"),
        }
    }

    #[test]
    fn cap_hit_reason_detects_plateau() {
        let result = CapHitReason::classify(&[10, 5, 5]);
        assert_eq!(result, CapHitReason::Plateau { delta: 5 });
    }

    #[test]
    fn cap_hit_reason_plateau_at_zero_is_not_a_plateau() {
        // Zero-delta means we converged; classifier should not flag.
        let result = CapHitReason::classify(&[3, 0, 0]);
        // Strictly decreasing tail → monotone-shrinking; not plateau.
        match result {
            CapHitReason::MonotoneShrinking { .. } => {}
            other => panic!("expected MonotoneShrinking; got {other:?}"),
        }
    }

    #[test]
    fn cap_hit_reason_detects_monotone_shrinking() {
        let result = CapHitReason::classify(&[10, 7, 4, 2]);
        match result {
            CapHitReason::MonotoneShrinking { trajectory } => {
                assert_eq!(trajectory.as_slice(), &[10, 7, 4, 2]);
            }
            other => panic!("expected MonotoneShrinking; got {other:?}"),
        }
    }

    #[test]
    fn cap_hit_reason_non_monotone_non_oscillating_is_unknown() {
        // Goes up then down without a clean period-2 pattern.
        let result = CapHitReason::classify(&[3, 8, 2]);
        assert_eq!(result, CapHitReason::Unknown);
    }

    #[test]
    fn cap_hit_reason_serializes_snake_case_tag() {
        let r = CapHitReason::Plateau { delta: 4 };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"kind\":\"plateau\""), "got {s}");
        assert!(s.contains("\"delta\":4"), "got {s}");
    }

    #[test]
    fn in_file_fixpoint_capped_serde_backcompat() {
        // Older serialized notes without the `reason` field must still
        // deserialize (serde(default) → CapHitReason::Unknown).
        let legacy = r#"{"kind":"in_file_fixpoint_capped","iterations":7}"#;
        let parsed: EngineNote = serde_json::from_str(legacy).unwrap();
        match parsed {
            EngineNote::InFileFixpointCapped { iterations, reason } => {
                assert_eq!(iterations, 7);
                assert_eq!(reason, CapHitReason::Unknown);
            }
            other => panic!("expected InFileFixpointCapped; got {other:?}"),
        }
    }

    #[test]
    fn cross_file_fixpoint_capped_serde_backcompat() {
        let legacy = r#"{"kind":"cross_file_fixpoint_capped","iterations":64}"#;
        let parsed: EngineNote = serde_json::from_str(legacy).unwrap();
        match parsed {
            EngineNote::CrossFileFixpointCapped { iterations, reason } => {
                assert_eq!(iterations, 64);
                assert_eq!(reason, CapHitReason::Unknown);
            }
            other => panic!("expected CrossFileFixpointCapped; got {other:?}"),
        }
    }

    #[test]
    fn loss_direction_tag_stable() {
        assert_eq!(LossDirection::UnderReport.tag(), "under-report");
        assert_eq!(LossDirection::OverReport.tag(), "over-report");
        assert_eq!(LossDirection::Bail.tag(), "bail");
        assert_eq!(LossDirection::Informational.tag(), "informational");
    }
}
