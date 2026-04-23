//! Provenance notes attached to findings when the engine has hit an
//! internal budget, widening, or lowering cap.
//!
//! The notes are surfaced through `Finding.engine_notes` (and
//! `Evidence.engine_notes` once the finding reaches the `Diag` layer) so
//! downstream consumers can tell "we found nothing" from "we stopped
//! looking".
//!
//! Each note carries a [`LossDirection`] classification that describes
//! *how* the engine deviated from a fully-converged analysis.  The
//! direction drives two downstream behaviours:
//!
//! * [`crate::evidence::compute_confidence`] caps confidence at
//!   `Medium` when any attached note has direction
//!   [`LossDirection::OverReport`] or [`LossDirection::Bail`] (the
//!   finding itself may be spurious).
//! * [`crate::rank`] applies a direction-aware `completeness` penalty
//!   to the attack-surface score (see `rank.rs::completeness_penalty`).
//!
//! This replaces the earlier Phase-3 stance of "notes are purely
//! additive and never influence score".  A release audit flagged that
//! users sorting thousands of findings by rank could not distinguish
//! converged analysis from capped analysis, which produced false
//! confidence in fragile findings.  The direction-aware pipeline
//! preserves the observability goal while fixing the credibility gap.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Classification of *why* a fix-point loop hit its safety cap.
///
/// The cap-hit alone is not actionable — "we ran 64 iterations and did
/// not detect convergence" can mean several very different things:
///
/// * the lattice is still shrinking but slowly (e.g. a 72-function chain
///   SCC that legitimately needs >64 iterations),
/// * the lattice stopped shrinking but the convergence predicate still
///   detects change (the change set stabilised at a non-zero value —
///   monotonicity is fine but something in the convergence predicate is
///   spurious), or
/// * the lattice is oscillating (two iterations alternating with the
///   same change-set size; this is a *bug*, not a tuning issue).
///
/// Recording the reason makes cap-hit telemetry actionable: operators
/// can tell when "raise the cap" would actually help vs. when they are
/// looking at a summary-non-monotonicity regression.
///
/// Serialized as a nested snake_case tagged enum so SARIF/JSON consumers
/// can pattern-match without depending on Rust layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapHitReason {
    /// The change-set size was still decreasing when the cap fired.
    /// `trajectory` is the last N iteration deltas (most recent last).
    /// Operators can safely raise the cap; the underlying analysis is
    /// healthy but the SCC is larger than the current budget.
    MonotoneShrinking { trajectory: SmallVec<[u32; 4]> },
    /// The change-set size stayed constant for the last ≥2 iterations
    /// without reaching zero.  This is unusual: every iteration is
    /// updating the *same* keys, which suggests a summary that changes
    /// the same fields back and forth even though the cap bits are
    /// saturating.  Raise the cap **and** investigate.
    Plateau { delta: u32 },
    /// The change-set size oscillated with a detected period ≤ N/2.
    /// Genuinely bad — the analysis is not monotone, convergence will
    /// *never* be reached, and raising the cap will not help.  File a
    /// bug with the fixture attached.
    SuspectedOscillation {
        period: u8,
        trajectory: SmallVec<[u32; 4]>,
    },
    /// Default when the engine did not record a trajectory (e.g. the
    /// cap fired after only one iteration so there is nothing to
    /// classify).  Preserves backwards compatibility for old notes
    /// deserialized from disk.
    Unknown,
}

impl Default for CapHitReason {
    fn default() -> Self {
        CapHitReason::Unknown
    }
}

impl CapHitReason {
    /// Classify a trajectory of per-iteration change-set sizes.
    ///
    /// `deltas` should carry the *changed-key counts* from the last N
    /// iterations (most recent last).  Classification rules:
    ///
    /// 1. Fewer than 2 samples → `Unknown` (nothing to diff against).
    /// 2. A period-2 pattern (a,b,a,b) with a ≠ b → `SuspectedOscillation`.
    /// 3. Last two samples equal and non-zero → `Plateau`.
    /// 4. Strictly decreasing tail → `MonotoneShrinking`.
    /// 5. Otherwise → `Unknown` (inconclusive; rare in practice).
    ///
    /// The function is pure — no allocation beyond the returned
    /// [`SmallVec`] — so it is safe to call from within a hot loop when
    /// a cap actually fires.  Callers should accumulate deltas in a
    /// fixed-size ring buffer to bound memory.
    pub fn classify(deltas: &[u32]) -> CapHitReason {
        if deltas.len() < 2 {
            return CapHitReason::Unknown;
        }

        // Detect period-2 oscillation: last 4 samples as (a,b,a,b) with a ≠ b.
        if deltas.len() >= 4 {
            let n = deltas.len();
            let (a0, b0, a1, b1) = (
                deltas[n - 4],
                deltas[n - 3],
                deltas[n - 2],
                deltas[n - 1],
            );
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
///
/// Every new [`EngineNote`] variant must declare a direction via
/// [`EngineNote::direction`] — the match is exhaustive by design so the
/// classification cannot silently default.
///
/// Ordering matters: variants are sorted by worsening impact on a
/// specific finding's credibility.  [`combine`](Self::combine) uses the
/// `Ord` impl to merge directions when multiple notes are attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossDirection {
    /// The note is informational only.  Analysis was fully converged;
    /// the note records a harmless event such as a cache reuse.
    Informational,
    /// The analysis may have *missed* additional findings (e.g. the
    /// worklist was capped before fully propagating taint).  Findings
    /// that *were* reported are still sound — they correspond to real
    /// flows — but the result set is a lower bound.
    UnderReport,
    /// The analysis may have reported a *spurious* finding (e.g.
    /// predicate state was widened to top, so a validation guard that
    /// would have suppressed the finding was lost).  The specific
    /// finding is more likely to be a false positive than one produced
    /// from converged state.
    OverReport,
    /// Analysis of this finding's body aborted before producing a
    /// trustworthy result (e.g. SSA lowering bailed, parse timed out).
    /// The finding is weakly supported; a human reviewer should treat
    /// it as a starting point rather than a confirmed flow.
    Bail,
}

impl LossDirection {
    /// Merge two directions by taking the worse (later in `Ord`).
    ///
    /// A body with both `UnderReport` and `OverReport` notes is treated
    /// as `OverReport` because over-reporting is the more credibility-
    /// damaging failure mode for a specific emitted finding.
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
///
/// `kind` is serialized as a snake_case tag so tooling can pattern-match
/// across JSON and SARIF output without depending on Rust enum layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineNote {
    /// The taint worklist hit its iteration budget before converging.
    /// Direction: [`LossDirection::UnderReport`] — the fixpoint was
    /// aborted, so some flows may have been missed, but emitted flows
    /// are still backed by propagated taint.
    WorklistCapped { iterations: u32 },
    /// Origin tracking was truncated when a value exceeded the configured
    /// per-value origin cap (`analysis.engine.max_origins`, default 32).
    /// Direction: [`LossDirection::UnderReport`] — each dropped origin
    /// corresponds to a real source flow whose independent finding will
    /// not be emitted.  Other survivors still produce findings, so the
    /// counter is a strict lower bound on under-reporting.  Raise
    /// `max_origins` if operators observe this note on realistic inputs.
    /// Truncation is deterministic: origins are sorted by source
    /// location and the largest-by-location are dropped first, so the
    /// survivor set is stable across runs and merge orderings.
    OriginsTruncated { dropped: u32 },
    /// JS/TS pass-2 in-file global propagation hit its iteration cap.
    /// Direction: [`LossDirection::UnderReport`] — global state may
    /// not have reached fixpoint; cross-function flows could be missed.
    ///
    /// `reason` classifies *why* the cap fired (monotone-but-slow,
    /// plateau, suspected oscillation) so operators can tell a
    /// tunable-budget problem from a monotonicity regression.  Older
    /// serialized notes without this field default to
    /// [`CapHitReason::Unknown`].
    InFileFixpointCapped {
        iterations: u32,
        #[serde(default)]
        reason: CapHitReason,
    },
    /// Cross-file SCC fixpoint hit `SCC_FIXPOINT_SAFETY_CAP`.
    /// Direction: [`LossDirection::UnderReport`] — the iterative
    /// cross-file join aborted; summaries for members of this SCC may
    /// be incomplete.
    ///
    /// `reason` classifies *why* the cap fired (monotone-but-slow,
    /// plateau, suspected oscillation) so operators can tell a
    /// tunable-budget problem from a monotonicity regression.  Older
    /// serialized notes without this field default to
    /// [`CapHitReason::Unknown`].
    CrossFileFixpointCapped {
        iterations: u32,
        #[serde(default)]
        reason: CapHitReason,
    },
    /// SSA lowering produced an empty body (parse failure or
    /// unsupported shape).  Direction: [`LossDirection::Bail`] — any
    /// finding attributed to this body is weakly supported because the
    /// IR itself is malformed.
    SsaLoweringBailed { reason: String },
    /// Tree-sitter parse exceeded the configured timeout.
    /// Direction: [`LossDirection::Bail`] — parse aborted; findings
    /// surfaced from the partial tree should be treated as a human-
    /// review starting point.
    ParseTimeout { timeout_ms: u32 },
    /// Predicate state was widened to top to maintain monotonicity.
    /// Direction: [`LossDirection::OverReport`] — validation guards
    /// that would have suppressed the finding may have been lost, so
    /// the finding is more likely to be a false positive.
    PredicateStateWidened,
    /// Path-environment constraints exceeded internal cap; widened to
    /// top.  Direction: [`LossDirection::OverReport`] — same reasoning
    /// as [`Self::PredicateStateWidened`]: dropped path constraints can
    /// only turn infeasible paths into apparent-feasible ones.
    PathEnvCapped,
    /// Inline cache reused a cached body summary; origins were
    /// re-attributed.  Direction: [`LossDirection::Informational`] —
    /// the cache hit does not affect precision, but surfacing the
    /// re-attribution helps explain why origin locations move between
    /// runs that share a body signature.
    InlineCacheReused,
}

impl EngineNote {
    /// Classify this note by direction of precision loss.
    ///
    /// The match is exhaustive: every `EngineNote` variant must declare
    /// a direction.  When adding a new cap site, pick the direction
    /// that most honestly describes the impact on an emitted finding:
    ///
    /// * `Informational` — analysis fully converged; note is a
    ///   provenance breadcrumb (e.g. cache reuse).
    /// * `UnderReport` — analysis was cut short, but anything emitted
    ///   is still backed by real propagation.
    /// * `OverReport` — precision was widened, so the emitted finding
    ///   is *more* likely to be a false positive than the baseline.
    /// * `Bail` — analysis of this body aborted; the finding is weakly
    ///   supported.
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
        }
    }

    /// True if this note indicates the engine may have deviated from a
    /// fully-converged analysis (any non-informational direction).
    ///
    /// This is a convenience over
    /// `self.direction() != LossDirection::Informational` and drives
    /// the `confidence_capped` SARIF property.
    pub fn lowers_confidence(&self) -> bool {
        self.direction() != LossDirection::Informational
    }
}

/// Compute the worst direction across a slice of notes.
///
/// Returns `None` when `notes` is empty or contains only
/// [`LossDirection::Informational`] notes.  Returns `Some(dir)` with
/// the most impactful direction otherwise — this is what downstream
/// consumers (rank, confidence) use to decide how to degrade a finding.
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

/// Deduplicating push: does not append if an identical note is already
/// present.  Used to keep per-finding note lists small when a cap site
/// fires repeatedly inside the same body.
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
