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
    InFileFixpointCapped { iterations: u32 },
    /// Cross-file SCC fixpoint hit `SCC_FIXPOINT_SAFETY_CAP`.
    /// Direction: [`LossDirection::UnderReport`] — the iterative
    /// cross-file join aborted; summaries for members of this SCC may
    /// be incomplete.
    CrossFileFixpointCapped { iterations: u32 },
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
            EngineNote::InFileFixpointCapped { iterations: 1 }.direction(),
            LossDirection::UnderReport
        );
        assert_eq!(
            EngineNote::CrossFileFixpointCapped { iterations: 1 }.direction(),
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
    fn loss_direction_tag_stable() {
        assert_eq!(LossDirection::UnderReport.tag(), "under-report");
        assert_eq!(LossDirection::OverReport.tag(), "over-report");
        assert_eq!(LossDirection::Bail.tag(), "bail");
        assert_eq!(LossDirection::Informational.tag(), "informational");
    }
}
