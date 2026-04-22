//! Provenance notes attached to findings when the engine has hit an
//! internal budget, widening, or lowering cap.
//!
//! The notes are surfaced through `Finding.engine_notes` (and
//! `Evidence.engine_notes` once the finding reaches the `Diag` layer) so
//! downstream consumers can tell "we found nothing" from "we stopped
//! looking".  The list is additive — never used as a confidence score
//! input in `rank.rs` — so adding a note never changes severity.
//!
//! See `PRE_RELEASE_PLAN.md` Phase 3 for the full rationale.

use serde::{Deserialize, Serialize};

/// A single provenance event recorded during analysis.
///
/// `kind` is serialized as a snake_case tag so tooling can pattern-match
/// across JSON and SARIF output without depending on Rust enum layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineNote {
    /// The taint worklist hit its iteration budget before converging.
    WorklistCapped { iterations: u32 },
    /// Origin tracking was truncated when a value exceeded `MAX_ORIGINS`.
    OriginsTruncated { dropped: u32 },
    /// JS/TS pass-2 in-file global propagation hit its iteration cap.
    InFileFixpointCapped { iterations: u32 },
    /// Cross-file SCC fixpoint hit `SCC_FIXPOINT_SAFETY_CAP`.
    CrossFileFixpointCapped { iterations: u32 },
    /// SSA lowering produced an empty body (parse failure or unsupported shape).
    SsaLoweringBailed { reason: String },
    /// Tree-sitter parse exceeded the configured timeout.
    ParseTimeout { timeout_ms: u32 },
    /// Predicate state was widened to top to maintain monotonicity.
    PredicateStateWidened,
    /// Path-environment constraints exceeded internal cap; widened to top.
    PathEnvCapped,
    /// Inline cache reused a cached body summary; origins were re-attributed.
    /// (Informational; not a confidence reduction.)
    InlineCacheReused,
}

impl EngineNote {
    /// True if this note indicates the engine may have missed information
    /// (i.e., findings are potentially under-reported).
    pub fn lowers_confidence(&self) -> bool {
        !matches!(self, EngineNote::InlineCacheReused)
    }
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
}
