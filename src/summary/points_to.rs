//! Parameter-granularity points-to summaries.
//!
//! Captures the subset of intra-procedural alias behaviour that matters
//! at cross-file call sites: which parameters' heap/field writes are
//! observable to the caller through *another* parameter's alias, and
//! which parameters flow identity to the return value.
//!
//! ## Scope
//!
//! This is **intentionally not** a whole-program points-to analysis.
//! Nyx already has bounded intra-procedural heap tracking
//! ([`crate::ssa::heap`]); this module bridges the cross-file cliff by recording
//! a small, bounded alias graph between parameter positions and the return
//! value, then replaying it at summary-resolution time.
//!
//! ## Edge model
//!
//! Edges are directed `AliasEdge { source, target, kind }`:
//!
//! * `Source(Param(i)) → Target(Param(j))` — the callee stores data
//!   derived from parameter `i` into a field/element of parameter `j`.
//!   Mutation is observable to the caller through its argument for `j`.
//! * `Source(Param(i)) → Target(Return)` — the return value aliases
//!   parameter `i`'s heap identity.  Adds heap-level precision on top of
//!   the coarser [`TaintTransform::Identity`] view already carried in
//!   [`crate::summary::ssa_summary::SsaFuncSummary::param_to_return`].
//!
//! `MustAlias` is intentionally omitted — the ROI on
//! must-alias inference for cross-file summaries is low, and the soundness
//! story for `MayAlias`-only application is straightforward ("take the
//! union").
//!
//! ## Bound and overflow policy
//!
//! Edge count is capped at [`MAX_ALIAS_EDGES`].  When a callee's alias
//! graph exceeds the cap the summary records `overflow = true` and
//! callers treat the function as "any tainted parameter may spread to
//! every other parameter and to the return" — the conservative
//! greatest-lower-bound over the alias lattice.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Identity of one endpoint in an alias edge.
///
/// Parameters are identified by their 0-based positional index as reported
/// by [`crate::ssa::ir::SsaOp::Param`]; the implicit receiver (`self`/`this`)
/// is handled outside this table and is deliberately not representable here.
/// `Return` denotes the function's return SSA value — one per function, so
/// no further qualifier is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AliasPosition {
    /// Positional parameter, 0-based.  Receiver is excluded.
    Param(u32),
    /// The function's return value (union of every `Terminator::Return`).
    Return,
}

/// Strength of an alias edge.  Only [`AliasKind::MayAlias`] is emitted
/// — the analysis over-approximates identity-level aliasing rather than
/// proving must-alias.  The variant is kept as an enum so a future
/// extension that distinguishes the two can slot in without migrating
/// on-disk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AliasKind {
    /// Under some execution, the two positions may reference the same
    /// heap object.  Callers applying the edge take the *union* of
    /// points-to / taint at the source into the target.
    MayAlias,
}

/// A single directed alias edge.
///
/// `(source, target)` are order-sensitive: data flows from `source` to
/// `target` at the callee.  Callers apply each edge by reading their
/// argument / return abstraction for `source` and propagating into
/// `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasEdge {
    pub source: AliasPosition,
    pub target: AliasPosition,
    pub kind: AliasKind,
}

/// Maximum edges retained per [`PointsToSummary`].
///
/// Chosen so typical callees (≤ 4 parameters, one return, a handful of
/// field writes) fit without approximation while pathological graphs
/// still terminate the analysis in bounded time.  Overflow triggers the
/// [`PointsToSummary::overflow`] fallback instead of silently dropping
/// edges, so callers can reason about soundness.
pub const MAX_ALIAS_EDGES: usize = 8;

/// Parameter-granularity alias summary persisted in
/// [`crate::summary::ssa_summary::SsaFuncSummary`].
///
/// The summary is empty by default — functions without any parameter /
/// return aliasing (pure transformers, sinks that consume but don't
/// mutate their arguments) carry no edges and cost nothing on disk.
///
/// When the callee's alias graph exceeds [`MAX_ALIAS_EDGES`], extraction
/// sets [`overflow = true`](Self::overflow) and callers must treat every
/// parameter as reaching every other parameter and the return.  This is
/// the conservative fallback for bounded alias analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointsToSummary {
    /// Bounded edge list, deduped by `(source, target, kind)`.  The
    /// [`serde(default)`] attribute lets summaries pre-dating points-to
    /// tracking deserialise cleanly (no edges).
    #[serde(default, skip_serializing_if = "SmallVec::is_empty")]
    pub edges: SmallVec<[AliasEdge; 4]>,
    /// Conservative fallback flag — set when extraction hit
    /// [`MAX_ALIAS_EDGES`] and refused to drop any edge silently.  When
    /// `true`, callers treat the callee as "every parameter may alias
    /// every other parameter and the return value".
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub overflow: bool,
    /// At least one return path produces a *fresh* container allocation —
    /// a container literal (`[]`, `{}`) or a known container constructor
    /// call (`new Map()`, `list()`, …) that does not trace back to any
    /// parameter.  When this is `true` the caller synthesises a fresh
    /// [`crate::ssa::heap::HeapObjectId`] keyed on the call's SSA value
    /// and seeds it into `dynamic_pts`, so later container operations on
    /// the call result (e.g. `bag[0]`, `fillBag(bag, …)`) can find a heap
    /// cell to read from or store into.
    ///
    /// Closes the factory-pattern cross-file gap — `const bag = makeBag()`
    /// followed by `fillBag(bag, env)` and `exec(bag[0])` — by giving the
    /// caller's heap analysis a stable identity to attach stores to.
    /// Combines freely with `Param(i) → Return` edges: a mixed-return
    /// function (one branch returns a param, another returns a fresh
    /// allocation) emits both and the caller joins the two points-to
    /// sets.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub returns_fresh_alloc: bool,
}

impl PointsToSummary {
    /// Empty summary — no aliasing, no overflow.  Equivalent to
    /// [`Self::default`] but explicit at call sites.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether this summary adds any information over the default "no
    /// aliasing" interpretation.  Used by extraction to decide whether
    /// the field should be persisted or left empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty() && !self.overflow && !self.returns_fresh_alloc
    }

    /// Insert an edge, preserving dedup and the bounded-size invariant.
    ///
    /// Returns `true` when the edge was added, `false` when it was a
    /// duplicate or when the cap triggered an overflow.  The caller can
    /// ignore the return — the summary always remains in a valid state.
    pub fn insert(&mut self, source: AliasPosition, target: AliasPosition, kind: AliasKind) {
        if self.overflow {
            return;
        }
        let edge = AliasEdge {
            source,
            target,
            kind,
        };
        if self.edges.contains(&edge) {
            return;
        }
        if self.edges.len() >= MAX_ALIAS_EDGES {
            self.overflow = true;
            // Keep the existing edge list — a consumer that still reads
            // the vector gets a strict *subset* of the sound over-
            // approximation conveyed by `overflow`.  Correctness is
            // owned by the overflow flag; the residual edges are purely
            // diagnostic.
            return;
        }
        self.edges.push(edge);
    }

    /// Union two summaries, merging edges and OR-ing the overflow /
    /// fresh-alloc flags.  Respects the [`MAX_ALIAS_EDGES`] cap via the
    /// same overflow promotion used by [`Self::insert`].
    pub fn merge(&mut self, other: &Self) {
        self.returns_fresh_alloc |= other.returns_fresh_alloc;
        if other.overflow {
            self.overflow = true;
            return;
        }
        for edge in &other.edges {
            self.insert(edge.source, edge.target, edge.kind);
        }
    }

    /// Parameter indices referenced by any edge in this summary.  Used by
    /// [`crate::summary::ssa_summary_fits_arity`] to confirm the summary
    /// does not reference a parameter beyond the key's declared arity
    /// (which would indicate a synthetic-param mis-attribution in
    /// extraction).
    pub fn max_param_index(&self) -> Option<u32> {
        let mut max: Option<u32> = None;
        for edge in &self.edges {
            if let AliasPosition::Param(i) = edge.source {
                max = Some(max.map_or(i, |m| m.max(i)));
            }
            if let AliasPosition::Param(i) = edge.target {
                max = Some(max.map_or(i, |m| m.max(i)));
            }
        }
        max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_summary_is_noop() {
        let s = PointsToSummary::empty();
        assert!(s.is_empty());
        assert!(!s.overflow);
        assert_eq!(s.edges.len(), 0);
    }

    #[test]
    fn insert_dedups() {
        let mut s = PointsToSummary::empty();
        s.insert(
            AliasPosition::Param(0),
            AliasPosition::Param(1),
            AliasKind::MayAlias,
        );
        s.insert(
            AliasPosition::Param(0),
            AliasPosition::Param(1),
            AliasKind::MayAlias,
        );
        assert_eq!(s.edges.len(), 1);
    }

    #[test]
    fn insert_overflows_at_cap() {
        let mut s = PointsToSummary::empty();
        for i in 0..(MAX_ALIAS_EDGES as u32) {
            s.insert(
                AliasPosition::Param(i),
                AliasPosition::Return,
                AliasKind::MayAlias,
            );
        }
        assert_eq!(s.edges.len(), MAX_ALIAS_EDGES);
        assert!(!s.overflow);
        s.insert(
            AliasPosition::Param(99),
            AliasPosition::Return,
            AliasKind::MayAlias,
        );
        assert!(s.overflow);
        assert_eq!(s.edges.len(), MAX_ALIAS_EDGES);
    }

    #[test]
    fn merge_propagates_overflow() {
        let mut a = PointsToSummary::empty();
        let mut b = PointsToSummary::empty();
        b.overflow = true;
        a.merge(&b);
        assert!(a.overflow);
    }

    #[test]
    fn max_param_index_tracks_both_endpoints() {
        let mut s = PointsToSummary::empty();
        s.insert(
            AliasPosition::Param(0),
            AliasPosition::Param(3),
            AliasKind::MayAlias,
        );
        s.insert(
            AliasPosition::Param(1),
            AliasPosition::Return,
            AliasKind::MayAlias,
        );
        assert_eq!(s.max_param_index(), Some(3));
    }

    #[test]
    fn serde_round_trip_is_stable() {
        let mut s = PointsToSummary::empty();
        s.insert(
            AliasPosition::Param(0),
            AliasPosition::Param(1),
            AliasKind::MayAlias,
        );
        s.insert(
            AliasPosition::Param(2),
            AliasPosition::Return,
            AliasKind::MayAlias,
        );
        let json = serde_json::to_string(&s).unwrap();
        let back: PointsToSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn serde_default_decodes_empty_object() {
        let back: PointsToSummary = serde_json::from_str("{}").unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn returns_fresh_alloc_is_not_empty() {
        let mut s = PointsToSummary::empty();
        assert!(s.is_empty());
        s.returns_fresh_alloc = true;
        assert!(!s.is_empty());
    }

    #[test]
    fn merge_propagates_fresh_alloc_flag() {
        let mut a = PointsToSummary::empty();
        let mut b = PointsToSummary::empty();
        b.returns_fresh_alloc = true;
        a.merge(&b);
        assert!(a.returns_fresh_alloc);
    }

    #[test]
    fn returns_fresh_alloc_roundtrips() {
        let mut s = PointsToSummary::empty();
        s.returns_fresh_alloc = true;
        let json = serde_json::to_string(&s).unwrap();
        let back: PointsToSummary = serde_json::from_str(&json).unwrap();
        assert!(back.returns_fresh_alloc);
        assert_eq!(s, back);
    }
}
