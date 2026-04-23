//! Taint state, lattice, and per-body observability hooks extracted from
//! the original monolithic `ssa_transfer.rs`.
//!
//! Contains:
//! * [`SsaTaintState`] — the per-block lattice value with `values`,
//!   `validated_must`/`validated_may`, `predicates`, `heap`, `path_env`,
//!   `abstract_state`.
//! * [`BindingKey`] / [`seed_lookup`] for cross-body taint seeding.
//! * Observability globals and overrides for worklist iterations and
//!   origin truncation (`MAX_ORIGINS`, `WORKLIST_SAFETY_CAP`, etc.).
//! * The merge-join helpers used by [`Lattice::join`] / [`Lattice::leq`].

use crate::abstract_interp::{self, AbstractState};
use crate::constraint;
use crate::ssa::heap::HeapState;
use crate::ssa::ir::SsaValue;
use crate::state::lattice::Lattice;
use crate::state::symbol::SymbolId;
use crate::taint::domain::{PredicateSummary, SmallBitSet, TaintOrigin, VarTaint};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::HashMap;

/// Maximum origins tracked per SSA value.
pub(super) const MAX_ORIGINS: usize = 4;

/// Default safety cap on taint worklist iterations.  Deliberately large so
/// well-formed programs never hit it; the cap exists to bound adversarial
/// inputs that would otherwise loop forever.  Observable and override-able
/// via [`set_worklist_cap_override`] / [`max_worklist_iterations`] for
/// tests; production behaviour unchanged.
pub(super) const WORKLIST_SAFETY_CAP: usize = 100_000;

static WORKLIST_CAP_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Records the MAX iteration count observed across every
/// `run_ssa_taint_full` call since the most recent reset.  Cheaper and
/// more useful for regression tests than the last-call value — a cap
/// hit anywhere in the scan is remembered.
pub(super) static MAX_WORKLIST_ITERATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Counts how many times the worklist safety cap tripped since the
/// most recent reset.  Lets tests assert "the cap fired at least once"
/// without depending on per-finding attribution, which can lose the
/// signal when cap-hit analyses produce no findings.
pub(super) static WORKLIST_CAP_HITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Test-only override for [`WORKLIST_SAFETY_CAP`].  `cap = 0` restores the
/// default.  Intended exclusively for the engine-notes regression tests
/// that need to force a worklist cap-hit on tiny fixtures.
#[doc(hidden)]
pub fn set_worklist_cap_override(cap: usize) {
    WORKLIST_CAP_OVERRIDE.store(cap, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn effective_worklist_cap() -> usize {
    let o = WORKLIST_CAP_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o == 0 { WORKLIST_SAFETY_CAP } else { o }
}

/// Observability hook: records the max iteration count used by any
/// `run_ssa_taint_full` call since the most recent reset.
pub fn max_worklist_iterations() -> usize {
    MAX_WORKLIST_ITERATIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// How many times the worklist cap has tripped since the most recent
/// reset.  Zero when the cap was never hit.
pub fn worklist_cap_hit_count() -> usize {
    WORKLIST_CAP_HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reset the worklist observability counters.  Intended for tests that
/// want a clean baseline before a scan.
pub fn reset_worklist_observability() {
    MAX_WORKLIST_ITERATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
    WORKLIST_CAP_HITS.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Test-only override for [`MAX_ORIGINS`].  `cap = 0` restores the default
/// (4).  Used to force `OriginsTruncated` emission on small fixtures.
static MAX_ORIGINS_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Total number of origins dropped since the most recent reset — captured
/// from `merge_origins` and the post-hoc saturation scan.  Used by tests
/// to detect truncation events that don't propagate to a finding (e.g.
/// when the cap is so tight no taint flow survives to emit a sink event).
pub(super) static ORIGINS_TRUNCATION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[doc(hidden)]
pub fn set_max_origins_override(cap: usize) {
    MAX_ORIGINS_OVERRIDE.store(cap, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn effective_max_origins() -> usize {
    let o = MAX_ORIGINS_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o == 0 { MAX_ORIGINS } else { o }
}

/// Observability: total origins dropped by the engine since the most
/// recent `reset_origins_observability` call.  Zero when no truncation
/// happened.  Monotone-increasing across calls.
pub fn origins_truncation_count() -> usize {
    ORIGINS_TRUNCATION_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reset the origins-truncation counter.  Intended for tests.
pub fn reset_origins_observability() {
    ORIGINS_TRUNCATION_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
}

thread_local! {
    /// Per-body engine-note collector.  Cleared at the start of each
    /// `analyse_body_with_seed` invocation and drained after
    /// `run_ssa_taint_full` returns — notes are then attached to every
    /// finding emitted from that body.  Living as a thread-local avoids
    /// threading a `&RefCell` through the nearly-10-argument transfer
    /// struct; inline analysis recursion is intentionally allowed to
    /// bubble callee-side cap hits up into the caller's collector.
    static BODY_ENGINE_NOTES: RefCell<SmallVec<[crate::engine_notes::EngineNote; 2]>> =
        RefCell::new(SmallVec::new());
}

/// Record an engine note for the body currently being analysed.  Safe to
/// call from anywhere under a `run_ssa_taint_full` call stack; duplicates
/// against notes already present in the body collector are suppressed.
pub(crate) fn record_engine_note(note: crate::engine_notes::EngineNote) {
    BODY_ENGINE_NOTES.with(|c| {
        crate::engine_notes::push_unique(&mut c.borrow_mut(), note);
    });
}

/// Reset the per-body collector (called at start of each body analysis).
pub(crate) fn reset_body_engine_notes() {
    BODY_ENGINE_NOTES.with(|c| c.borrow_mut().clear());
}

/// Take the current collected notes, leaving the collector empty.  Called
/// after `run_ssa_taint_full` to attach collected notes to findings.
pub(crate) fn take_body_engine_notes() -> SmallVec<[crate::engine_notes::EngineNote; 2]> {
    BODY_ENGINE_NOTES.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// Stable identity for a variable binding at body boundaries.
///
/// Translates between independent per-body `SymbolId` spaces.
/// `SymbolId` remains body-local for intra-body analysis; `BindingKey`
/// is used when taint crosses body boundaries via `global_seed`.
///
/// The optional `body_id` disambiguates same-named bindings across
/// scopes.  When `body_id` is `None`, the key matches by name alone
/// (backward-compatible wildcard); when `Some`, it scopes the binding
/// to a specific body.  Use [`BindingKey::matches`] and [`seed_lookup`]
/// for body-id-aware comparison.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BindingKey {
    pub name: String,
    /// Owning body id.  `None` = scope-unaware (matches any body).
    pub body_id: Option<u32>,
}

impl BindingKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body_id: None,
        }
    }

    pub fn with_body_id(name: impl Into<String>, body_id: u32) -> Self {
        Self {
            name: name.into(),
            body_id: Some(body_id),
        }
    }

    /// Body-id-aware matching: `None` on either side matches by name alone.
    pub fn matches(&self, other: &BindingKey) -> bool {
        if self.name != other.name {
            return false;
        }
        match (self.body_id, other.body_id) {
            (Some(a), Some(b)) => a == b,
            _ => true, // None on either side → name-only match
        }
    }
}

/// Look up a binding in a seed map with body-id-aware fallback.
///
/// 1. Exact HashMap lookup (name + body_id).
/// 2. Fallback: linear scan for any entry where [`BindingKey::matches`]
///    succeeds (handles `None`-wildcard cases).
pub fn seed_lookup<'a>(
    seed: &'a HashMap<BindingKey, VarTaint>,
    key: &BindingKey,
) -> Option<&'a VarTaint> {
    // Fast path: exact match (name + body_id)
    if let Some(taint) = seed.get(key) {
        return Some(taint);
    }
    // Slow path: wildcard match when body_ids differ
    seed.iter().find(|(k, _)| k.matches(key)).map(|(_, v)| v)
}

// ── SSA Taint State ─────────────────────────────────────────────────────

/// Taint state keyed by SsaValue instead of SymbolId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaTaintState {
    /// Per-SSA-value taint, sorted by SsaValue for O(n) merge-join.
    pub values: SmallVec<[(SsaValue, VarTaint); 16]>,
    /// Variables validated on ALL paths (intersection on join). Keyed by SymbolId.
    pub validated_must: SmallBitSet,
    /// Variables validated on ANY path (union on join). Keyed by SymbolId.
    pub validated_may: SmallBitSet,
    /// Per-variable predicate summary (sorted by SymbolId, intersection on join).
    pub predicates: SmallVec<[(SymbolId, PredicateSummary); 4]>,
    /// Per-heap-object taint: container contents taint tracked through
    /// abstract heap identity. Separate from `values` so container taint
    /// persists independently of the SSA value referencing the container.
    pub heap: HeapState,
    /// Path constraint environment. `None` when constraint solving is
    /// disabled (`analysis.engine.constraint_solving = false`).
    pub path_env: Option<constraint::PathEnv>,
    /// Per-SSA-value abstract domain state. `None` when abstract
    /// interpretation is disabled (`analysis.engine.abstract_interpretation
    /// = false`).
    pub abstract_state: Option<AbstractState>,
}

impl SsaTaintState {
    pub fn initial() -> Self {
        Self {
            values: SmallVec::new(),
            validated_must: SmallBitSet::empty(),
            validated_may: SmallBitSet::empty(),
            predicates: SmallVec::new(),
            heap: HeapState::empty(),
            path_env: if constraint::is_enabled() {
                Some(constraint::PathEnv::empty())
            } else {
                None
            },
            abstract_state: if abstract_interp::is_enabled() {
                Some(AbstractState::empty())
            } else {
                None
            },
        }
    }

    /// Check if any variable has contradictory predicates or path constraints.
    pub fn has_contradiction(&self) -> bool {
        self.predicates.iter().any(|(_, s)| s.has_contradiction())
            || self.path_env.as_ref().is_some_and(|e| e.is_unsat())
    }

    pub fn get(&self, v: SsaValue) -> Option<&VarTaint> {
        self.values
            .binary_search_by_key(&v, |(id, _)| *id)
            .ok()
            .map(|idx| &self.values[idx].1)
    }

    pub fn set(&mut self, v: SsaValue, taint: VarTaint) {
        match self.values.binary_search_by_key(&v, |(id, _)| *id) {
            Ok(idx) => self.values[idx].1 = taint,
            Err(idx) => self.values.insert(idx, (v, taint)),
        }
    }

    pub fn remove(&mut self, v: SsaValue) {
        if let Ok(idx) = self.values.binary_search_by_key(&v, |(id, _)| *id) {
            self.values.remove(idx);
        }
    }
}

impl Lattice for SsaTaintState {
    fn bot() -> Self {
        Self::initial()
    }

    fn join(&self, other: &Self) -> Self {
        let values = merge_join_ssa_vars(&self.values, &other.values);
        let validated_must = self.validated_must.intersection(other.validated_must);
        let validated_may = self.validated_may.union(other.validated_may);
        let predicates = merge_join_ssa_predicates(&self.predicates, &other.predicates);
        let heap = self.heap.join(&other.heap);
        let path_env = match (&self.path_env, &other.path_env) {
            (Some(a), Some(b)) => Some(a.join(b)),
            _ => None, // absent = Top, Top.join(x) = Top
        };
        let abstract_state = match (&self.abstract_state, &other.abstract_state) {
            (Some(a), Some(b)) => Some(a.join(b)),
            _ => None,
        };
        SsaTaintState {
            values,
            validated_must,
            validated_may,
            predicates,
            heap,
            path_env,
            abstract_state,
        }
    }

    fn leq(&self, other: &Self) -> bool {
        if !ssa_vars_leq(&self.values, &other.values) {
            return false;
        }
        if !self.validated_must.is_superset_of(other.validated_must) {
            return false;
        }
        if !self.validated_may.is_subset_of(other.validated_may) {
            return false;
        }
        if !self.heap.leq(&other.heap) {
            return false;
        }
        // path_env: None (Top) ≥ everything; Some(a) ≤ None only if a is Top-equivalent
        match (&self.path_env, &other.path_env) {
            (None, Some(_)) => return false, // Top is NOT ≤ constrained
            (Some(_), None) => {}            // constrained ≤ Top: ok
            (None, None) => {}
            (Some(a), Some(b)) => {
                // a ≤ b means a has at least as many constraints as b.
                // For the worklist to converge, we only need: if the
                // joined state didn't change, we stop. The PartialEq
                // check on the full SsaTaintState handles this.
                // For leq, we use a simple approximation: a ≤ b iff
                // a.fact_count() >= b.fact_count() (more facts = lower).
                // This is sound for convergence but approximate.
                if a.fact_count() < b.fact_count() {
                    return false;
                }
            }
        }
        // Abstract-state comparison
        match (&self.abstract_state, &other.abstract_state) {
            (None, Some(_)) => return false,
            (Some(a), Some(b)) if !a.leq(b) => return false,
            _ => {}
        }
        true
    }
}

/// Merge-join two sorted SSA var lists.
pub(super) fn merge_join_ssa_vars(
    a: &[(SsaValue, VarTaint)],
    b: &[(SsaValue, VarTaint)],
) -> SmallVec<[(SsaValue, VarTaint); 16]> {
    let mut result = SmallVec::with_capacity(a.len().max(b.len()));
    let (mut i, mut j) = (0, 0);

    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                result.push(a[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                result.push(b[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let caps = a[i].1.caps | b[j].1.caps;
                let origins = merge_origins(&a[i].1.origins, &b[j].1.origins);
                let uses_summary = a[i].1.uses_summary || b[j].1.uses_summary;
                result.push((
                    a[i].0,
                    VarTaint {
                        caps,
                        origins,
                        uses_summary,
                    },
                ));
                i += 1;
                j += 1;
            }
        }
    }

    while i < a.len() {
        result.push(a[i].clone());
        i += 1;
    }
    while j < b.len() {
        result.push(b[j].clone());
        j += 1;
    }

    result
}

pub(super) fn merge_origins(
    a: &SmallVec<[TaintOrigin; 2]>,
    b: &SmallVec<[TaintOrigin; 2]>,
) -> SmallVec<[TaintOrigin; 2]> {
    let mut merged = a.clone();
    let cap = effective_max_origins();
    let mut dropped: u32 = 0;
    for origin in b {
        if merged.iter().any(|o| o.node == origin.node) {
            continue;
        }
        if merged.len() >= cap {
            dropped = dropped.saturating_add(1);
            continue;
        }
        merged.push(*origin);
    }
    if dropped > 0 {
        ORIGINS_TRUNCATION_COUNT.fetch_add(dropped as usize, std::sync::atomic::Ordering::Relaxed);
        record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated { dropped });
    }
    merged
}

#[allow(dead_code)] // called by Lattice::leq
fn ssa_vars_leq(a: &[(SsaValue, VarTaint)], b: &[(SsaValue, VarTaint)]) -> bool {
    let (mut i, mut j) = (0, 0);

    while i < a.len() {
        if j >= b.len() {
            return false;
        }
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Greater => {
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if a[i].1.caps & b[j].1.caps != a[i].1.caps {
                    return false;
                }
                // uses_summary is monotone: a.uses_summary ≤ b.uses_summary
                if a[i].1.uses_summary && !b[j].1.uses_summary {
                    return false;
                }
                for orig in &a[i].1.origins {
                    if !b[j].1.origins.iter().any(|o| o.node == orig.node) {
                        return false;
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    true
}

/// Merge-join predicate summaries with intersection semantics.
pub(super) fn merge_join_ssa_predicates(
    a: &[(SymbolId, PredicateSummary)],
    b: &[(SymbolId, PredicateSummary)],
) -> SmallVec<[(SymbolId, PredicateSummary); 4]> {
    let mut result = SmallVec::new();
    let (mut i, mut j) = (0, 0);

    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let joined = a[i].1.join(b[j].1);
                if !joined.is_empty() {
                    result.push((a[i].0, joined));
                }
                i += 1;
                j += 1;
            }
        }
    }
    result
}
