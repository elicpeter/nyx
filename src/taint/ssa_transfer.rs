#![allow(
    clippy::collapsible_if,
    clippy::if_same_then_else,
    clippy::manual_flatten,
    clippy::needless_range_loop,
    clippy::only_used_in_recursion,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::unnecessary_map_or
)]

use crate::abstract_interp::{self, AbstractState};
use crate::callgraph::{callee_container_hint, callee_leaf_name};
use crate::cfg::{Cfg, FuncSummaries, NodeInfo};
use crate::constraint;
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, SourceKind};
use crate::ssa::heap::{HeapSlot, HeapState, PointsToResult, PointsToSet};
use crate::ssa::ir::*;
use crate::state::lattice::Lattice;
use crate::state::symbol::{SymbolId, SymbolInterner};
use crate::summary::{CalleeQuery, CalleeResolution, GlobalSummaries, SinkSite};
use crate::symbol::{FuncKey, Lang};
use crate::taint::domain::{
    PredicateSummary, SmallBitSet, TaintOrigin, VarTaint, predicate_kind_bit,
};
use crate::taint::path_state::{PredicateKind, classify_condition_with_target};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum origins tracked per SSA value.
const MAX_ORIGINS: usize = 4;

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
    /// Path constraint environment (Phase 15). `None` when constraint
    /// solving is disabled (`analysis.engine.constraint_solving = false`).
    pub path_env: Option<constraint::PathEnv>,
    /// Per-SSA-value abstract domain state (Phase 17). `None` when abstract
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
        // Phase 17: abstract_state
        match (&self.abstract_state, &other.abstract_state) {
            (None, Some(_)) => return false,
            (Some(a), Some(b)) if !a.leq(b) => return false,
            _ => {}
        }
        true
    }
}

/// Merge-join two sorted SSA var lists.
fn merge_join_ssa_vars(
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

fn merge_origins(
    a: &SmallVec<[TaintOrigin; 2]>,
    b: &SmallVec<[TaintOrigin; 2]>,
) -> SmallVec<[TaintOrigin; 2]> {
    let mut merged = a.clone();
    for origin in b {
        if merged.len() >= MAX_ORIGINS {
            break;
        }
        if !merged.iter().any(|o| o.node == origin.node) {
            merged.push(*origin);
        }
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
fn merge_join_ssa_predicates(
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

// ── SSA Taint Events ────────────────────────────────────────────────────

/// Event emitted when taint reaches a sink in SSA analysis.
#[derive(Clone, Debug)]
pub struct SsaTaintEvent {
    pub sink_node: NodeIndex,
    pub tainted_values: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    pub sink_caps: Cap,
    pub all_validated: bool,
    pub guard_kind: Option<PredicateKind>,
    /// Whether any callee in this event's taint path was resolved via a
    /// function summary (SSA, local, or global) rather than direct label.
    pub uses_summary: bool,
    /// Primary (callee-internal) sink location for cross-file attribution.
    ///
    /// Populated when this event was emitted via summary resolution and the
    /// callee summary carried a [`SinkSite`] whose `cap` intersects
    /// `sink_caps`.  When multiple [`SinkSite`]s for the same `(param_idx,
    /// cap mask)` match, the emission site produces one event per
    /// [`SinkSite`] so each downstream [`crate::taint::Finding`] carries a
    /// single primary attribution — the multi-primary case collapses to
    /// multiple single-primary events.
    ///
    /// `None` for:
    /// * intra-procedural sinks (`uses_summary == false`), where the
    ///   caller's sink span already names the dangerous instruction;
    /// * summary-resolved sinks whose callee summary carried only cap-only
    ///   [`SinkSite`]s (no source coordinates — e.g. pass-2 transient
    ///   summaries or local `LocalFuncSummary`-only callees).
    pub primary_sink_site: Option<SinkSite>,
}

// ── Context-Sensitive Inline Analysis ──────────────────────────────────
//
// # Cache key scope and origin attribution
//
// The inline-analysis cache below ([`InlineCache`]) is keyed by
// `(FuncKey, ArgTaintSig)`, where [`ArgTaintSig`] encodes **per-arg capability
// bits only** — not the identity of the source [`TaintOrigin`]s that produced
// those caps.  This is a deliberate trade-off:
//
// * **Soundness is preserved.**  Capability flow through the callee body is
//   determined entirely by the seed caps; two callers with identical
//   `ArgTaintSig` provably produce the same return caps and the same
//   callee-internal sink activations.
//
// * **Origin attribution is non-deterministic across callers with matching
//   caps but differing origins.**  The first caller to populate a cache entry
//   writes its origin set into `return_taint.origins`; every later caller
//   with the same `ArgTaintSig` reads back those origins and unions them
//   into its own state.  Attribution remains deterministic within a single
//   file analysis (the cache is a per-scope `RefCell` populated in a fixed
//   traversal order), but an individual caller's finding may display an
//   origin that was seeded by a sibling call site.
//
// The engine prefers cap-based correctness over origin-attribution stability.
// If a future change makes origin identity load-bearing for a finding field
// (e.g. a new `primary_source_site` attribution path that reads
// `return_taint.origins` and trusts them to belong to the current caller),
// the fix is to either (a) extend `ArgTaintSig` with a truncated origin-set
// hash, accepting the resulting cache-miss cost, or (b) re-derive origins at
// the call site from the caller's own argument taint rather than from the
// cached `InlineResult`.  Today no downstream consumer assumes this — the
// two read sites (inline-result return-taint union, cross-file summary
// resolution) treat cached origins as best-effort provenance.

/// Maximum SSA blocks in a callee body before skipping inline analysis.
const MAX_INLINE_BLOCKS: usize = 500;

/// Compact cache key: per-arg-position cap bits (sorted, non-empty only).
///
/// Two calls with identical `ArgTaintSig` produce identical inline results
/// for soundness purposes (return caps, callee-internal sink activations).
/// Origin identity is **not** part of the key — see the module-level note
/// above on origin-attribution non-determinism.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ArgTaintSig(SmallVec<[(usize, u16); 4]>);

/// Cached result of inline-analyzing a callee with specific argument taint.
///
/// The `return_taint.origins` set is populated by the first caller that
/// populated the cache entry; later callers with matching caps but different
/// origins read back those same origins.  Cap bits are authoritative; origins
/// are best-effort provenance.
#[derive(Clone, Debug)]
pub(crate) struct InlineResult {
    /// Taint on the return value after inline analysis.
    return_taint: Option<VarTaint>,
}

/// Cache for context-sensitive inline analysis results.
///
/// Keyed by the callee's canonical [`FuncKey`] rather than a bare string name
/// so that same-name definitions (e.g. two `process/1` methods on different
/// classes in the same file) never share or overwrite each other's cache
/// entries.  See the module-level note above for the cap-vs-origin trade-off
/// in the `ArgTaintSig` component of the key.
pub(crate) type InlineCache = HashMap<(FuncKey, ArgTaintSig), InlineResult>;

/// Phase CF-5: drop every entry from an inline cache, marking the start
/// of a new convergence epoch.
///
/// Cross-file SCC fixed-point iteration runs pass 2 repeatedly until the
/// merged summaries stop changing.  Between iterations the callee-summary
/// inputs to inline analysis may have changed, so results cached under a
/// stale snapshot must not leak into the next iteration — otherwise the
/// engine could converge to a non-fixed-point (reporting a taint result
/// that would not reproduce on a fresh run of the same file order).
///
/// The per-file inline cache is already reconstructed fresh at the top of
/// each [`crate::taint::analyse_file`] call, so in the current code this
/// call is effectively a no-op plumbing hook.  Keeping the method (instead
/// of relying on ambient re-construction) makes the lifecycle explicit for
/// any future refactor that moves the cache up into the SCC orchestrator.
#[allow(dead_code)] // CF-5 semantic hook; used by tests and future shared-cache refactor
pub(crate) fn inline_cache_clear_epoch(cache: &mut InlineCache) {
    cache.clear();
}

/// Phase CF-5: set-equal fingerprint of an inline cache, used by the SCC
/// orchestrator to detect when cross-file inline analysis has reached a
/// fixed point alongside summary convergence.
///
/// Returns a `HashMap` mapping each `(FuncKey, ArgTaintSig)` cache key to
/// the return-value capability bits of its inline result.  `HashMap`
/// equality is set-equal (unordered), so two caches with the same entries
/// compare equal regardless of insertion order.
///
/// Origins are intentionally omitted — they are non-deterministic across
/// callers with identical caps (see the module-level note on origin
/// attribution) and would cause the fingerprint to oscillate without
/// reflecting a real precision change.
#[allow(dead_code)] // CF-5 observability hook; used by tests and future shared-cache refactor
pub(crate) fn inline_cache_fingerprint(
    cache: &InlineCache,
) -> HashMap<(FuncKey, ArgTaintSig), u16> {
    cache
        .iter()
        .map(|(k, v)| {
            let caps_bits = v
                .return_taint
                .as_ref()
                .map(|vt| vt.caps.bits())
                .unwrap_or(0);
            (k.clone(), caps_bits)
        })
        .collect()
}

/// CFG node metadata embedded in cross-file callee bodies.
///
/// ## Phase CF-3 (Option A) — why a full [`NodeInfo`] lives here
///
/// Earlier phases carried only the two fields the symex executor reads
/// (`bin_op`, `labels`).  That was sufficient for symex but not for the taint
/// engine, which reads ~20 fields off `cfg[inst.cfg_node]` across
/// `transfer_inst`, `collect_block_events`, `compute_succ_states`, and helpers
/// (callee name, `arg_uses`, `arg_callees`, `call_ordinal`, `outer_callee`,
/// `kwargs`, `arg_string_literals`, `ast.span`, `ast.enclosing_func`,
/// `condition_*`, `all_args_literal`, `catch_param`, `parameterized_query`,
/// `in_defer`, `cast_target_type`, `string_prefix`, `taint.uses`,
/// `taint.defines`, `taint.extra_defines`, `taint.const_text`, …).  Rather
/// than shuttling each of those through a `CfgView` accessor at every
/// callsite, we store a full serde-able [`NodeInfo`] snapshot here so the
/// indexed-scan path can rehydrate an equivalent `Cfg` on load
/// (see [`rebuild_body_graph`]).  Both scan paths then feed the same
/// `&Cfg` into the taint engine, and cross-file inline fires regardless of
/// whether the body came from pass 1 or from SQLite.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrossFileNodeMeta {
    /// Full `NodeInfo` snapshot for this body-local NodeIndex.
    pub info: crate::cfg::NodeInfo,
}

/// Pre-lowered and optimized SSA body for a function,
/// ready for context-sensitive re-analysis with different argument taint.
///
/// For intra-file use, `node_meta` is empty and the original CFG is used.
/// For cross-file persistence (Phase 30), `node_meta` carries the minimal
/// CFG metadata needed by the symex executor.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CalleeSsaBody {
    pub ssa: SsaBody,
    pub opt: crate::ssa::OptimizeResult,
    pub param_count: usize,
    /// Per-NodeIndex CFG metadata for cross-file bodies.
    /// Empty for intra-file bodies (the original CFG is used instead).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub node_meta: std::collections::HashMap<u32, CrossFileNodeMeta>,
    /// The body's own CFG graph.  Populated for intra-file bodies so that
    /// inline analysis can reference the correct graph (per-body CFGs have
    /// body-local NodeIndex spaces).  `None` for cross-file deserialized bodies.
    #[serde(skip)]
    pub body_graph: Option<crate::cfg::Cfg>,
}

/// Populate `node_meta` from the original CFG for cross-file persistence.
///
/// Returns `true` if all referenced NodeIndex values were resolved successfully.
/// Returns `false` if any node was out of bounds (body is ineligible for cross-file use).
pub fn populate_node_meta(body: &mut CalleeSsaBody, cfg: &crate::cfg::Cfg) -> bool {
    // Collect every NodeIndex this body references, then snapshot each one's
    // NodeInfo into `node_meta`.  Done in two passes so the inner loop can
    // mutate `body.node_meta` without borrow-checker conflicts on
    // `body.ssa.blocks`.
    //
    // `Terminator::Branch.cond` must be captured as well: it is consumed by
    // `compute_succ_states` via `cfg[*cond]`, so without it the synthesized
    // cross-file proxy CFG (`rebuild_body_graph`) ends up too small whenever
    // the callee body has any conditional branch whose `cond` index sits
    // past the maximum `inst.cfg_node` index — inline analysis then panics
    // with an out-of-bounds index.
    let mut referenced: Vec<NodeIndex> = Vec::new();
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            referenced.push(inst.cfg_node);
        }
        if let Terminator::Branch { cond, .. } = &block.terminator {
            referenced.push(*cond);
        }
    }
    for node in referenced {
        let idx = node.index() as u32;
        if body.node_meta.contains_key(&idx) {
            continue;
        }
        if node.index() >= cfg.node_count() {
            return false;
        }
        let info = cfg[node].clone();
        body.node_meta.insert(idx, CrossFileNodeMeta { info });
    }
    true
}

/// Synthesize a proxy [`Cfg`] from `node_meta` so the taint engine can
/// index `cfg[inst.cfg_node]` uniformly on the indexed-scan path.
///
/// When the callee body was loaded from SQLite, `body_graph` is `None`
/// (it is `#[serde(skip)]`), but `node_meta` carries a full [`NodeInfo`]
/// for every referenced NodeIndex (see [`populate_node_meta`]).  This
/// helper rebuilds a petgraph `Cfg` with nodes at exactly the right
/// NodeIndex positions so the taint engine's existing indexing works
/// without change.
///
/// Returns `true` if a proxy graph was freshly installed.  Idempotent:
/// subsequent calls are cheap no-ops once `body_graph` is `Some`.  No-op
/// for intra-file bodies (which arrive with `body_graph` already set and
/// `node_meta` empty).
pub fn rebuild_body_graph(body: &mut CalleeSsaBody) -> bool {
    if body.body_graph.is_some() {
        return false;
    }
    if body.node_meta.is_empty() {
        return false;
    }
    // Determine the maximum NodeIndex referenced by the SSA so the
    // synthesized graph has an entry at every position the engine may
    // index.  We fill any unreferenced intermediate indices with
    // `NodeInfo::default()`.
    //
    // Walks both instruction `cfg_node`s and `Terminator::Branch.cond` —
    // the latter is read by `compute_succ_states` via `cfg[*cond]`, so
    // missing it produces an OOB panic when a conditional branch's cond
    // node has a higher index than any `inst.cfg_node` in the body.
    let mut max_idx: u32 = 0;
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let idx = inst.cfg_node.index() as u32;
            if idx > max_idx {
                max_idx = idx;
            }
        }
        if let Terminator::Branch { cond, .. } = &block.terminator {
            let idx = cond.index() as u32;
            if idx > max_idx {
                max_idx = idx;
            }
        }
    }
    // Also consider node_meta keys — they should be a subset of the
    // SSA-referenced indices, but be defensive.
    for &k in body.node_meta.keys() {
        if k > max_idx {
            max_idx = k;
        }
    }

    use petgraph::graph::Graph;
    let mut graph: crate::cfg::Cfg = Graph::new();
    // petgraph allocates sequential NodeIndex values.  Insert placeholders
    // up to and including max_idx.
    for i in 0..=max_idx {
        let info = body
            .node_meta
            .get(&i)
            .map(|m| m.info.clone())
            .unwrap_or_default();
        graph.add_node(info);
    }
    // Edges are not consulted by the taint engine during inline analysis
    // (control flow comes from `SsaBlock::preds`/`succs` and
    // `SsaBlock::terminator`), so we leave the graph edge-free.
    body.body_graph = Some(graph);
    true
}

// ── SSA Taint Transfer ──────────────────────────────────────────────────

/// Configuration for SSA taint analysis.
pub struct SsaTaintTransfer<'a> {
    pub lang: Lang,
    pub namespace: &'a str,
    pub interner: &'a SymbolInterner,
    pub local_summaries: &'a FuncSummaries,
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub interop_edges: &'a [InteropEdge],
    /// Taint from enclosing/parent body scope, keyed by [`BindingKey`].
    /// Read-only fallback for `Param` ops representing captured or
    /// module-scope variables.  Used in multi-body analysis for lexical
    /// containment propagation (top-level → function → closure).
    pub global_seed: Option<&'a HashMap<BindingKey, VarTaint>>,
    /// Per-SSA-value constant lattice from constant propagation.
    /// Used for SSA-level literal suppression at sinks.
    pub const_values: Option<&'a HashMap<SsaValue, crate::ssa::const_prop::ConstLattice>>,
    /// Type facts from type analysis.
    /// Used for type-aware sink filtering (e.g., suppress SQL injection for int-typed values).
    pub type_facts: Option<&'a crate::ssa::type_facts::TypeFactResult>,
    /// Precise per-function SSA summaries for intra-file callee resolution.
    /// Checked before legacy FuncSummary resolution.
    ///
    /// Keyed by canonical [`FuncKey`] — never bare function name — so
    /// same-name functions in the same file cannot silently overwrite one
    /// another.
    pub ssa_summaries: Option<&'a HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>>,
    /// Extra label rules from user config (custom sources/sanitizers/sinks).
    /// Used as fallback when `resolve_callee` finds no summary for an inner
    /// arg callee — so label-only sanitizers still reduce sink caps.
    pub extra_labels: Option<&'a [RuntimeLabelRule]>,
    /// Pre-lowered + optimized SSA bodies for intra-file functions.
    /// When present, enables context-sensitive inline analysis at call sites.
    ///
    /// Keyed by canonical [`FuncKey`] (same identity model as `ssa_summaries`).
    pub callee_bodies: Option<&'a HashMap<FuncKey, CalleeSsaBody>>,
    /// Cache for context-sensitive inline results. Uses `RefCell` for interior
    /// mutability (safe: k=1 depth limit prevents re-entrancy during borrow).
    pub(crate) inline_cache: Option<&'a RefCell<InlineCache>>,
    /// Base-variable alias groups for alias-aware sanitization propagation.
    /// When present, sanitization of `alias.field` also sanitizes `base.field`
    /// for all must-aliased base names.
    pub base_aliases: Option<&'a crate::ssa::alias::BaseAliasResult>,
    /// Current inline analysis depth (0 = top-level caller). When >= 1,
    /// inline analysis falls back to summary resolution (k=1 bound).
    pub context_depth: u8,
    /// Callback bindings: maps callee parameter name → resolved callee
    /// [`FuncKey`].
    ///
    /// Populated during inline analysis when the caller passes a function
    /// reference as an argument.  The value is a full `FuncKey` so that when
    /// the callee invokes the parameter the call resolves back to the exact
    /// same definition without re-entering bare-name lookup.
    pub callback_bindings: Option<&'a HashMap<String, FuncKey>>,
    /// Points-to analysis result: per-SSA-value abstract heap object sets.
    /// When present, container taint flows through heap objects instead of
    /// being merged directly into SSA values.
    pub points_to: Option<&'a PointsToResult>,
    /// Dynamic points-to set: populated at call sites by inter-procedural
    /// container identity propagation from `param_container_to_return` summaries.
    /// Uses `RefCell` for interior mutability (same pattern as `inline_cache`).
    pub dynamic_pts: Option<&'a RefCell<HashMap<SsaValue, PointsToSet>>>,
    /// Import alias bindings: local alias → (original name, module path).
    /// Used in `resolve_callee` to map aliased import names back to their
    /// original exported symbol before summary lookup.
    pub import_bindings: Option<&'a crate::cfg::ImportBindings>,
    /// Promisify alias bindings: `const alias = util.promisify(wrapped)` for
    /// JS/TS.  Used in `resolve_callee` so summary lookup for `alias(...)` falls
    /// back to `wrapped`'s summary.  Label-based sink/source detection is
    /// handled by a CFG post-pass that unions the wrapped callee's labels into
    /// every matching call-site's `info.taint.labels`.
    pub promisify_aliases: Option<&'a crate::cfg::PromisifyAliases>,
    /// Module aliases from `require()` calls: SSA value → possible module names.
    /// Used to resolve dynamic dispatch (e.g., `lib.request()` where
    /// `lib = require("http")`) for sink label matching.
    pub module_aliases: Option<&'a HashMap<SsaValue, smallvec::SmallVec<[String; 2]>>>,
    /// Static-map analysis result: SSA values whose concrete string value is
    /// provably bounded to a finite set of literals (e.g. the result of
    /// `map.get(x).unwrap_or("fallback")` over an all-literal-insert map).
    /// When present, seeded into [`AbstractState`] at entry so downstream sink
    /// suppression can clear command-injection findings whose payload is
    /// provably metacharacter-free.
    pub static_map: Option<&'a crate::ssa::static_map::StaticMapResult>,
    /// When `true`, JS/TS formal parameters whose names strongly imply user
    /// input (see [`crate::labels::is_js_ts_handler_param_name`]) are
    /// auto-seeded with a `UserInput` source on entry.  Defaults to `false`
    /// so summary probes and non-JS/TS pipelines keep their existing
    /// baseline-subtraction semantics; the findings pipeline flips this on
    /// to detect handler-style flows that have no registered caller.
    pub auto_seed_handler_params: bool,
    /// Phase CF-1: Cross-file callee bodies sourced from
    /// [`GlobalSummaries::bodies_iter`].  Populated in pass 2 so that a
    /// follow-up phase (CF-2) can enable context-sensitive inline
    /// re-analysis across file boundaries the same way `callee_bodies`
    /// enables it intra-file.  This field is plumbing only in CF-1 — no
    /// code path reads it yet.  `None` preserves pre-CF-1 behaviour for
    /// unit tests and non-cross-file construction sites.
    pub cross_file_bodies: Option<&'a HashMap<FuncKey, CalleeSsaBody>>,
}

/// Per-predecessor state tracking for path-sensitive phi evaluation.
/// Maps (successor_block_idx, predecessor_block_idx) → predecessor's exit state.
type PredStates = HashMap<(usize, usize), SsaTaintState>;

struct SsaTaintRunResult {
    events: Vec<SsaTaintEvent>,
    block_states: Vec<Option<SsaTaintState>>,
    block_exit_states: Vec<Option<SsaTaintState>>,
}

/// Run SSA-based taint analysis, returning events AND converged block states.
pub fn run_ssa_taint_full(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> (Vec<SsaTaintEvent>, Vec<Option<SsaTaintState>>) {
    let result = run_ssa_taint_internal(ssa, cfg, transfer);
    (result.events, result.block_states)
}

/// Run SSA-based taint analysis, returning events plus converged entry and
/// exit states for each block. Intended for debug/introspection views.
pub fn run_ssa_taint_full_with_exits(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> (
    Vec<SsaTaintEvent>,
    Vec<Option<SsaTaintState>>,
    Vec<Option<SsaTaintState>>,
) {
    let result = run_ssa_taint_internal(ssa, cfg, transfer);
    (result.events, result.block_states, result.block_exit_states)
}

fn run_ssa_taint_internal(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> SsaTaintRunResult {
    let num_blocks = ssa.blocks.len();

    // Detect induction variables before analysis
    let back_edges = detect_back_edges(ssa);
    let induction_vars = detect_induction_phis(ssa, &back_edges);

    // Per-block entry states
    let mut block_states: Vec<Option<SsaTaintState>> = vec![None; num_blocks];
    let mut block_exit_states: Vec<Option<SsaTaintState>> = vec![None; num_blocks];
    block_states[ssa.entry.0 as usize] = Some(SsaTaintState::initial());

    // Phase 15: Seed entry block's PathEnv from optimization results
    if let Some(ref mut entry_state) = block_states[ssa.entry.0 as usize] {
        if let Some(ref mut env) = entry_state.path_env {
            if let (Some(cv), Some(tf)) = (transfer.const_values, transfer.type_facts) {
                env.seed_from_optimization(cv, tf);
            }
        }
    }

    // Phase 17: Seed entry block's AbstractState from optimization results
    if let Some(ref mut entry_state) = block_states[ssa.entry.0 as usize] {
        if let Some(ref mut abs) = entry_state.abstract_state {
            if let Some(cv) = transfer.const_values {
                use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, StringFact};
                use crate::ssa::const_prop::ConstLattice;
                for (v, cl) in cv {
                    match cl {
                        ConstLattice::Int(n) => {
                            abs.set(
                                *v,
                                AbstractValue {
                                    interval: IntervalFact::exact(*n),
                                    string: StringFact::top(),
                                    bits: BitFact::from_const(*n),
                                },
                            );
                        }
                        ConstLattice::Str(s) => {
                            abs.set(
                                *v,
                                AbstractValue {
                                    interval: IntervalFact::top(),
                                    string: StringFact::exact(s),
                                    bits: BitFact::top(),
                                },
                            );
                        }
                        _ => {}
                    }
                }
            }
            // Static-map seeding is intentionally NOT fused into the
            // AbstractState here.  A blanket `StringFact::finite_set` would
            // compose with `StringFact::exact` facts emitted by
            // `transfer_abstract` for every string literal — and downstream
            // suppression logic can't distinguish "single-literal exact"
            // from "multi-literal bounded lookup".  Instead the sink check
            // consults `transfer.static_map` directly via the dedicated
            // `is_static_map_shell_safe` predicate, which only fires when
            // the value was proved bounded by the HashMap idiom detector.
        }
    }

    // Phase 17: Compute loop heads for widening
    let loop_heads: HashSet<usize> = back_edges
        .iter()
        .map(|(_, target)| target.0 as usize)
        .collect();

    // Per-predecessor exit states for path-sensitive phi evaluation
    let mut pred_states: PredStates = HashMap::new();

    // Phase 1: fixed-point iteration
    let mut worklist: VecDeque<usize> = VecDeque::new();
    let mut in_worklist: HashSet<usize> = HashSet::new();
    worklist.push_back(ssa.entry.0 as usize);
    in_worklist.insert(ssa.entry.0 as usize);

    // Initialize orphan blocks (no predecessors, not entry) with initial state.
    // This handles catch blocks that are disconnected after exception edge stripping.
    for (bid, block) in ssa.blocks.iter().enumerate() {
        if bid != ssa.entry.0 as usize && block.preds.is_empty() {
            block_states[bid] = Some(SsaTaintState::initial());
            worklist.push_back(bid);
            in_worklist.insert(bid);
        }
    }
    if !ssa.exception_edges.is_empty() {
        tracing::debug!(
            count = ssa.exception_edges.len(),
            "SSA taint: exception edges for catch-block seeding"
        );
    }
    let mut iterations: usize = 0;
    const BUDGET: usize = 100_000;

    while let Some(bid) = worklist.pop_front() {
        in_worklist.remove(&bid);
        iterations += 1;
        if iterations > BUDGET {
            tracing::warn!("SSA taint: worklist budget exceeded");
            break;
        }

        let entry_state = match &block_states[bid] {
            Some(s) => s.clone(),
            None => continue,
        };

        let block = &ssa.blocks[bid];
        let exit_state = transfer_block(
            block,
            cfg,
            ssa,
            transfer,
            entry_state,
            &induction_vars,
            Some(&pred_states),
        );
        block_exit_states[bid] = Some(exit_state.clone());

        // Build per-successor states (branch-aware for Branch terminators)
        let succ_states = compute_succ_states(block, cfg, ssa, transfer, &exit_state);

        // Store predecessor-specific states before joining
        for &(succ_id, ref succ_state) in &succ_states {
            let succ_idx = succ_id.0 as usize;
            pred_states.insert((succ_idx, bid), succ_state.clone());
        }

        // Propagate to successors
        for (succ_id, succ_state) in succ_states {
            let succ_idx = succ_id.0 as usize;

            let new_succ_state = match &block_states[succ_idx] {
                Some(existing) => {
                    let mut joined = existing.join(&succ_state);
                    // Phase 17: Widen abstract values at loop heads
                    if loop_heads.contains(&succ_idx) {
                        if let (Some(new_abs), Some(old_abs)) =
                            (&joined.abstract_state, &existing.abstract_state)
                        {
                            let widened = old_abs.widen(new_abs);
                            joined.abstract_state = Some(widened);
                        }
                    }
                    joined
                }
                None => succ_state,
            };

            let changed = block_states[succ_idx]
                .as_ref()
                .is_none_or(|existing| *existing != new_succ_state);

            if changed {
                block_states[succ_idx] = Some(new_succ_state);
                if in_worklist.insert(succ_idx) {
                    worklist.push_back(succ_idx);
                }
            }
        }

        // Propagate taint to catch blocks via exception edges.
        // Mirrors legacy semantics: variable taint carries across exception
        // edges but predicates are cleared (exception bypasses try conditions).
        let bid_id = BlockId(bid as u32);
        for &(src_blk, catch_blk) in &ssa.exception_edges {
            if src_blk != bid_id {
                continue;
            }
            let catch_idx = catch_blk.0 as usize;
            let mut exc_state = exit_state.clone();
            exc_state.predicates.clear();
            exc_state.path_env = None; // constraints don't survive exceptions

            let new_catch_state = match &block_states[catch_idx] {
                Some(existing) => existing.join(&exc_state),
                None => exc_state,
            };

            let changed = block_states[catch_idx]
                .as_ref()
                .is_none_or(|existing| *existing != new_catch_state);

            if changed {
                block_states[catch_idx] = Some(new_catch_state);
                if in_worklist.insert(catch_idx) {
                    worklist.push_back(catch_idx);
                }
            }
        }
    }

    // Phase 2: single pass over converged states to collect events
    let mut events: Vec<SsaTaintEvent> = Vec::new();

    for bid in 0..num_blocks {
        let entry_state = match &block_states[bid] {
            Some(s) => s.clone(),
            None => continue,
        };

        let block = &ssa.blocks[bid];
        collect_block_events(
            block,
            cfg,
            ssa,
            transfer,
            entry_state,
            &mut events,
            &induction_vars,
            Some(&pred_states),
        );
    }

    SsaTaintRunResult {
        events,
        block_states,
        block_exit_states,
    }
}

/// Convenience wrapper: returns only events (existing signature).
pub fn run_ssa_taint(ssa: &SsaBody, cfg: &Cfg, transfer: &SsaTaintTransfer) -> Vec<SsaTaintEvent> {
    run_ssa_taint_full(ssa, cfg, transfer).0
}

/// Project SsaValue-keyed taint back to [`BindingKey`]-keyed taint via var_name.
///
/// Recomputes exit states from converged entry states, then maps
/// SsaValue → var_name → `BindingKey`.  The returned map is suitable
/// for seeding child bodies via `global_seed`.
pub fn extract_ssa_exit_state(
    block_states: &[Option<SsaTaintState>],
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> HashMap<BindingKey, VarTaint> {
    // Compute exit states by replaying transfer on converged entry states
    let empty_induction = HashSet::new();
    let mut joined = SsaTaintState::initial();
    for (bid, entry_state) in block_states.iter().enumerate() {
        if let Some(state) = entry_state {
            let exit_state = transfer_block(
                &ssa.blocks[bid],
                cfg,
                ssa,
                transfer,
                state.clone(),
                &empty_induction,
                None,
            );
            joined = joined.join(&exit_state);
        }
    }

    // Map SsaValue → var_name → BindingKey
    // TODO(C-2): pass body_id into this function and use BindingKey::with_body_id
    // to scope exit-state keys to their owning body.
    let mut result: HashMap<BindingKey, VarTaint> = HashMap::new();
    for (val, taint) in &joined.values {
        let var_name = ssa
            .value_defs
            .get(val.0 as usize)
            .and_then(|vd| vd.var_name.as_deref());
        if let Some(name) = var_name {
            let key = BindingKey::new(name);
            result
                .entry(key)
                .and_modify(|existing| {
                    existing.caps |= taint.caps;
                    for orig in &taint.origins {
                        if existing.origins.len() < MAX_ORIGINS
                            && !existing.origins.iter().any(|o| o.node == orig.node)
                        {
                            existing.origins.push(*orig);
                        }
                    }
                })
                .or_insert_with(|| taint.clone());
        }
    }

    // Capture source spans on all origins before the seed crosses a body
    // boundary.  At consumption time the parent's graph is not in scope,
    // so we snapshot each origin's span now.  Use the classification span
    // so the recorded origin points at the labeled sub-expression (e.g.
    // the inner `req.query.x` call) rather than the enclosing statement.
    for taint in result.values_mut() {
        for origin in taint.origins.iter_mut() {
            if origin.source_span.is_none() {
                if let Some(info) = cfg.node_weight(origin.node) {
                    origin.source_span = Some(info.classification_span());
                }
            }
        }
    }

    result
}

/// Join two [`BindingKey`]-keyed seed maps (OR caps, merge origins).
pub fn join_seed_maps(
    a: &HashMap<BindingKey, VarTaint>,
    b: &HashMap<BindingKey, VarTaint>,
) -> HashMap<BindingKey, VarTaint> {
    let mut result = a.clone();
    for (key, taint) in b {
        result
            .entry(key.clone())
            .and_modify(|existing| {
                existing.caps |= taint.caps;
                for orig in &taint.origins {
                    if existing.origins.len() < MAX_ORIGINS
                        && !existing.origins.iter().any(|o| o.node == orig.node)
                    {
                        existing.origins.push(*orig);
                    }
                }
            })
            .or_insert_with(|| taint.clone());
    }
    result
}

/// Filter seed map to only include bindings in the given set.
///
/// Uses [`BindingKey::matches`] so that toplevel keys with `body_id=None`
/// match seed entries regardless of their body_id.
pub fn filter_seed_to_toplevel(
    seed: &HashMap<BindingKey, VarTaint>,
    toplevel: &HashSet<BindingKey>,
) -> HashMap<BindingKey, VarTaint> {
    seed.iter()
        .filter(|(key, _)| toplevel.iter().any(|tk| tk.matches(key)))
        .map(|(key, taint)| (key.clone(), taint.clone()))
        .collect()
}

// ── Loop Induction Variable Detection ────────────────────────────────────

/// Detect back edges using block numbering heuristic.
/// A back edge is (pred, block) where pred.0 >= block.0, valid because
/// `form_blocks()` builds blocks in BFS order.
fn detect_back_edges(ssa: &SsaBody) -> HashSet<(BlockId, BlockId)> {
    let mut back_edges = HashSet::new();
    for block in &ssa.blocks {
        for &pred in &block.preds {
            if pred.0 >= block.id.0 {
                back_edges.insert((pred, block.id));
            }
        }
    }
    back_edges
}

/// Check if `inc_val` is defined as a simple increment of `phi_val`:
/// `inc_val = phi_val + const` or `inc_val = phi_val - const`.
fn is_simple_increment(ssa: &SsaBody, inc_val: SsaValue, phi_val: SsaValue) -> bool {
    let def = ssa.def_of(inc_val);
    let block = ssa.block(def.block);
    // Look in the block body for the defining instruction
    for inst in &block.body {
        if inst.value == inc_val {
            if let SsaOp::Assign(ref uses) = inst.op {
                // Pattern: assign([phi_val, const_val]) — simple binary op
                if uses.len() == 2 && uses.contains(&phi_val) {
                    let other = if uses[0] == phi_val { uses[1] } else { uses[0] };
                    // Check if the other operand is a constant
                    let other_def = ssa.def_of(other);
                    let other_block = ssa.block(other_def.block);
                    for other_inst in other_block.phis.iter().chain(other_block.body.iter()) {
                        if other_inst.value == other && matches!(other_inst.op, SsaOp::Const(_)) {
                            return true;
                        }
                    }
                }
            }
            break;
        }
    }
    false
}

/// Detect phi nodes that represent loop induction variables.
/// Returns the set of SsaValues (phi results) that are simple induction variables.
fn detect_induction_phis(
    ssa: &SsaBody,
    back_edges: &HashSet<(BlockId, BlockId)>,
) -> HashSet<SsaValue> {
    let mut induction_vars = HashSet::new();

    for block in &ssa.blocks {
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                if operands.len() != 2 {
                    continue;
                }

                // Identify which operand comes via back edge
                let mut back_edge_op = None;
                let mut init_op = None;
                for &(pred_blk, operand_val) in operands {
                    if back_edges.contains(&(pred_blk, block.id)) {
                        back_edge_op = Some(operand_val);
                    } else {
                        init_op = Some(operand_val);
                    }
                }

                if let (Some(back_val), Some(_init_val)) = (back_edge_op, init_op) {
                    if is_simple_increment(ssa, back_val, phi.value) {
                        induction_vars.insert(phi.value);
                    }
                }
            }
        }
    }

    induction_vars
}

/// Transfer a single block: process phis then body, return exit state.
fn transfer_block(
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    mut state: SsaTaintState,
    induction_vars: &HashSet<SsaValue>,
    pred_states: Option<&PredStates>,
) -> SsaTaintState {
    // Process phis
    let block_idx = block.id.0 as usize;
    for phi in &block.phis {
        if let SsaOp::Phi(ref operands) = phi.op {
            // Induction variable optimization: skip back-edge operands
            let is_induction = induction_vars.contains(&phi.value);

            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut all_tainted_validated = true;
            let mut any_tainted = false;

            for &(pred_blk, operand_val) in operands {
                // Skip back-edge operands for induction vars
                if is_induction && pred_blk.0 >= block.id.0 {
                    continue;
                }

                // Phase 15: Skip predecessor operands from infeasible paths
                if let Some(ps) = pred_states {
                    if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                        if pred_st.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                            continue;
                        }
                    }
                }

                // Use predecessor-specific state when available (path sensitivity)
                let operand_taint = if let Some(ps) = pred_states {
                    ps.get(&(block_idx, pred_blk.0 as usize))
                        .and_then(|pred_st| pred_st.get(operand_val))
                } else {
                    None
                };
                // Fall back to joined entry state
                let operand_taint = operand_taint.or_else(|| state.get(operand_val));

                if let Some(taint) = operand_taint {
                    any_tainted = true;
                    combined_caps |= taint.caps;
                    for orig in &taint.origins {
                        if combined_origins.len() < MAX_ORIGINS
                            && !combined_origins.iter().any(|o| o.node == orig.node)
                        {
                            combined_origins.push(*orig);
                        }
                    }

                    // Path sensitivity: check if this operand is validated in its predecessor
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            let var_name = ssa
                                .value_defs
                                .get(operand_val.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref());
                            if let Some(name) = var_name {
                                if let Some(sym) = transfer.interner.get(name) {
                                    if !pred_st.validated_must.contains(sym) {
                                        all_tainted_validated = false;
                                    }
                                } else {
                                    all_tainted_validated = false;
                                }
                            } else {
                                all_tainted_validated = false;
                            }
                        } else {
                            all_tainted_validated = false;
                        }
                    } else {
                        all_tainted_validated = false;
                    }
                }
            }

            if combined_caps.is_empty() {
                state.remove(phi.value);
            } else {
                state.set(
                    phi.value,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                        uses_summary: false,
                    },
                );

                // Path sensitivity: if all tainted predecessors validated, propagate to phi result
                if any_tainted && all_tainted_validated {
                    if let Some(name) = ssa
                        .value_defs
                        .get(phi.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    {
                        if let Some(sym) = transfer.interner.get(name) {
                            state.validated_may.insert(sym);
                            state.validated_must.insert(sym);
                        }
                    }
                }
            }
        }
    }

    // Phase 17: Abstract value phi join (from predecessor exit states)
    if state.abstract_state.is_some() {
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                use crate::abstract_interp::AbstractValue;
                let is_induction = induction_vars.contains(&phi.value);
                let mut joined = AbstractValue::bottom();
                let mut any_operand = false;

                for &(pred_blk, operand_val) in operands {
                    if is_induction && pred_blk.0 >= block.id.0 {
                        continue;
                    }
                    // Skip infeasible predecessors
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            if pred_st.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                                continue;
                            }
                        }
                    }
                    // Look up operand abstract value from predecessor exit state
                    let pred_abs = pred_states
                        .and_then(|ps| ps.get(&(block_idx, pred_blk.0 as usize)))
                        .and_then(|s| s.abstract_state.as_ref())
                        .map(|a| a.get(operand_val))
                        .unwrap_or_else(AbstractValue::top);
                    joined = joined.join(&pred_abs);
                    any_operand = true;
                }

                if any_operand {
                    if let Some(ref mut abs) = state.abstract_state {
                        abs.set(phi.value, joined);
                    }
                }
            }
        }
    }

    // Process body
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);
    }

    state
}

/// Compute per-successor states with branch-aware predicate handling.
///
/// For `Branch` terminators, inspects the condition node for validation/predicate
/// info and produces specialized true/false states. For other terminators,
/// propagates the exit state uniformly.
fn compute_succ_states(
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    exit_state: &SsaTaintState,
) -> SmallVec<[(BlockId, SsaTaintState); 2]> {
    match &block.terminator {
        Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            condition,
        } => {
            // Defensive: `cond` should always be present in `cfg`, but cross-file
            // proxy CFGs synthesized in `rebuild_body_graph` previously missed
            // Branch.cond entries (now fixed above).  Falling through to uniform
            // propagation on a missing cond preserves liveness rather than
            // crashing the worker thread if a future regression re-introduces it.
            let Some(cond_info) = cfg.node_weight(*cond) else {
                return smallvec::smallvec![
                    (*true_blk, exit_state.clone()),
                    (*false_blk, exit_state.clone()),
                ];
            };
            if cond_info.kind == crate::cfg::StmtKind::If && !cond_info.condition_vars.is_empty() {
                let cond_text = cond_info.condition_text.as_deref().unwrap_or("");
                let (kind, target_var) = classify_condition_with_target(cond_text);

                // Determine which vars to apply validation to:
                // If we extracted a specific target, narrow to just that var
                // (if it's in condition_vars). Otherwise use all condition_vars.
                let effective_vars: Vec<String> = if let Some(ref target) = target_var {
                    if cond_info.condition_vars.iter().any(|v| v == target) {
                        vec![target.clone()]
                    } else {
                        cond_info.condition_vars.clone()
                    }
                } else {
                    cond_info.condition_vars.clone()
                };

                let mut true_state = exit_state.clone();
                let mut false_state = exit_state.clone();

                // Detect semantic negation that isn't captured by AST-level
                // `condition_negated` (which only detects unary `!`/`not`).
                //
                // - Python `not in`: comparison operator, not unary negation
                // - TypeCheck with `!==`/`!=`: "typeof x !== 'number'" means
                //   the true branch is the REJECT path (type mismatch)
                let cond_lower = cond_text.to_ascii_lowercase();
                let has_semantic_negation = (kind == PredicateKind::AllowlistCheck
                    && cond_lower.contains(" not in "))
                    || (kind == PredicateKind::TypeCheck
                        && (cond_lower.contains("!==") || cond_lower.contains("!=")));
                let effective_negated = if has_semantic_negation {
                    !cond_info.condition_negated
                } else {
                    cond_info.condition_negated
                };

                // True edge polarity: effective_negated XOR true
                let true_polarity = !effective_negated;
                let false_polarity = effective_negated;

                // Apply validation/predicate to true branch
                apply_branch_predicates(
                    &mut true_state,
                    &effective_vars,
                    kind,
                    true_polarity,
                    transfer.interner,
                );
                // Apply validation/predicate to false branch
                apply_branch_predicates(
                    &mut false_state,
                    &effective_vars,
                    kind,
                    false_polarity,
                    transfer.interner,
                );

                // Phase 15/16: Constraint refinement
                //
                // `lower_condition` returns a ConditionExpr that represents the
                // full semantic condition (it already applies `condition_negated`
                // internally). The true branch is where the condition holds
                // (polarity=true), the false branch is where it doesn't
                // (polarity=false). We do NOT reuse `effective_negated` here —
                // that variable incorporates `has_semantic_negation` which is a
                // predicate-system concern, not a constraint-system concern.
                if true_state.path_env.is_some() || false_state.path_env.is_some() {
                    // Prefer pre-lowered structured condition from terminator;
                    // fall back to text-based lowering for backward compat.
                    let cond_expr = if let Some(pre_lowered) = condition {
                        (**pre_lowered).clone()
                    } else {
                        constraint::lower_condition(cond_info, ssa, block.id, transfer.const_values)
                    };
                    if !matches!(cond_expr, constraint::ConditionExpr::Unknown) {
                        if let Some(ref mut env) = true_state.path_env {
                            *env = constraint::refine_env(env, &cond_expr, true);
                            if env.is_unsat() {
                                tracing::debug!(
                                    block = ?block.id,
                                    cond = cond_text,
                                    "constraint: pruned true branch (unsat)"
                                );
                            }
                        }
                        if let Some(ref mut env) = false_state.path_env {
                            *env = constraint::refine_env(env, &cond_expr, false);
                            if env.is_unsat() {
                                tracing::debug!(
                                    block = ?block.id,
                                    cond = cond_text,
                                    "constraint: pruned false branch (unsat)"
                                );
                            }
                        }
                    }
                }

                // Contradiction pruning
                if true_state.has_contradiction() {
                    true_state = SsaTaintState::bot();
                }
                if false_state.has_contradiction() {
                    false_state = SsaTaintState::bot();
                }

                smallvec::smallvec![(*true_blk, true_state), (*false_blk, false_state),]
            } else {
                // Non-If condition or no condition vars — uniform propagation
                smallvec::smallvec![
                    (*true_blk, exit_state.clone()),
                    (*false_blk, exit_state.clone()),
                ]
            }
        }
        Terminator::Goto(_) => {
            // `block.succs` is authoritative. The terminator target records
            // the single logical successor (or the first of a collapsed
            // ≥3-way fanout — see src/ssa/lower.rs `three_successor_collapse`).
            // Propagating only the terminator target would drop flow to the
            // other successors; iterate `succs` instead so every downstream
            // block receives the exit state.
            block
                .succs
                .iter()
                .map(|s| (*s, exit_state.clone()))
                .collect()
        }
        Terminator::Return(_) | Terminator::Unreachable => {
            // `block.succs` is authoritative for analysis flow; the terminator
            // is advisory.  Lowering records finally/cleanup continuation
            // edges on the try-body's succs even when the structured
            // terminator is `Return`/`Unreachable`.  Propagate the exit state
            // across those edges (determinism: iterate in stored order) so
            // downstream analysis sees the flow.  Empty `succs` preserves the
            // true-terminal fast path.
            block
                .succs
                .iter()
                .map(|s| (*s, exit_state.clone()))
                .collect()
        }
    }
}

/// Apply validation and predicate bits for a branch edge.
fn apply_branch_predicates(
    state: &mut SsaTaintState,
    condition_vars: &[String],
    kind: PredicateKind,
    polarity: bool,
    interner: &SymbolInterner,
) {
    // Validation-like predicates: mark condition vars as validated when polarity is true
    if matches!(
        kind,
        PredicateKind::ValidationCall | PredicateKind::AllowlistCheck | PredicateKind::TypeCheck
    ) && polarity
    {
        for var in condition_vars {
            if let Some(sym) = interner.get(var) {
                state.validated_may.insert(sym);
                state.validated_must.insert(sym);
            }
        }
    }

    // ShellMetaValidated: inverted polarity — the FALSE branch (no metachar
    // found) is the validated path; the TRUE branch is the rejection path.
    if kind == PredicateKind::ShellMetaValidated && !polarity {
        for var in condition_vars {
            if let Some(sym) = interner.get(var) {
                state.validated_may.insert(sym);
                state.validated_must.insert(sym);
            }
        }
    }

    // Whitelisted predicate kinds: update PredicateSummary bits
    if let Some(bit_idx) = predicate_kind_bit(kind) {
        for var in condition_vars {
            if let Some(sym) = interner.get(var) {
                let mut summary = state
                    .predicates
                    .binary_search_by_key(&sym, |(id, _)| *id)
                    .ok()
                    .map(|idx| state.predicates[idx].1)
                    .unwrap_or_else(PredicateSummary::empty);
                if polarity {
                    summary.known_true |= 1 << bit_idx;
                } else {
                    summary.known_false |= 1 << bit_idx;
                }
                match state.predicates.binary_search_by_key(&sym, |(id, _)| *id) {
                    Ok(idx) => state.predicates[idx].1 = summary,
                    Err(idx) => state.predicates.insert(idx, (sym, summary)),
                }
            }
        }
    }
}

// ── Context-Sensitive Inline Analysis Functions ───────────────────────

/// Build a compact taint signature from the actual argument taint at a call site.
fn build_arg_taint_sig(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
) -> ArgTaintSig {
    let mut sig = SmallVec::new();

    // Receiver taint at position usize::MAX (sentinel)
    if let Some(rv) = receiver {
        if let Some(taint) = state.get(*rv) {
            sig.push((usize::MAX, taint.caps.bits()));
        }
    }

    // Per-argument-position taint
    for (i, arg_vals) in args.iter().enumerate() {
        let mut caps = Cap::empty();
        for v in arg_vals {
            if let Some(taint) = state.get(*v) {
                caps |= taint.caps;
            }
        }
        if !caps.is_empty() {
            sig.push((i, caps.bits()));
        }
    }

    sig.sort_by_key(|(idx, _)| *idx);
    ArgTaintSig(sig)
}

/// Attempt context-sensitive inline analysis of a callee at a specific call site.
///
/// Returns `Some(InlineResult)` if inline analysis succeeded, `None` if the
/// callee is unavailable, the body is too large, or we're already at depth limit.
///
/// Resolution ordering for the callee body:
///
/// 1. **Intra-file** (`transfer.callee_bodies`): resolve the callee via
///    [`resolve_local_func_key`] against this file's local summaries and
///    look up the body by canonical [`FuncKey`].  This is the original
///    Phase 11 path.
/// 2. **Cross-file** (Phase CF-2): if (1) misses but
///    [`GlobalSummaries::resolve_callee`] resolves the call site to a
///    cross-file [`FuncKey`], look up the body in
///    `transfer.cross_file_bodies`.  Both in-memory and indexed-scan
///    bodies are usable here: the former arrives with `body_graph`
///    already set (pass 1), the latter has it rehydrated from
///    `node_meta` via [`rebuild_body_graph`] at load time (Phase CF-3).
///
/// The cache ([`InlineCache`]) is keyed by `(FuncKey, ArgTaintSig)`.
/// `FuncKey` carries the callee's namespace, so cross-file and intra-file
/// entries never collide even when two files define same-leaf helpers.
fn inline_analyse_callee(
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    transfer: &SsaTaintTransfer,
    cfg: &Cfg,
    caller_ssa: &SsaBody,
    call_inst: &SsaInst,
) -> Option<InlineResult> {
    // Enforce k=1 depth limit
    if transfer.context_depth >= 1 {
        return None;
    }

    let cache_ref = transfer.inline_cache?;

    // Resolve the call site to a canonical FuncKey and the body to inline.
    // Step 1: intra-file (Phase 11).  Step 2: cross-file (Phase CF-2).
    //
    // Without a resolved key we cannot inline safely — bare-name lookup could
    // pick the wrong same-name sibling (e.g. `A::process/1` vs `B::process/1`).
    let normalized = callee_leaf_name(callee);
    let container_raw = callee_container_hint(callee);
    let container_hint = if container_raw.is_empty() {
        None
    } else {
        Some(container_raw)
    };

    let intra_key = transfer.callee_bodies.and_then(|_| {
        resolve_local_func_key(
            transfer.local_summaries,
            transfer.lang,
            transfer.namespace,
            normalized,
            container_hint,
        )
    });
    let intra_body = intra_key
        .as_ref()
        .and_then(|k| transfer.callee_bodies.and_then(|cb| cb.get(k)));

    let (callee_key, callee_body) = if let (Some(k), Some(b)) = (intra_key, intra_body) {
        (k, b)
    } else if let Some(gs) = transfer.global_summaries {
        // Phase CF-2: Cross-file fallback.  Build a structured query mirroring
        // resolve_callee_full (qualifier/receiver_var/caller_container) so that
        // qualified-first policy is preserved.
        let (namespace_qualifier, receiver_var) = split_qualifier(callee);
        let caller_func = caller_ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter().chain(b.body.iter()))
            .filter_map(|inst| {
                cfg.node_weight(inst.cfg_node)
                    .and_then(|info| info.ast.enclosing_func.as_deref())
            })
            .next()
            .unwrap_or("");
        let caller_container_opt = caller_container_for(transfer, caller_func);
        let caller_container: Option<&str> = caller_container_opt.as_deref();
        let receiver_type = receiver_type_prefix(transfer, *receiver);
        let arity_hint = Some(args.len());
        let query = CalleeQuery {
            name: normalized,
            caller_lang: transfer.lang,
            caller_namespace: transfer.namespace,
            caller_container,
            receiver_type,
            namespace_qualifier,
            receiver_var,
            arity: arity_hint,
        };
        match gs.resolve_callee(&query) {
            CalleeResolution::Resolved(key) => {
                let xfile_bodies = transfer.cross_file_bodies?;
                let body = xfile_bodies.get(&key)?;
                // Phase CF-3: indexed-scan bodies deserialized from SQLite
                // arrive with `body_graph: None`, but the load path
                // ([`rebuild_body_graph`] in `load_all_ssa_bodies`)
                // synthesizes a proxy `Cfg` from `node_meta` so the taint
                // engine can index `cfg[inst.cfg_node]` uniformly.  A
                // body that still has neither a real graph nor any
                // rehydrated metadata is structurally unusable — skip it.
                if body.body_graph.is_none() {
                    tracing::debug!(
                        callee = %normalized,
                        "cross-file inline miss: body has no body_graph and no node_meta"
                    );
                    return None;
                }
                tracing::debug!(
                    callee = %normalized,
                    namespace = %key.namespace,
                    "cross-file inline hit: using GlobalSummaries.bodies_by_key"
                );
                (key, body)
            }
            _ => return None,
        }
    } else {
        return None;
    };

    // Skip very large function bodies
    if callee_body.ssa.blocks.len() > MAX_INLINE_BLOCKS {
        tracing::debug!(
            callee = %callee_key.name,
            namespace = %callee_key.namespace,
            blocks = callee_body.ssa.blocks.len(),
            max = MAX_INLINE_BLOCKS,
            "inline miss: body too large (budget-exceeded)"
        );
        return None;
    }

    // Build cache key from actual argument taint
    let sig = build_arg_taint_sig(args, receiver, state);

    // Check cache (keyed by FuncKey + arg signature)
    {
        let cache = cache_ref.borrow();
        if let Some(cached) = cache.get(&(callee_key.clone(), sig.clone())) {
            return Some(cached.clone());
        }
    }

    // Build per-parameter seed from actual argument taint.
    // Map callee's Param var_name → caller's argument taint via BindingKey.
    // TODO(C-2): use BindingKey::with_body_id(var_name, callee_body_id) to scope
    // seeds to the callee's body, preventing shadowed-name collisions.
    let mut param_seed: HashMap<BindingKey, VarTaint> = HashMap::new();

    for block in &callee_body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            // Seed caps for positional params and for the receiver (SelfParam)
            // via separate channels — args[i] ↔ Param{index=i}, receiver ↔ SelfParam.
            let source_values: Option<&SmallVec<[SsaValue; 2]>> = match &inst.op {
                SsaOp::Param { index } => args.get(*index),
                SsaOp::SelfParam => {
                    // receiver is a single optional SsaValue — wrap for uniform iteration.
                    // We match it in a separate branch below since it isn't a slice.
                    None
                }
                _ => continue,
            };
            let Some(var_name) = inst.var_name.as_ref() else {
                continue;
            };
            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

            // Phase CF-2 note: `populate_span` lazily fills
            // `source_span` from the *caller's* CFG before the origin
            // crosses into the callee.  The Param-op branch of
            // `transfer_inst` remaps `node` to the callee's own
            // `cfg_node` and preserves only `source_span`, so without
            // this pre-fill cross-file inline would lose the caller's
            // source line entirely (finding emission in `ast.rs` uses
            // `source_span` first, falls back to indexing the caller's
            // CFG at `node` — which is now the callee's NodeIndex and
            // resolves to a wrong or missing span).  Intra-file inline
            // also benefits: the caller-scoped anchor stays canonical.
            let populate_span = |mut o: TaintOrigin| -> TaintOrigin {
                if o.source_span.is_none() {
                    if let Some(info) = cfg.node_weight(o.node) {
                        o.source_span = Some(info.classification_span());
                    }
                }
                o
            };

            match &inst.op {
                SsaOp::Param { .. } => {
                    if let Some(arg_vals) = source_values {
                        for v in arg_vals {
                            if let Some(taint) = state.get(*v) {
                                combined_caps |= taint.caps;
                                for orig in &taint.origins {
                                    if combined_origins.len() < MAX_ORIGINS
                                        && !combined_origins.iter().any(|o| o.node == orig.node)
                                    {
                                        combined_origins.push(populate_span(*orig));
                                    }
                                }
                            }
                        }
                    }
                }
                SsaOp::SelfParam => {
                    if let Some(rv) = receiver {
                        if let Some(taint) = state.get(*rv) {
                            combined_caps |= taint.caps;
                            for orig in &taint.origins {
                                if combined_origins.len() < MAX_ORIGINS
                                    && !combined_origins.iter().any(|o| o.node == orig.node)
                                {
                                    combined_origins.push(populate_span(*orig));
                                }
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }

            if !combined_caps.is_empty() {
                param_seed.insert(
                    BindingKey::new(var_name.as_str()),
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                        uses_summary: false,
                    },
                );
            }
        }
    }

    // Detect callback arguments: when a call argument refers to a known function
    // name (resolvable to a FuncKey in the local summaries index), record the
    // mapping so the callee's analysis can resolve calls through the parameter.
    //
    // The binding value is a full `FuncKey` rather than a leaf string so the
    // child transfer can look up `callee_bodies` / `ssa_summaries` / local
    // summaries by canonical identity.
    let mut callback_bindings: HashMap<String, FuncKey> = HashMap::new();
    for block in &callee_body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = &inst.op {
                if let Some(param_name) = inst.var_name.as_ref() {
                    if *index < args.len() {
                        for v in &args[*index] {
                            if let Some(arg_var_name) = caller_ssa
                                .value_defs
                                .get(v.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref())
                            {
                                let norm = callee_leaf_name(arg_var_name);
                                let hint_raw = callee_container_hint(arg_var_name);
                                let hint = if hint_raw.is_empty() {
                                    None
                                } else {
                                    Some(hint_raw)
                                };
                                if let Some(target_key) = resolve_local_func_key(
                                    transfer.local_summaries,
                                    transfer.lang,
                                    transfer.namespace,
                                    norm,
                                    hint,
                                ) {
                                    if transfer
                                        .callee_bodies
                                        .is_some_and(|cb| cb.contains_key(&target_key))
                                    {
                                        callback_bindings.insert(param_name.clone(), target_key);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let seed_ref = if param_seed.is_empty() {
        None
    } else {
        Some(&param_seed)
    };
    let cb_ref = if callback_bindings.is_empty() {
        None
    } else {
        Some(&callback_bindings)
    };
    let child_transfer = SsaTaintTransfer {
        lang: transfer.lang,
        namespace: transfer.namespace,
        interner: transfer.interner,
        local_summaries: transfer.local_summaries,
        global_summaries: transfer.global_summaries,
        interop_edges: transfer.interop_edges,
        global_seed: seed_ref,
        const_values: Some(&callee_body.opt.const_values),
        type_facts: Some(&callee_body.opt.type_facts),
        ssa_summaries: transfer.ssa_summaries,
        extra_labels: transfer.extra_labels,
        base_aliases: Some(&callee_body.opt.alias_result),
        callee_bodies: None, // no recursion into further inline analysis
        inline_cache: None,
        context_depth: transfer.context_depth + 1,
        callback_bindings: cb_ref,
        points_to: Some(&callee_body.opt.points_to),
        dynamic_pts: None, // no inter-procedural container propagation at k>1
        import_bindings: transfer.import_bindings,
        promisify_aliases: transfer.promisify_aliases,
        module_aliases: None, // callee body has its own const_values; module aliases not propagated
        static_map: None, // static-map seeding is caller-body local, not propagated to inlined callees
        auto_seed_handler_params: transfer.auto_seed_handler_params,
        cross_file_bodies: transfer.cross_file_bodies,
    };

    // Use the callee's own body graph for inline analysis (per-body CFGs
    // have body-local NodeIndex spaces, so the caller's graph is wrong).
    let callee_cfg = callee_body.body_graph.as_ref().unwrap_or(cfg);
    let (_, callee_block_states) =
        run_ssa_taint_full(&callee_body.ssa, callee_cfg, &child_transfer);

    // Extract return taint from return-block exit states
    let empty_induction = HashSet::new();
    let return_taint = extract_inline_return_taint(
        &callee_body.ssa,
        callee_cfg,
        &child_transfer,
        &callee_block_states,
        &empty_induction,
        call_inst.cfg_node,
    );

    let result = InlineResult { return_taint };

    // Cache the result under the canonical FuncKey.
    {
        let mut cache = cache_ref.borrow_mut();
        cache.insert((callee_key, sig), result.clone());
    }

    Some(result)
}

/// Extract the return value taint from an inline-analyzed callee.
///
/// Replays `transfer_block` on converged return-block states and collects
/// taint from all live values at return points. Remaps origin nodes to the
/// call site for cleaner finding paths.
fn extract_inline_return_taint(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    block_states: &[Option<SsaTaintState>],
    induction_vars: &HashSet<SsaValue>,
    call_site_node: NodeIndex,
) -> Option<VarTaint> {
    // Collect all param SSA values to separate from derived values
    let param_values: HashSet<SsaValue> = ssa
        .blocks
        .iter()
        .flat_map(|b| b.phis.iter().chain(b.body.iter()))
        .filter(|i| matches!(i.op, SsaOp::Param { .. }))
        .map(|i| i.value)
        .collect();

    let mut derived_caps = Cap::empty();
    let mut derived_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut param_caps = Cap::empty();
    let mut param_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

    // Origins crossing back into the caller must reference NodeIndex values
    // valid in the **caller's** body CFG.  Callee-internal origins (e.g. a
    // `Source` op inside the inlined body) carry a `node` from the callee
    // body's NodeIndex space, which is out-of-bounds when finding emission
    // later does `caller_body_cfg[finding.source]`.  Remap them to the
    // caller's call-site node and lazily fill `source_span` from the
    // callee CFG so the byte→line lookup in `build_taint_diag` still has
    // something to render.  Origins that already have `source_span` set
    // (e.g. caller-arg origins forwarded through a Param) are remapped the
    // same way — their `node` was rewritten to a callee-internal Param
    // index by `transfer_inst::SsaOp::Param` before reaching this exit
    // state, so leaving the node untouched would re-introduce the OOB.
    let remap_origin = |o: &TaintOrigin| -> TaintOrigin {
        let mut out = *o;
        if out.source_span.is_none() {
            if let Some(info) = cfg.node_weight(o.node) {
                out.source_span = Some(info.classification_span());
            }
        }
        out.node = call_site_node;
        out
    };

    let push_remapped = |target_origins: &mut SmallVec<[TaintOrigin; 2]>, orig: &TaintOrigin| {
        let new_orig = remap_origin(orig);
        if target_origins.len() < MAX_ORIGINS
            && !target_origins.iter().any(|o| {
                o.node == new_orig.node
                    && o.source_span == new_orig.source_span
                    && o.source_kind == new_orig.source_kind
            })
        {
            target_origins.push(new_orig);
        }
    };

    for (bid, block) in ssa.blocks.iter().enumerate() {
        let ret_val = match &block.terminator {
            Terminator::Return(rv) => rv.as_ref().copied(),
            _ => continue,
        };
        if let Some(entry_state) = &block_states[bid] {
            let exit = transfer_block(
                block,
                cfg,
                ssa,
                transfer,
                entry_state.clone(),
                induction_vars,
                None,
            );

            if let Some(rv) = ret_val {
                // Explicit return value: use ONLY its taint.
                // If rv has no taint entry, this block contributes nothing —
                // the return value is provably untainted on this path.
                if let Some(taint) = exit.get(rv) {
                    let (target_caps, target_origins) = if param_values.contains(&rv) {
                        (&mut param_caps, &mut param_origins)
                    } else {
                        (&mut derived_caps, &mut derived_origins)
                    };
                    *target_caps |= taint.caps;
                    for orig in &taint.origins {
                        push_remapped(target_origins, orig);
                    }
                }
            } else {
                // Return(None): implicit return / empty body.
                // Fall back to collecting all live values.
                for (val, taint) in &exit.values {
                    let (target_caps, target_origins) = if param_values.contains(val) {
                        (&mut param_caps, &mut param_origins)
                    } else {
                        (&mut derived_caps, &mut derived_origins)
                    };
                    *target_caps |= taint.caps;
                    for orig in &taint.origins {
                        push_remapped(target_origins, orig);
                    }
                }
            }
        }
    }

    // Prefer derived caps; fall back to param caps for passthrough functions
    let (final_caps, final_origins) = if !derived_caps.is_empty() {
        (derived_caps, derived_origins)
    } else {
        (param_caps, param_origins)
    };

    if final_caps.is_empty() {
        return None;
    }

    Some(VarTaint {
        caps: final_caps,
        origins: final_origins,
        uses_summary: true, // inline analysis is a form of summary
    })
}

/// Transfer a single SSA instruction.
fn transfer_inst(
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let info = &cfg[inst.cfg_node];

    // Phase 17 hardening: cross-file abstract return fact from callee resolution.
    // Set inside the Call arm, applied after transfer_abstract to override Top.
    let mut callee_return_abstract: Option<crate::abstract_interp::AbstractValue> = None;

    match &inst.op {
        SsaOp::Source => {
            // Apply source labels from NodeInfo
            let mut source_caps = Cap::empty();
            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    source_caps |= *bits;
                }
            }
            if !source_caps.is_empty() {
                let callee = info.call.callee.as_deref().unwrap_or("");
                let source_kind = crate::labels::infer_source_kind(source_caps, callee);
                let origin = TaintOrigin {
                    node: inst.cfg_node,
                    source_kind,
                    source_span: None,
                };
                state.set(
                    inst.value,
                    VarTaint {
                        caps: source_caps,
                        origins: SmallVec::from_elem(origin, 1),
                        uses_summary: false,
                    },
                );
            }
        }

        SsaOp::CatchParam => {
            let origin = TaintOrigin {
                node: inst.cfg_node,
                source_kind: SourceKind::CaughtException,
                source_span: None,
            };
            state.set(
                inst.value,
                VarTaint {
                    caps: Cap::all(),
                    origins: SmallVec::from_elem(origin, 1),
                    uses_summary: false,
                },
            );
        }

        SsaOp::Call {
            callee,
            args,
            receiver,
        } => {
            // Excluded callees (e.g. router.get, app.post) should not propagate
            // taint through their return value — they are framework scaffolding,
            // not data-flow operations.
            if crate::labels::is_excluded(transfer.lang.as_str(), callee.as_bytes()) {
                return;
            }

            // Check for source labels first
            let mut return_bits = Cap::empty();
            let mut return_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    return_bits |= *bits;
                    let callee_str = info.call.callee.as_deref().unwrap_or("");
                    let source_kind = crate::labels::infer_source_kind(*bits, callee_str);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                        source_span: None,
                    };
                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                        return_origins.push(origin);
                    }
                }
            }

            // Output-parameter source tainting (C/C++): for known APIs that
            // write to a buffer argument (fgets, getline, recv, etc.), taint
            // the argument SSA values at the registered output positions.
            if !return_bits.is_empty() {
                if let Some(positions) =
                    crate::labels::output_param_source_positions(transfer.lang.as_str(), callee)
                {
                    for &pos in positions {
                        if let Some(arg_group) = args.get(pos) {
                            for &arg_v in arg_group {
                                state.set(
                                    arg_v,
                                    VarTaint {
                                        caps: return_bits,
                                        origins: return_origins.clone(),
                                        uses_summary: false,
                                    },
                                );
                            }
                        }
                    }
                }
            }

            // Check for sanitizer labels
            let mut sanitizer_bits = Cap::empty();
            for lbl in &info.taint.labels {
                if let DataLabel::Sanitizer(bits) = lbl {
                    sanitizer_bits |= *bits;
                }
            }

            // Resolve callee summary — always attempt, even when explicit
            // labels are present. Labels take precedence for source caps, but
            // summary propagation and sanitizer behaviour must still apply
            // (matches legacy `apply_call()` semantics).
            let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
            let has_source_label = info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)));

            let mut resolved_callee = false;

            // Context-sensitive inline analysis: attempt before summary fallback.
            // Only for intra-file calls when context sensitivity is enabled.
            // Only claims resolution when the inline result produces non-empty
            // return taint — otherwise falls through to summary for cases like
            // receiver-only method calls where summary propagation is needed.
            if transfer.inline_cache.is_some() && transfer.context_depth < 1 {
                if let Some(result) =
                    inline_analyse_callee(callee, args, receiver, state, transfer, cfg, ssa, inst)
                {
                    if let Some(ref ret) = result.return_taint {
                        resolved_callee = true;
                        return_bits |= ret.caps;
                        for orig in &ret.origins {
                            if return_origins.len() < MAX_ORIGINS
                                && !return_origins.iter().any(|o| o.node == orig.node)
                            {
                                return_origins.push(*orig);
                            }
                        }
                    }
                }
            }

            // Inter-procedural container fields: populated from resolve_callee
            // even when inline analysis already handled return taint, since inline
            // analysis doesn't model cross-parameter container stores.
            let mut resolved_container_to_return: Vec<usize> = Vec::new();
            let mut resolved_container_store: Vec<(usize, usize)> = Vec::new();

            // Resolve callee summary (used for both taint propagation and container fields)
            // Pass arity (positional-arg count) so same-name/different-arity
            // overloads are not conflated during cross-file resolution.
            //
            // Use `info.call.arg_uses.len()` rather than `args.len()`: `args`
            // may include an extra "implicit" trailing group built by SSA
            // lowering to surface chained-call taint (see `build_call_args` in
            // `ssa/lower.rs`), which inflates `args.len()` beyond the real
            // positional arity.  The CFG's `arg_uses` is the authoritative
            // positional-arg list.
            let arity_hint = info.call.arg_uses.len();
            // Type-aware resolution: when the SSA receiver value has a
            // known abstract type (HttpClient, URL, …), feed that into
            // the resolver as an authoritative `receiver_type`.  This
            // causes qualified-first resolution to prefer
            // `{Type}::{name}` over any same-leaf collision in the
            // global summary table.
            let callee_summary = resolve_callee_typed(
                transfer,
                callee,
                caller_func,
                info.call.call_ordinal,
                Some(arity_hint),
                *receiver,
            );

            // Capture container fields and return type regardless of whether
            // inline analysis handled the call
            if let Some(ref resolved) = callee_summary {
                resolved_container_to_return = resolved.param_container_to_return.clone();
                resolved_container_store = resolved.param_to_container_store.clone();

                // Phase 17 hardening: capture abstract return for post-transfer injection
                callee_return_abstract = resolved.return_abstract.clone();

                // Phase CF-3: apply per-parameter abstract transfers.
                //
                // For each (param_idx, transfer) in the callee's summary,
                // apply the transfer to the caller's current abstract value
                // of the argument at that position.  Join the per-parameter
                // contributions (disjunctive: any transfer's output is a
                // valid over-approximation of the return), then `meet` with
                // the baseline `return_abstract` (both facts must hold).
                //
                // Runs regardless of whether inline analysis (CF-2) already
                // resolved the call: inline re-analyses taint only; abstract
                // values are not threaded into or out of the callee body on
                // that path, so abstract transfer remains the summary-level
                // channel for propagating intervals / string prefixes across
                // a cross-file call.
                if !resolved.abstract_transfer.is_empty() {
                    let mut synthesised: Option<crate::abstract_interp::AbstractValue> = None;
                    for (idx, transfer) in &resolved.abstract_transfer {
                        if transfer.is_top() {
                            continue;
                        }
                        let arg_abs = if let Some(group) = args.get(*idx) {
                            let mut joined: Option<crate::abstract_interp::AbstractValue> = None;
                            for &v in group {
                                let av = state
                                    .abstract_state
                                    .as_ref()
                                    .map(|a| a.get(v))
                                    .unwrap_or_else(crate::abstract_interp::AbstractValue::top);
                                joined = Some(match joined {
                                    None => av,
                                    Some(prev) => prev.join(&av),
                                });
                            }
                            joined.unwrap_or_else(crate::abstract_interp::AbstractValue::top)
                        } else {
                            crate::abstract_interp::AbstractValue::top()
                        };
                        let applied = transfer.apply(&arg_abs);
                        if applied.is_top() {
                            continue;
                        }
                        synthesised = Some(match synthesised {
                            None => applied,
                            Some(prev) => prev.join(&applied),
                        });
                    }
                    if let Some(synth) = synthesised {
                        callee_return_abstract = match callee_return_abstract.take() {
                            Some(base) => {
                                let m = base.meet(&synth);
                                // Fall back to whichever side is non-bottom
                                // (meet can contradict when the callee's
                                // baseline and the caller-side transfer
                                // describe disjoint facts — rare, but sound
                                // to widen back to the less restrictive).
                                if m.is_bottom() {
                                    Some(synth.join(&base))
                                } else {
                                    Some(m)
                                }
                            }
                            None => Some(synth),
                        };
                    }
                }

                // Cross-file type propagation: if the callee has a known return
                // type (from SSA summary), inject it into the caller's path env
                // so downstream type-qualified resolution can use it.
                if let Some(ref rtype) = resolved.return_type {
                    if let Some(ref mut env) = state.path_env {
                        use crate::constraint::domain::{TypeSet, ValueFact};
                        let mut fact = ValueFact::top();
                        fact.types = TypeSet::singleton(rtype);
                        env.refine(inst.value, &fact);
                    }
                }
            }

            // When find_classifiable_inner_call overrides the callee (e.g.
            // `storeInto(req.query.input, items)` → callee="req.query.input"),
            // the outer_callee preserves the original. Resolve it too for
            // container fields that depend on the wrapping function's summary.
            if resolved_container_store.is_empty() {
                if let Some(ref oc) = info.call.outer_callee {
                    if let Some(ref resolved) = resolve_callee_hinted(
                        transfer,
                        oc,
                        caller_func,
                        info.call.call_ordinal,
                        Some(arity_hint),
                    ) {
                        if resolved_container_to_return.is_empty() {
                            resolved_container_to_return =
                                resolved.param_container_to_return.clone();
                        }
                        resolved_container_store = resolved.param_to_container_store.clone();
                    }
                }
            }

            if !resolved_callee && let Some(resolved) = callee_summary {
                resolved_callee = true;

                // Source caps from summary: only when no explicit Source label
                if !has_source_label && !resolved.source_caps.is_empty() {
                    return_bits |= resolved.source_caps;
                    let source_kind =
                        crate::labels::infer_source_kind(resolved.source_caps, callee);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                        source_span: None,
                    };
                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                        return_origins.push(origin);
                    }
                }

                // Phase CF-4: per-parameter predicate-consistent transforms.
                //
                // When the summary carries `param_return_paths`, apply a
                // per-parameter effective sanitizer narrowed by the caller's
                // current predicate state.  This recovers callee-internal
                // path splits that the coarse `resolved.sanitizer_caps`
                // union would erase (`if validated { return sanitised }
                // else { return raw }` can be resolved to "strip all
                // sanitised bits" when the caller validated the input).
                //
                // Falls back to the aggregate path when:
                //   * `param_return_paths` is empty (single-path callee or
                //     non-SSA resolution);
                //   * the parameter has no entry (no per-path decomposition
                //     was recorded for this param);
                //   * no paths are predicate-compatible (conservative: keep
                //     the aggregate sanitizer bits).
                let mut aggregate_sanitizer_applied = false;

                // Propagation: ALWAYS apply
                if resolved.propagates_taint {
                    // Only use positional filtering when original arg_uses is populated
                    let effective_params = if info.call.arg_uses.is_empty() {
                        &[] as &[usize]
                    } else {
                        &resolved.propagating_params
                    };

                    if !resolved.param_return_paths.is_empty() && !effective_params.is_empty() {
                        // Per-parameter application: each propagating param
                        // contributes taint narrowed by its own per-path
                        // sanitizer.  Origins are still aggregated across
                        // params — they name source anchors, not transforms.
                        let mut any_origin_added = false;
                        for &param_idx in effective_params {
                            let arg_caps_origins =
                                collect_args_taint(args, receiver, state, &[param_idx]);
                            let arg_caps = arg_caps_origins.0;
                            let arg_origins = arg_caps_origins.1;
                            let param_sanitizer =
                                effective_param_sanitizer(&resolved, param_idx, state);
                            return_bits |= arg_caps & !param_sanitizer;
                            for orig in &arg_origins {
                                if return_origins.len() < MAX_ORIGINS
                                    && !return_origins.iter().any(|o| o.node == orig.node)
                                {
                                    return_origins.push(*orig);
                                    any_origin_added = true;
                                }
                            }
                        }
                        aggregate_sanitizer_applied = true;
                        // Sentinel reference to silence unused on cold paths.
                        let _ = any_origin_added;
                    } else {
                        let (prop_caps, prop_origins) =
                            collect_args_taint(args, receiver, state, effective_params);
                        return_bits |= prop_caps;
                        for orig in &prop_origins {
                            if return_origins.len() < MAX_ORIGINS
                                && !return_origins.iter().any(|o| o.node == orig.node)
                            {
                                return_origins.push(*orig);
                            }
                        }
                    }
                }

                // Summary sanitizer: apply the aggregate only when per-param
                // path narrowing above did not already strip per-argument.
                if !aggregate_sanitizer_applied {
                    return_bits &= !resolved.sanitizer_caps;
                }
            }

            // Type-qualified receiver resolution: when normal callee resolution
            // failed and explicit labels are absent, try constructing a type-qualified
            // callee name from the receiver's inferred type (e.g., client.send →
            // HttpClient.send when client is typed as HttpClient).
            if !resolved_callee && info.taint.labels.is_empty() {
                if let Some(rv) = receiver {
                    if transfer.type_facts.is_some() || state.path_env.is_some() {
                        let tq_labels = resolve_type_qualified_labels(
                            callee,
                            *rv,
                            transfer.type_facts,
                            state.path_env.as_ref(),
                            transfer.lang,
                            transfer.extra_labels,
                            Some(ssa),
                        );
                        for lbl in &tq_labels {
                            match lbl {
                                DataLabel::Source(bits) if !has_source_label => {
                                    return_bits |= *bits;
                                    let source_kind =
                                        crate::labels::infer_source_kind(*bits, callee);
                                    let origin = TaintOrigin {
                                        node: inst.cfg_node,
                                        source_kind,
                                        source_span: None,
                                    };
                                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                                        return_origins.push(origin);
                                    }
                                }
                                DataLabel::Sanitizer(bits) => {
                                    sanitizer_bits |= *bits;
                                }
                                DataLabel::Sink(_) => {
                                    // Sink detection is handled separately in
                                    // collect_block_events via resolve_sink_caps_typed
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Apply explicit sanitizer labels.  When a callee summary has
            // already resolved the call, `return_bits` reflects the summary's
            // precise propagation + sanitization; re-unioning `use_caps` here
            // would restore taint the summary already stripped and clobber
            // any cross-procedural sanitization (e.g. an interprocedural
            // path-traversal sanitizer whose caller also carries a label-only
            // sanitizer matching on callee name).  Only collect `use_caps`
            // when no summary applied — that is the original pure-label
            // sanitizer-wrapper code path.
            if !sanitizer_bits.is_empty() {
                if !resolved_callee {
                    let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
                    return_bits |= use_caps;
                    for orig in &use_origins {
                        if return_origins.len() < MAX_ORIGINS
                            && !return_origins.iter().any(|o| o.node == orig.node)
                        {
                            return_origins.push(*orig);
                        }
                    }
                }
                return_bits &= !sanitizer_bits;
            } else if !resolved_callee {
                // Container operation propagation (push/pop/get/set/etc.)
                // Try the primary callee first, then fall back to outer_callee
                // (set when find_classifiable_inner_call overrides the callee,
                // e.g. `parts.add(req.getParameter("input"))` — callee is
                // "req.getParameter" but outer_callee is "parts.add").
                let mut container_handled = try_container_propagation(
                    inst, info, args, receiver, state, transfer, callee, ssa,
                );
                if !container_handled {
                    if let Some(ref oc) = info.call.outer_callee {
                        container_handled = try_container_propagation(
                            inst, info, args, receiver, state, transfer, oc, ssa,
                        );
                    }
                }
                if container_handled {
                    // When this call node is also a Source (e.g. items.push(req.query.item)
                    // where req.query.item triggers a Source label on the call), merge
                    // the source taint into the container receiver too.
                    if !return_bits.is_empty() {
                        let recv_callee = info.call.outer_callee.as_deref().unwrap_or(callee);
                        if let Some(container_val) =
                            find_container_receiver(recv_callee, receiver, args, ssa, transfer.lang)
                        {
                            // Also store into heap objects when available
                            if let Some(pts) = lookup_pts(transfer, container_val) {
                                state.heap.store_set(
                                    &pts,
                                    HeapSlot::Elements,
                                    return_bits,
                                    &return_origins,
                                );
                            }
                            merge_taint_into(state, container_val, return_bits, &return_origins);
                        }
                    }
                    // Fall through to write return_bits to inst.value if non-empty
                    if return_bits.is_empty() {
                        return;
                    }
                } else {
                    // Curl special case: propagate URL taint to handle
                    if try_curl_url_propagation(inst, info, args, state) {
                        return;
                    }

                    // Arg-to-arg propagation for known C/C++ functions (e.g.,
                    // inet_pton). When an input arg is tainted, propagate to
                    // all SSA values in the output arg positions.
                    if let Some(prop) =
                        crate::labels::arg_propagation(transfer.lang.as_str(), callee)
                    {
                        let mut input_caps = Cap::empty();
                        let mut input_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                        for &from_pos in prop.from_args {
                            if let Some(arg_group) = args.get(from_pos) {
                                for &v in arg_group {
                                    if let Some(taint) = state.get(v) {
                                        input_caps |= taint.caps;
                                        for orig in &taint.origins {
                                            if input_origins.len() < MAX_ORIGINS
                                                && !input_origins
                                                    .iter()
                                                    .any(|o| o.node == orig.node)
                                            {
                                                input_origins.push(*orig);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if !input_caps.is_empty() {
                            for &to_pos in prop.to_args {
                                if let Some(arg_group) = args.get(to_pos) {
                                    for &arg_v in arg_group {
                                        state.set(
                                            arg_v,
                                            VarTaint {
                                                caps: input_caps,
                                                origins: input_origins.clone(),
                                                uses_summary: false,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // No labels and no summary — default propagation (gen/kill)
                    let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
                    if return_bits.is_empty() {
                        return_bits = use_caps;
                        return_origins = use_origins;
                    }
                }
            }

            // Alias-aware sanitization: propagate through must-aliased field paths
            if !sanitizer_bits.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_sanitization_to_aliases(
                            inst,
                            state,
                            sanitizer_bits,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            // Inter-procedural container identity propagation:
            // If callee returns the same container it received, propagate
            // the caller's points-to set for that argument to the call result.
            // Uses precise positional matching: param indices correspond to
            // call-site argument positions (ensured by lower_to_ssa_with_params).
            if !resolved_container_to_return.is_empty() {
                if let Some(dyn_ref) = transfer.dynamic_pts {
                    let mut container_pts_list: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                    for &param_idx in &resolved_container_to_return {
                        if let Some(arg_group) = args.get(param_idx) {
                            for &arg_v in arg_group {
                                if let Some(pts) = lookup_pts(transfer, arg_v) {
                                    container_pts_list.push(pts);
                                }
                            }
                        }
                    }
                    if !container_pts_list.is_empty() {
                        let mut dyn_pts = dyn_ref.borrow_mut();
                        for pts in &container_pts_list {
                            match dyn_pts.get(&inst.value) {
                                Some(existing) => {
                                    let merged = existing.union(pts);
                                    dyn_pts.insert(inst.value, merged);
                                }
                                None => {
                                    dyn_pts.insert(inst.value, pts.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Inter-procedural container store propagation:
            // If callee stores src_param taint into container_param's container,
            // use precise positional matching: param indices correspond to
            // call-site argument positions (ensured by lower_to_ssa_with_params).
            if !resolved_container_store.is_empty() {
                for &(src_param, container_param) in &resolved_container_store {
                    // Collect container pts at the specific arg position
                    let mut container_pts: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                    if let Some(arg_group) = args.get(container_param) {
                        for &v in arg_group {
                            if let Some(pts) = lookup_pts(transfer, v) {
                                container_pts.push(pts);
                            }
                        }
                    }
                    if container_pts.is_empty() {
                        continue;
                    }
                    // Collect source taint at the specific arg position
                    let mut src_caps = Cap::empty();
                    let mut src_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                    if let Some(arg_group) = args.get(src_param) {
                        for &v in arg_group {
                            if let Some(taint) = state.get(v) {
                                src_caps |= taint.caps;
                                for orig in &taint.origins {
                                    if src_origins.len() < MAX_ORIGINS
                                        && !src_origins.iter().any(|o| o.node == orig.node)
                                    {
                                        src_origins.push(*orig);
                                    }
                                }
                            }
                        }
                    }
                    // When the primary callee is a Source (e.g. req.query.input
                    // overrode storeInto as the callee), the source taint is
                    // produced as the call's return — not yet in args. Use
                    // return_bits as the source taint for the container store.
                    if src_caps.is_empty() && !return_bits.is_empty() {
                        src_caps = return_bits;
                        src_origins = return_origins.clone();
                    }
                    // Store source taint into container's heap objects
                    if !src_caps.is_empty() {
                        for pts in &container_pts {
                            state
                                .heap
                                .store_set(pts, HeapSlot::Elements, src_caps, &src_origins);
                        }
                    }
                }
            }

            // Alias-aware taint propagation: when a.field becomes tainted and
            // a/b are base aliases, b.field should also be tainted.
            if !return_bits.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_taint_to_aliases(
                            inst,
                            state,
                            return_bits,
                            &return_origins,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            // Outer-callee taint suppression: when find_classifiable_inner_call
            // overrode the callee (e.g. transform(req.query.data) → callee becomes
            // "req.query.data" Source, outer_callee="transform"), the Source label
            // produces return_bits. Check if the wrapper function blocks taint:
            // if its SSA summary shows no propagation, no source_caps, and no
            // container identity return, the return value is independent of its
            // arguments — clear return_bits.
            if !return_bits.is_empty() && has_source_label {
                if let Some(ref oc) = info.call.outer_callee {
                    if let Some(ref oc_sum) = resolve_callee_hinted(
                        transfer,
                        oc,
                        caller_func,
                        info.call.call_ordinal,
                        Some(arity_hint),
                    ) {
                        if !oc_sum.propagates_taint && oc_sum.source_caps.is_empty() {
                            // Outer callee blocks taint: no param→return flow,
                            // no internal sources reaching return.
                            return_bits = Cap::empty();
                            return_origins.clear();
                        }
                    }
                }
            }

            // Write result
            if return_bits.is_empty() {
                state.remove(inst.value);
            } else {
                state.set(
                    inst.value,
                    VarTaint {
                        caps: return_bits,
                        origins: return_origins,
                        uses_summary: resolved_callee,
                    },
                );
            }
        }

        SsaOp::Assign(uses) => {
            // Check for sanitizer labels
            let mut sanitizer_bits = Cap::empty();
            for lbl in &info.taint.labels {
                if let DataLabel::Sanitizer(bits) = lbl {
                    sanitizer_bits |= *bits;
                }
            }

            // Collect taint from operands.  Equality-with-constant comparisons
            // (`x === 'literal'`) produce a boolean result that carries no
            // attacker-controlled data, so skip unioning operand caps into the
            // result.  Source/sanitizer labels on this same node still apply
            // normally below.
            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut inherited_summary = false;

            if !info.is_eq_with_const {
                for &use_val in uses {
                    if let Some(taint) = state.get(use_val) {
                        combined_caps |= taint.caps;
                        inherited_summary |= taint.uses_summary;
                        for orig in &taint.origins {
                            if combined_origins.len() < MAX_ORIGINS
                                && !combined_origins.iter().any(|o| o.node == orig.node)
                            {
                                combined_origins.push(*orig);
                            }
                        }
                    }
                }
            }

            // Apply sanitizer
            combined_caps &= !sanitizer_bits;

            // Alias-aware sanitization: propagate through must-aliased field paths
            if !sanitizer_bits.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_sanitization_to_aliases(
                            inst,
                            state,
                            sanitizer_bits,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            // Check for source labels
            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    combined_caps |= *bits;
                    let callee_str = info.call.callee.as_deref().unwrap_or("");
                    let source_kind = crate::labels::infer_source_kind(*bits, callee_str);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                        source_span: None,
                    };
                    if combined_origins.len() < MAX_ORIGINS
                        && !combined_origins.iter().any(|o| o.node == inst.cfg_node)
                    {
                        combined_origins.push(origin);
                    }
                }
            }

            // Alias-aware taint propagation
            if !combined_caps.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_taint_to_aliases(
                            inst,
                            state,
                            combined_caps,
                            &combined_origins,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            if combined_caps.is_empty() {
                state.remove(inst.value);
            } else {
                state.set(
                    inst.value,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                        uses_summary: inherited_summary,
                    },
                );
            }
        }

        SsaOp::Const(_) | SsaOp::Nop => {
            // No taint — this is the kill mechanism for `x = "literal"` after
            // `x = source()`.  The fresh SsaValue carries zero caps.
        }

        SsaOp::Param { .. } | SsaOp::SelfParam => {
            // Seed from enclosing/parent body scope (multi-body analysis).
            // Look up via BindingKey (name-based, interner-independent).
            //
            // `SelfParam` receives the same treatment as positional `Param`:
            // both represent inbound values whose taint comes from the
            // surrounding scope via the global seed map.
            let mut seeded_from_scope = false;
            if let Some(seed) = &transfer.global_seed {
                if let Some(var_name) = ssa
                    .value_defs
                    .get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    let key = BindingKey::new(var_name);
                    if let Some(taint) = seed_lookup(seed, &key) {
                        // Remap origins to this body's Param cfg_node:
                        // the meaningful anchor where taint enters this body.
                        // Preserve source_span from the original origin for
                        // diagnostics (captured in extract_ssa_exit_state).
                        let remapped_origins: SmallVec<[TaintOrigin; 2]> = taint
                            .origins
                            .iter()
                            .map(|o| TaintOrigin {
                                node: inst.cfg_node,
                                source_kind: o.source_kind,
                                source_span: o.source_span,
                            })
                            .collect();
                        state.set(
                            inst.value,
                            VarTaint {
                                caps: taint.caps,
                                origins: remapped_origins,
                                uses_summary: true,
                            },
                        );
                        seeded_from_scope = true;
                    }
                }
            }

            // Handler-param auto-seed: formal parameters whose names imply
            // user input (e.g. `userInput`, `payload`, `cmd`) start tainted
            // so downstream sinks still fire when a function has no
            // registered caller (typical for controller methods, handler
            // dispatch functions, and stream lambda bodies). Skipped in
            // summary-extraction mode so baseline probes keep their
            // intrinsic-source contract. Gate is set by the caller — e.g.
            // always-on for JS/TS, only AnonymousFunction bodies for Java.
            if transfer.auto_seed_handler_params
                && !seeded_from_scope
                && matches!(&inst.op, SsaOp::Param { .. })
            {
                if let Some(var_name) = ssa
                    .value_defs
                    .get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if crate::labels::is_js_ts_handler_param_name(var_name) {
                        let origin = TaintOrigin {
                            node: inst.cfg_node,
                            source_kind: SourceKind::UserInput,
                            source_span: None,
                        };
                        state.set(
                            inst.value,
                            VarTaint {
                                caps: Cap::all(),
                                origins: SmallVec::from_elem(origin, 1),
                                uses_summary: false,
                            },
                        );
                    }
                }
            }
        }

        SsaOp::Phi(_) => {
            // Phis processed separately above — shouldn't appear in body
        }
    }

    // Phase 15/16: Constraint propagation through instructions
    if let Some(ref mut env) = state.path_env {
        match &inst.op {
            SsaOp::Assign(uses) if uses.len() == 1 => {
                // Copy: propagate facts from source to destination
                let src_fact = env.get(uses[0]);
                if !src_fact.is_top() {
                    env.refine(inst.value, &src_fact);
                    env.assert_equal(inst.value, uses[0]);
                }
                // Phase 16: Cast/assertion type narrowing.
                //
                // If this Assign's CFG node is a cast/type-assertion expression,
                // narrow the destination value's type in PathEnv.
                //
                // Semantics vary by language:
                // - Java casts: runtime-checked — type is reliably narrowed
                // - TypeScript `as`: compile-time assertion only, not runtime proof
                // - Go type assertions: runtime-checked (direct form)
                //
                // In ALL cases: taint is preserved. Narrowing the type does NOT
                // erase taint — a tainted value cast to String is still tainted.
                let node_info = &cfg[inst.cfg_node];
                if let Some(ref cast_type) = node_info.cast_target_type {
                    if let Some(kind) = crate::constraint::solver::parse_type_name(cast_type) {
                        let mut fact = constraint::ValueFact::top();
                        fact.types = constraint::TypeSet::singleton(&kind);
                        fact.null = constraint::Nullability::NonNull;
                        env.refine(inst.value, &fact);
                    }
                }
            }
            SsaOp::Const(Some(text)) => {
                // Constant: seed fact from literal value
                if let Some(cv) = constraint::ConstValue::parse_literal(text) {
                    let mut fact = constraint::ValueFact::top();
                    fact.exact = Some(cv.clone());
                    match &cv {
                        constraint::ConstValue::Int(i) => {
                            fact.lo = Some(*i);
                            fact.hi = Some(*i);
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::Int,
                            );
                            fact.null = constraint::Nullability::NonNull;
                        }
                        constraint::ConstValue::Bool(b) => {
                            fact.bool_state = if *b {
                                constraint::BoolState::True
                            } else {
                                constraint::BoolState::False
                            };
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::Bool,
                            );
                            fact.null = constraint::Nullability::NonNull;
                        }
                        constraint::ConstValue::Null => {
                            fact.null = constraint::Nullability::Null;
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::Null,
                            );
                        }
                        constraint::ConstValue::Str(_) => {
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::String,
                            );
                            fact.null = constraint::Nullability::NonNull;
                        }
                    }
                    env.refine(inst.value, &fact);
                }
            }
            _ => {
                // All other ops: no constraint propagation (conservative)
            }
        }
    }

    // Phase 17: Forward abstract value transfer
    if let Some(ref mut abs) = state.abstract_state {
        transfer_abstract(inst, cfg, abs);
    }

    // Phase 17 hardening: cross-file abstract return injection.
    // Applied after transfer_abstract so summary-provided facts override the
    // default Top that transfer_abstract assigns to unknown callees.
    if let Some(ref abs_val) = callee_return_abstract {
        if let Some(ref mut abs) = state.abstract_state {
            abs.set(inst.value, abs_val.clone());
        }
    }
}

/// Phase 17: Compute abstract values for an SSA instruction.
///
/// Propagates interval and string domain facts forward through constants,
/// copies, binary arithmetic, and concatenation. Conservative (Top) for
/// unknown operations (calls, sources, params).
fn transfer_abstract(inst: &SsaInst, cfg: &Cfg, abs: &mut AbstractState) {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, StringFact};
    use crate::cfg::BinOp;

    let info = &cfg[inst.cfg_node];
    match &inst.op {
        SsaOp::Const(Some(text)) => {
            let trimmed = text.trim();
            // Try integer
            if let Ok(n) = trimmed.parse::<i64>() {
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::exact(n),
                        string: StringFact::top(),
                        bits: BitFact::from_const(n),
                    },
                );
            } else if is_string_const(trimmed) {
                let s = strip_string_quotes(trimmed);
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::top(),
                        string: StringFact::exact(&s),
                        bits: BitFact::top(),
                    },
                );
            }
            // Bool/Null/other: leave as Top
        }

        // Template-literal / string-prefix override: when the RHS is
        // `\`scheme://host/…${x}\`` or `"scheme://host/" + x`, seed the
        // result's StringFact prefix regardless of interpolation arity. Taint
        // still flows through the normal taint lattice; the prefix is only
        // consumed by `is_string_safe_for_ssrf` to suppress SSRF sinks on
        // fixed-host URLs. Placed before the arithmetic/copy arms so it wins
        // over the default Top StringFact.
        SsaOp::Assign(_) if info.string_prefix.is_some() => {
            let prefix = info.string_prefix.as_deref().unwrap();
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact::top(),
                    string: StringFact::from_prefix(prefix),
                    bits: BitFact::top(),
                },
            );
        }

        // Same prefix-from-CFG override for Call instructions whose result is
        // the variable binding (e.g. `url = wrapper('lit' + userPath)`).  The
        // CFG node carries `string_prefix` extracted from the call's first
        // positional argument; without this arm the Call result's StringFact
        // is Top and downstream SSRF suppression (`is_call_abstract_safe`
        // looking at `axios.get(url)`'s own first arg) cannot read the lock.
        // Mirrors the same passthrough-heuristic that the
        // `is_call_abstract_safe` node-attached check at the sink site
        // already relies on.
        SsaOp::Call { .. } if info.string_prefix.is_some() => {
            let prefix = info.string_prefix.as_deref().unwrap();
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact::top(),
                    string: StringFact::from_prefix(prefix),
                    bits: BitFact::top(),
                },
            );
        }

        SsaOp::Assign(uses) if uses.len() == 1 => {
            // Phase 26: single-use Assign with bin_op + literal operand.
            // When a binary expression like `x & 0x07` has one identifier use
            // and one numeric literal, the SSA sees only the identifier (1 use).
            // Use bin_op_const from the CFG node to reconstruct the full binary
            // operation for abstract transfer.
            if let (Some(bin_op), Some(const_val)) = (info.bin_op, info.bin_op_const) {
                let var_abs = abs.get(uses[0]);
                let const_abs = AbstractValue {
                    interval: IntervalFact::exact(const_val),
                    string: StringFact::top(),
                    bits: BitFact::from_const(const_val),
                };
                let result_interval = match bin_op {
                    BinOp::Add => var_abs.interval.add(&const_abs.interval),
                    BinOp::Sub => var_abs.interval.sub(&const_abs.interval),
                    BinOp::Mul => var_abs.interval.mul(&const_abs.interval),
                    BinOp::Div => var_abs.interval.div(&const_abs.interval),
                    BinOp::Mod => var_abs.interval.modulo(&const_abs.interval),
                    BinOp::BitAnd => var_abs.interval.bit_and(&const_abs.interval),
                    BinOp::BitOr => var_abs.interval.bit_or(&const_abs.interval),
                    BinOp::BitXor => var_abs.interval.bit_xor(&const_abs.interval),
                    BinOp::LeftShift => var_abs.interval.left_shift(&const_abs.interval),
                    BinOp::RightShift => var_abs.interval.right_shift(&const_abs.interval),
                    BinOp::Eq
                    | BinOp::NotEq
                    | BinOp::Lt
                    | BinOp::LtEq
                    | BinOp::Gt
                    | BinOp::GtEq => IntervalFact {
                        lo: Some(0),
                        hi: Some(1),
                    },
                };
                let result_bits = match bin_op {
                    BinOp::BitAnd => var_abs.bits.bit_and(&const_abs.bits),
                    BinOp::BitOr => var_abs.bits.bit_or(&const_abs.bits),
                    BinOp::BitXor => var_abs.bits.bit_xor(&const_abs.bits),
                    BinOp::LeftShift => var_abs.bits.left_shift(&const_abs.interval),
                    BinOp::RightShift => var_abs.bits.right_shift(&const_abs.interval),
                    _ => BitFact::top(),
                };
                let val = AbstractValue {
                    interval: result_interval,
                    string: StringFact::top(),
                    bits: result_bits,
                };
                if !val.is_top() {
                    abs.set(inst.value, val);
                }
            } else {
                // Copy: propagate abstract value (including bits)
                let src = abs.get(uses[0]);
                if !src.is_top() {
                    abs.set(inst.value, src);
                }
            }
        }

        SsaOp::Assign(uses) if uses.len() == 2 => {
            let lhs_abs = abs.get(uses[0]);
            let rhs_abs = abs.get(uses[1]);

            if let Some(bin_op) = info.bin_op {
                // Known operator → apply interval transfer
                let result_interval = match bin_op {
                    BinOp::Add => lhs_abs.interval.add(&rhs_abs.interval),
                    BinOp::Sub => lhs_abs.interval.sub(&rhs_abs.interval),
                    BinOp::Mul => lhs_abs.interval.mul(&rhs_abs.interval),
                    BinOp::Div => lhs_abs.interval.div(&rhs_abs.interval),
                    BinOp::Mod => lhs_abs.interval.modulo(&rhs_abs.interval),
                    BinOp::BitAnd => lhs_abs.interval.bit_and(&rhs_abs.interval),
                    BinOp::BitOr => lhs_abs.interval.bit_or(&rhs_abs.interval),
                    BinOp::BitXor => lhs_abs.interval.bit_xor(&rhs_abs.interval),
                    BinOp::LeftShift => lhs_abs.interval.left_shift(&rhs_abs.interval),
                    BinOp::RightShift => lhs_abs.interval.right_shift(&rhs_abs.interval),
                    // Comparisons produce boolean 0/1
                    BinOp::Eq
                    | BinOp::NotEq
                    | BinOp::Lt
                    | BinOp::LtEq
                    | BinOp::Gt
                    | BinOp::GtEq => IntervalFact {
                        lo: Some(0),
                        hi: Some(1),
                    },
                };
                // For Add: also handle string concatenation (+ is overloaded)
                let result_string = if bin_op == BinOp::Add {
                    lhs_abs.string.concat(&rhs_abs.string)
                } else {
                    StringFact::top()
                };
                // Bitwise transfer via BitFact subdomain
                let result_bits = match bin_op {
                    BinOp::BitAnd => lhs_abs.bits.bit_and(&rhs_abs.bits),
                    BinOp::BitOr => lhs_abs.bits.bit_or(&rhs_abs.bits),
                    BinOp::BitXor => lhs_abs.bits.bit_xor(&rhs_abs.bits),
                    BinOp::LeftShift => lhs_abs.bits.left_shift(&rhs_abs.interval),
                    BinOp::RightShift => lhs_abs.bits.right_shift(&rhs_abs.interval),
                    _ => BitFact::top(),
                };
                let val = AbstractValue {
                    interval: result_interval,
                    string: result_string,
                    bits: result_bits,
                };
                if !val.is_top() {
                    abs.set(inst.value, val);
                }
            } else {
                // Unknown operator: conservative for interval and bits,
                // but still propagate string concat (prefix from LHS, suffix from RHS)
                let string_result = lhs_abs.string.concat(&rhs_abs.string);
                if !string_result.is_top() {
                    abs.set(
                        inst.value,
                        AbstractValue {
                            interval: IntervalFact::top(),
                            string: string_result,
                            bits: BitFact::top(),
                        },
                    );
                }
            }
        }

        // Known integer-producing calls get a bounded interval so downstream
        // arithmetic transfer produces useful facts (e.g. parseInt(x) * 10).
        // Unknown calls: implicit Top (don't store).
        SsaOp::Call { callee, .. } if is_int_producing_callee(callee) => {
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact {
                        lo: Some(i32::MIN as i64),
                        hi: Some(i32::MAX as i64),
                    },
                    string: StringFact::top(),
                    bits: BitFact::top(),
                },
            );
        }

        SsaOp::Source | SsaOp::CatchParam | SsaOp::Param { .. } => {
            // Untrusted / unknown: Top (no abstract knowledge)
        }

        _ => {}
    }
}

/// Re-export from type_facts for use in transfer_abstract.
fn is_int_producing_callee(callee: &str) -> bool {
    crate::ssa::type_facts::is_int_producing_callee(callee)
}

/// Check if a constant text is a string literal (quoted).
fn is_string_const(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2)
}

/// Strip surrounding quotes from a string literal.
fn strip_string_quotes(text: &str) -> String {
    if text.len() >= 2
        && ((text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\'')))
    {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

/// Collect events from a block (Phase 2).
fn collect_block_events(
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    mut state: SsaTaintState,
    events: &mut Vec<SsaTaintEvent>,
    induction_vars: &HashSet<SsaValue>,
    pred_states: Option<&PredStates>,
) {
    // Replay phis to get accurate state (mirrors transfer_block phi handling)
    let block_idx = block.id.0 as usize;
    for phi in &block.phis {
        if let SsaOp::Phi(ref operands) = phi.op {
            let is_induction = induction_vars.contains(&phi.value);

            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut all_tainted_validated = true;
            let mut any_tainted = false;

            for &(pred_blk, operand_val) in operands {
                // Skip back-edge operands for induction vars
                if is_induction && pred_blk.0 >= block.id.0 {
                    continue;
                }

                // Use predecessor-specific state when available
                let operand_taint = if let Some(ps) = pred_states {
                    ps.get(&(block_idx, pred_blk.0 as usize))
                        .and_then(|pred_st| pred_st.get(operand_val))
                } else {
                    None
                };
                let operand_taint = operand_taint.or_else(|| state.get(operand_val));

                if let Some(taint) = operand_taint {
                    any_tainted = true;
                    combined_caps |= taint.caps;
                    for orig in &taint.origins {
                        if combined_origins.len() < MAX_ORIGINS
                            && !combined_origins.iter().any(|o| o.node == orig.node)
                        {
                            combined_origins.push(*orig);
                        }
                    }

                    // Path sensitivity: check if this operand is validated in predecessor
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            let var_name = ssa
                                .value_defs
                                .get(operand_val.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref());
                            if let Some(name) = var_name {
                                if let Some(sym) = transfer.interner.get(name) {
                                    if !pred_st.validated_must.contains(sym) {
                                        all_tainted_validated = false;
                                    }
                                } else {
                                    all_tainted_validated = false;
                                }
                            } else {
                                all_tainted_validated = false;
                            }
                        } else {
                            all_tainted_validated = false;
                        }
                    } else {
                        all_tainted_validated = false;
                    }
                }
            }

            if combined_caps.is_empty() {
                state.remove(phi.value);
            } else {
                state.set(
                    phi.value,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                        uses_summary: false,
                    },
                );

                // Path sensitivity: if all tainted predecessors validated, propagate
                if any_tainted && all_tainted_validated {
                    if let Some(name) = ssa
                        .value_defs
                        .get(phi.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    {
                        if let Some(sym) = transfer.interner.get(name) {
                            state.validated_may.insert(sym);
                            state.validated_must.insert(sym);
                        }
                    }
                }
            }
        }
    }

    // Phase 17: Replay abstract value phi join (from predecessor exit states).
    // Mirrors the same logic in transfer_block() — without this, abstract
    // values for phi-defined SSA values would be stale during sink suppression.
    if state.abstract_state.is_some() {
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                use crate::abstract_interp::AbstractValue;
                let is_induction = induction_vars.contains(&phi.value);
                let mut joined = AbstractValue::bottom();
                let mut any_operand = false;

                for &(pred_blk, operand_val) in operands {
                    if is_induction && pred_blk.0 >= block.id.0 {
                        continue;
                    }
                    // Skip infeasible predecessors
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            if pred_st.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                                continue;
                            }
                        }
                    }
                    // Look up operand abstract value from predecessor exit state
                    let pred_abs = pred_states
                        .and_then(|ps| ps.get(&(block_idx, pred_blk.0 as usize)))
                        .and_then(|s| s.abstract_state.as_ref())
                        .map(|a| a.get(operand_val))
                        .unwrap_or_else(AbstractValue::top);
                    joined = joined.join(&pred_abs);
                    any_operand = true;
                }

                if any_operand {
                    if let Some(ref mut abs) = state.abstract_state {
                        abs.set(phi.value, joined);
                    }
                }
            }
        }
    }

    // Process body with sink detection
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);

        // Check for sink
        let info = &cfg[inst.cfg_node];
        if info.all_args_literal {
            continue;
        }

        // Parameterized SQL queries are safe — skip sink detection.
        if info.parameterized_query {
            continue;
        }

        let sink_info = resolve_sink_info(info, transfer);
        let mut sink_caps = sink_info.caps;

        // Type-qualified sink resolution: when normal sink resolution found nothing,
        // try using the receiver's inferred type to construct a qualified callee name.
        if sink_caps.is_empty() {
            if let SsaOp::Call {
                callee,
                receiver: Some(rv),
                ..
            } = &inst.op
            {
                if transfer.type_facts.is_some() || state.path_env.is_some() {
                    let tq_labels = resolve_type_qualified_labels(
                        callee,
                        *rv,
                        transfer.type_facts,
                        state.path_env.as_ref(),
                        transfer.lang,
                        transfer.extra_labels,
                        Some(ssa),
                    );
                    for lbl in &tq_labels {
                        if let DataLabel::Sink(bits) = lbl {
                            sink_caps |= *bits;
                        }
                    }
                }
            }
        }

        // Module alias resolution: when the receiver was assigned from require()
        // of a known module (e.g., `const lib = require("http")`), substitute
        // the module name into the callee for label matching.
        // Example: `lib.request(url)` with lib→"http" tries "http.request".
        if sink_caps.is_empty() {
            if let SsaOp::Call {
                callee,
                receiver: Some(rv),
                ..
            } = &inst.op
            {
                if let Some(aliases) = transfer.module_aliases {
                    if let Some(module_names) = aliases.get(rv) {
                        if let Some(dot_pos) = callee.find('.') {
                            let method = &callee[dot_pos + 1..];
                            let lang_str = transfer.lang.as_str();
                            for module_name in module_names {
                                let qualified = format!("{}.{}", module_name, method);
                                let labels = crate::labels::classify_all(
                                    lang_str,
                                    &qualified,
                                    transfer.extra_labels,
                                );
                                for lbl in &labels {
                                    if let DataLabel::Sink(bits) = lbl {
                                        sink_caps |= *bits;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if sink_caps.is_empty() {
            // Callback pattern: check if callee has source_to_callback and the
            // actual callback argument has a matching param_to_sink.
            if let SsaOp::Call { callee, .. } = &inst.op {
                let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
                // Use arg_uses.len() for arity (see transfer_inst's Call arm).
                if let Some(resolved) = resolve_callee_hinted(
                    transfer,
                    callee,
                    caller_func,
                    info.call.call_ordinal,
                    Some(info.call.arg_uses.len()),
                ) {
                    for &(cb_idx, src_caps) in &resolved.source_to_callback {
                        let cb_name = info.arg_callees.get(cb_idx).and_then(|ac| ac.as_ref());
                        if let Some(cb_callee) = cb_name {
                            if let Some(cb_resolved) =
                                resolve_callee(transfer, cb_callee, caller_func, 0)
                            {
                                let matching_sink_caps = cb_resolved
                                    .param_to_sink
                                    .iter()
                                    .filter(|(_, caps)| !(src_caps & *caps).is_empty())
                                    .fold(Cap::empty(), |acc, (_, c)| acc | *c);
                                if !matching_sink_caps.is_empty() {
                                    let source_kind =
                                        crate::labels::infer_source_kind(src_caps, callee);
                                    let origin = TaintOrigin {
                                        node: inst.cfg_node,
                                        source_kind,
                                        source_span: None,
                                    };
                                    // Phase 2: pick callback-path sink sites.
                                    // The callback callee's `param_to_sink_sites`
                                    // drives attribution when available; cap-only
                                    // fallback yields `primary_sink_site = None`.
                                    let cb_tainted: Vec<(
                                        SsaValue,
                                        Cap,
                                        SmallVec<[TaintOrigin; 2]>,
                                    )> = vec![(
                                        inst.value,
                                        src_caps & matching_sink_caps,
                                        SmallVec::from_elem(origin, 1),
                                    )];
                                    let cb_sites = pick_primary_sink_sites_from_resolved(
                                        matching_sink_caps,
                                        &cb_resolved.param_to_sink_sites,
                                    );
                                    emit_ssa_taint_events(
                                        events,
                                        inst.cfg_node,
                                        cb_tainted,
                                        matching_sink_caps,
                                        false,
                                        None,
                                        true,
                                        cb_sites,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            continue;
        }

        // Phase 16: Receiver type incompatibility check.
        // If the receiver's flow-sensitive type proves it cannot be the kind
        // of object the sink expects (e.g., Int receiver → not an HTTP response
        // sink), strip those sink caps.
        if let Some(ref env) = state.path_env {
            if let SsaOp::Call {
                receiver: Some(rv), ..
            } = &inst.op
            {
                if let Some(kind) = env.get(*rv).types.as_singleton() {
                    sink_caps &= !receiver_incompatible_sink_caps(&kind, sink_caps);
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // Phase 16: Go interface satisfaction check.
        // For Go sinks that require http.ResponseWriter (e.g., fmt.Fprintf),
        // skip if the first argument's type is known to NOT satisfy the interface.
        if transfer.lang == Lang::Go {
            if let Some(ref env) = state.path_env {
                if let SsaOp::Call { args, .. } = &inst.op {
                    if let Some(first_arg_vals) = args.first() {
                        if let Some(&first_val) = first_arg_vals.first() {
                            if let Some(kind) = env.get(first_val).types.as_singleton() {
                                if crate::ssa::type_facts::GoInterfaceTable::definitely_not(
                                    &kind,
                                    "http.ResponseWriter",
                                ) && sink_caps.intersects(Cap::HTML_ESCAPE)
                                {
                                    sink_caps &= !Cap::HTML_ESCAPE;
                                }
                            }
                        }
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // Suppress known non-sink callees (e.g., System.out.println in Java)
        if let SsaOp::Call { callee, .. } = &inst.op {
            sink_caps = suppress_known_safe_callees(sink_caps, callee, transfer.lang);
            if sink_caps.is_empty() {
                continue;
            }
        }

        // Interprocedural sanitizer: subtract sanitizer caps from inner arg callees.
        // If an argument is wrapped in a call to a known sanitizer (e.g.
        // `os.system(sanitize(cmd))`), the sanitizer's caps reduce the effective
        // sink sensitivity so tainted data stripped by the inner call isn't flagged.
        for maybe_callee in &info.arg_callees {
            if let Some(inner_callee) = maybe_callee {
                let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
                if let Some(resolved) = resolve_callee(transfer, inner_callee, caller_func, 0) {
                    sink_caps &= !resolved.sanitizer_caps;
                } else {
                    // Fallback: check label classification (built-in + custom rules).
                    // This handles sanitizers that have no function summary (e.g.
                    // external libraries like `escapeHtml`, `DOMPurify.sanitize`).
                    let lang_str = transfer.lang.as_str();
                    let labels =
                        crate::labels::classify_all(lang_str, inner_callee, transfer.extra_labels);
                    for lbl in &labels {
                        if let DataLabel::Sanitizer(bits) = lbl {
                            sink_caps &= !*bits;
                        }
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // SSA-level literal suppression: if all argument SSA values are known
        // constants (from const propagation), skip sink detection.
        // Only applies to non-Call instructions (Assign to a sink) — for Call
        // instructions, the CFG-level `all_args_literal` check already handles
        // chained calls more accurately.
        if !matches!(inst.op, SsaOp::Call { .. }) {
            if let Some(const_values) = transfer.const_values {
                if all_args_const(inst, const_values) {
                    continue;
                }
            }
        }

        // Type-aware sink filtering: suppress SQL injection for int-typed values.
        // Only applies to non-Call instructions to avoid interfering with
        // call-chain taint detection.
        if !matches!(inst.op, SsaOp::Call { .. }) {
            if let Some(type_facts) = transfer.type_facts {
                if is_type_safe_for_sink(inst, sink_caps, type_facts) {
                    continue;
                }
            }
        }

        // Phase 16: Path-sensitive type-safe sink filtering.
        // Uses flow-sensitive type constraints from PathEnv (branch narrowing,
        // casts) to suppress sinks when all argument values are proven to have
        // non-injectable types (Int, Bool).
        if !matches!(inst.op, SsaOp::Call { .. }) {
            if let Some(ref env) = state.path_env {
                if is_path_type_safe_for_sink(inst, sink_caps, env) {
                    continue;
                }
            }
        }

        // Phase 17: Abstract-domain-aware sink suppression.
        // Includes SSRF prefix locking and dual-gate (type + interval) for SQL/FILE_IO.
        if let Some(ref abs) = state.abstract_state {
            if is_abstract_safe_for_sink(
                inst,
                sink_caps,
                abs,
                transfer.type_facts,
                transfer.static_map,
                &state,
                ssa,
                cfg,
            ) {
                continue;
            }
        }
        // Phase 17: Call-site abstract suppression.
        if let SsaOp::Call { ref args, .. } = inst.op {
            if let Some(ref abs) = state.abstract_state {
                if is_call_abstract_safe(
                    inst,
                    args,
                    sink_caps,
                    abs,
                    transfer.type_facts,
                    transfer.static_map,
                    &state,
                    ssa,
                    cfg,
                ) {
                    continue;
                }
            }
        }

        // Collect tainted SSA values that flow into this sink
        let tainted = collect_tainted_sink_values(
            inst,
            info,
            &state,
            sink_caps,
            ssa,
            transfer,
            &sink_info.param_to_sink,
        );
        if !tainted.is_empty() {
            // Compute all_validated: check if all tainted vars are validated
            let all_validated = tainted.iter().all(|(val, _, _)| {
                let var_name = ssa
                    .value_defs
                    .get(val.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref());
                if let Some(name) = var_name {
                    if let Some(sym) = transfer.interner.get(name) {
                        return state.validated_may.contains(sym);
                    }
                }
                false
            });
            let guard_kind = if all_validated {
                Some(PredicateKind::ValidationCall)
            } else {
                None
            };
            // Check if any tainted value's taint chain used summary resolution
            let any_uses_summary = tainted
                .iter()
                .any(|(val, _, _)| state.get(*val).is_some_and(|t| t.uses_summary));

            // Phase 2: pick primary sink sites (if any) from the resolved
            // callee summary.  Multi-site cases emit one event per matching
            // [`SinkSite`] so each downstream Finding carries one attribution.
            let primary_sites =
                pick_primary_sink_sites(inst, &tainted, sink_caps, &sink_info.param_to_sink_sites);
            emit_ssa_taint_events(
                events,
                inst.cfg_node,
                tainted,
                sink_caps,
                all_validated,
                guard_kind,
                any_uses_summary,
                primary_sites,
            );
        }
    }
}

// ── Primary sink-site attribution (Phase 2) ─────────────────────────────

/// Pick primary [`SinkSite`]s for a summary-based sink event in the main
/// sink-detection path.
///
/// Filters `param_to_sink_sites` to entries whose:
/// 1. `param_idx` appears in the call's positional `args` and contains one
///    of the `tainted` SSA values (proves this site's parameter actually
///    carried the tainted flow), AND
/// 2. [`SinkSite`] carries resolved coordinates (`line != 0` — cap-only
///    sites are ignored), AND
/// 3. [`SinkSite::cap`] intersects `sink_caps` (the propagated cap mask).
///
/// Returns the deduped list of matching sites (`dedup_key` identity).
/// Empty ⇒ no primary attribution — caller emits a single event with
/// `primary_sink_site = None`.
fn pick_primary_sink_sites(
    inst: &SsaInst,
    tainted: &[(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)],
    sink_caps: Cap,
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
) -> Vec<SinkSite> {
    if param_to_sink_sites.is_empty() || tainted.is_empty() {
        return Vec::new();
    }
    let SsaOp::Call { ref args, .. } = inst.op else {
        return Vec::new();
    };
    let mut out: Vec<SinkSite> = Vec::new();
    let mut seen: HashSet<(String, u32, u32, u16)> = HashSet::new();
    for (param_idx, sites) in param_to_sink_sites {
        let Some(arg_vals) = args.get(*param_idx) else {
            continue;
        };
        let carries_tainted = arg_vals
            .iter()
            .any(|v| tainted.iter().any(|(tv, _, _)| tv == v));
        if !carries_tainted {
            continue;
        }
        for site in sites {
            if site.line == 0 {
                continue;
            }
            if (site.cap & sink_caps).is_empty() {
                continue;
            }
            let key = (site.file_rel.clone(), site.line, site.col, site.cap.bits());
            if seen.insert(key) {
                out.push(site.clone());
            }
        }
    }
    out
}

/// Pick primary [`SinkSite`]s for the callback-pattern path, where the
/// tainted-arg positional mapping is not directly available (the callback
/// callee is resolved separately from the outer call's `args`).  Matches
/// solely on cap intersection and coordinate resolution.
fn pick_primary_sink_sites_from_resolved(
    sink_caps: Cap,
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
) -> Vec<SinkSite> {
    if param_to_sink_sites.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<SinkSite> = Vec::new();
    let mut seen: HashSet<(String, u32, u32, u16)> = HashSet::new();
    for (_, sites) in param_to_sink_sites {
        for site in sites {
            if site.line == 0 {
                continue;
            }
            if (site.cap & sink_caps).is_empty() {
                continue;
            }
            let key = (site.file_rel.clone(), site.line, site.col, site.cap.bits());
            if seen.insert(key) {
                out.push(site.clone());
            }
        }
    }
    out
}

/// Emit one or more [`SsaTaintEvent`]s for a sink hit.
///
/// Multi-primary collapse: when `primary_sites` contains more than one
/// entry, one event is emitted per site so downstream findings each carry
/// a single attribution.  When `primary_sites` is empty, a single event
/// is emitted with `primary_sink_site = None` (intra-procedural sinks,
/// cap-only callee summaries, or label-based sinks).
///
/// # Invariants enforced by debug_assert!
///
/// Every [`SinkSite`] in `primary_sites` must have been filtered at the
/// pick-site to satisfy:
/// * `site.line != 0` — cap-only sites carry no primary attribution and
///   must not reach the event stream.
/// * `(site.cap & sink_caps).is_empty() == false` — the site's cap
///   intersects the propagated cap mask (it's the dangerous-bit
///   justification for the finding).
///
/// Note: `uses_summary` intentionally does not gate `primary_sites` here.
/// The taint-chain `uses_summary` flag tracks whether a callee summary
/// propagated taint along the source→sink chain, whereas a primary
/// [`SinkSite`] only requires that the *sink* itself was resolved via a
/// callee summary — an intra-file source can still reach a cross-file
/// sink, producing `uses_summary == false` alongside a populated primary.
fn emit_ssa_taint_events(
    events: &mut Vec<SsaTaintEvent>,
    sink_node: NodeIndex,
    tainted_values: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    sink_caps: Cap,
    all_validated: bool,
    guard_kind: Option<PredicateKind>,
    uses_summary: bool,
    primary_sites: Vec<SinkSite>,
) {
    // Data-integrity invariant: every surviving primary site carries
    // resolved coordinates and a cap that intersects `sink_caps`.  This is
    // the contract the pick functions enforce; the assertion defends
    // against a future caller that builds `primary_sites` by hand.
    debug_assert!(
        primary_sites
            .iter()
            .all(|s| s.line != 0 && !(s.cap & sink_caps).is_empty()),
        "primary_sites must all carry resolved coordinates and cap ∩ sink_caps ≠ ∅",
    );

    if primary_sites.is_empty() {
        events.push(SsaTaintEvent {
            sink_node,
            tainted_values,
            sink_caps,
            all_validated,
            guard_kind,
            uses_summary,
            primary_sink_site: None,
        });
        return;
    }

    for site in primary_sites {
        events.push(SsaTaintEvent {
            sink_node,
            tainted_values: tainted_values.clone(),
            sink_caps,
            all_validated,
            guard_kind,
            uses_summary,
            primary_sink_site: Some(site),
        });
    }
}

/// Collect taint from call arguments.
///
/// `args` contains **positional arguments only** — the receiver is a separate
/// channel and is passed via `receiver`.  `propagating_params` indexes directly
/// into `args` using callee positional-parameter indices (no receiver offset).
///
/// When `propagating_params` is empty, taint is collected from the receiver
/// (if any) and from all positional args.
fn collect_args_taint(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    propagating_params: &[usize],
) -> (Cap, SmallVec<[TaintOrigin; 2]>) {
    let mut combined_caps = Cap::empty();
    let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

    if propagating_params.is_empty() {
        // Collect from all args + receiver
        if let Some(rv) = receiver {
            if let Some(taint) = state.get(*rv) {
                combined_caps |= taint.caps;
                for orig in &taint.origins {
                    if combined_origins.len() < MAX_ORIGINS
                        && !combined_origins.iter().any(|o| o.node == orig.node)
                    {
                        combined_origins.push(*orig);
                    }
                }
            }
        }
        for arg_vals in args {
            for &v in arg_vals {
                if let Some(taint) = state.get(v) {
                    combined_caps |= taint.caps;
                    for orig in &taint.origins {
                        if combined_origins.len() < MAX_ORIGINS
                            && !combined_origins.iter().any(|o| o.node == orig.node)
                        {
                            combined_origins.push(*orig);
                        }
                    }
                }
            }
        }
    } else {
        // Collect only from propagating param positions.  Positional only —
        // receiver-to-return propagation is handled by `receiver_to_return` on
        // the summary, not by this path.
        for &param_idx in propagating_params {
            if let Some(arg_vals) = args.get(param_idx) {
                for &v in arg_vals {
                    if let Some(taint) = state.get(v) {
                        combined_caps |= taint.caps;
                        for orig in &taint.origins {
                            if combined_origins.len() < MAX_ORIGINS
                                && !combined_origins.iter().any(|o| o.node == orig.node)
                            {
                                combined_origins.push(*orig);
                            }
                        }
                    }
                }
            }
        }
    }

    (combined_caps, combined_origins)
}

/// Scoped libcurl special case: when `curl_easy_setopt(handle, CURLOPT_URL, value)`
/// is called and `value` is tainted, propagate that taint to `handle`.
///
/// Mirrors `TaintTransfer::try_curl_url_propagation` from `transfer.rs`.
fn try_curl_url_propagation(
    inst: &SsaInst,
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    state: &mut SsaTaintState,
) -> bool {
    if info.taint.defines.is_some() {
        return false;
    }
    let callee = match info.call.callee.as_deref() {
        Some(c) if c.ends_with("curl_easy_setopt") => c,
        _ => return false,
    };
    if !info.taint.uses.iter().any(|u| u == "CURLOPT_URL") {
        return false;
    }
    // Identify handle and URL SSA values from args.
    // Layout: args[0]=handle, args[1]=CURLOPT_URL, args[2]=url_value
    // But the uses list determines which are which. We need handle = first use
    // that isn't the callee or CURLOPT_URL.
    // In SSA form, the args vec gives us positional access.
    // Handle is first arg, URL value is last arg (skip CURLOPT_URL constant).
    let handle_val = args.first().and_then(|a| a.first().copied());
    let handle_val = match handle_val {
        Some(v) => v,
        None => return false,
    };

    // Collect taint from all args except the handle (args[0])
    let mut url_caps = Cap::empty();
    let mut url_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    for arg_vals in args.iter().skip(1) {
        for &v in arg_vals {
            if let Some(taint) = state.get(v) {
                url_caps |= taint.caps;
                for orig in &taint.origins {
                    if url_origins.len() < MAX_ORIGINS
                        && !url_origins.iter().any(|o| o.node == orig.node)
                    {
                        url_origins.push(*orig);
                    }
                }
            }
        }
    }
    // Also check info.taint.uses for identifiers that aren't callee, handle, or CURLOPT_URL
    // in case arg_uses was empty and SSA lowering put all uses into a single group
    if url_caps.is_empty() {
        // Fallback: look at all used SSA values except handle
        let used = inst_use_values(inst);
        for v in used {
            if v == handle_val {
                continue;
            }
            if let Some(taint) = state.get(v) {
                url_caps |= taint.caps;
                for orig in &taint.origins {
                    if url_origins.len() < MAX_ORIGINS
                        && !url_origins.iter().any(|o| o.node == orig.node)
                    {
                        url_origins.push(*orig);
                    }
                }
            }
        }
    }
    if url_caps.is_empty() {
        return false;
    }
    // Merge URL taint into handle (monotone: caps OR, origins union)
    match state.get(handle_val) {
        Some(existing) => {
            let mut merged = existing.clone();
            merged.caps |= url_caps;
            for orig in &url_origins {
                if merged.origins.len() < MAX_ORIGINS
                    && !merged.origins.iter().any(|o| o.node == orig.node)
                {
                    merged.origins.push(*orig);
                }
            }
            state.set(handle_val, merged);
        }
        None => {
            state.set(
                handle_val,
                VarTaint {
                    caps: url_caps,
                    origins: url_origins,
                    uses_summary: false,
                },
            );
        }
    }

    // Also write the inst's own value as non-tainted (no defines on this node)
    let _ = callee;
    true
}

/// Resolve a container index SSA operand to a `HeapSlot`.
///
/// Uses the current function's `const_values` (from `SsaTaintTransfer`) to
/// determine whether the index is a provably non-negative integer constant
/// within `MAX_TRACKED_INDICES`.
///
/// - Intraprocedural: guaranteed — each function's own const propagation
///   results are used.
/// - Inline callee analysis (k=1): guaranteed — `inline_analyse_callee()`
///   sets `const_values: Some(&callee_body.opt.const_values)` on the child
///   transfer, so callee-local constants are resolved.
/// - Unknown / non-integer / out-of-bounds: falls back to `HeapSlot::Elements`.
fn resolve_container_index(index_val: SsaValue, transfer: &SsaTaintTransfer) -> HeapSlot {
    use crate::ssa::heap::MAX_TRACKED_INDICES;

    if let Some(cv) = transfer.const_values {
        if let Some(crate::ssa::const_prop::ConstLattice::Int(n)) = cv.get(&index_val) {
            if *n >= 0 && (*n as u64) < MAX_TRACKED_INDICES as u64 {
                return HeapSlot::Index(*n as u64);
            }
        }
    }
    HeapSlot::Elements
}

/// Resolve the `HeapSlot` for a container operation given its `index_arg`.
///
/// When `index_arg` is `Some(idx_pos)`, applies `arg_offset` and resolves
/// the SSA value from `args`.  Otherwise returns `HeapSlot::Elements`.
fn resolve_op_slot(
    index_arg: Option<usize>,
    arg_offset: usize,
    args: &[SmallVec<[SsaValue; 2]>],
    transfer: &SsaTaintTransfer,
) -> HeapSlot {
    if let Some(idx_pos) = index_arg {
        let effective = idx_pos + arg_offset;
        if let Some(arg_vals) = args.get(effective) {
            if let Some(&v) = arg_vals.first() {
                return resolve_container_index(v, transfer);
            }
        }
    }
    HeapSlot::Elements
}

/// Handle container operations: propagate taint between receiver and arguments.
///
/// **Store** operations (push, append, set, add, insert, etc.):
///   Merge value-argument taint into receiver SSA value.
///
/// **Load** operations (pop, get, join, shift, values, etc.):
///   Propagate receiver taint to the instruction's result value.
///
/// Returns `true` if the operation was handled and the caller should skip
/// default propagation.
fn try_container_propagation(
    inst: &SsaInst,
    _info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
    callee: &str,
    ssa: &SsaBody,
) -> bool {
    let lang = transfer.lang;
    use crate::ssa::pointsto::{ContainerOp, classify_container_op};

    let op = match classify_container_op(callee, lang) {
        Some(op) => op,
        None => return false,
    };

    // Resolve the container SSA value.
    // Languages with `Kind::CallMethod` (Java, Ruby, PHP, Rust, etc.) set
    // `receiver` explicitly. For languages like JS/TS where method calls are
    // `Kind::CallFn`, the receiver is embedded in the args. We find it by
    // looking for an SSA value whose var_name matches the receiver portion
    // of the dotted callee (e.g. "items" from "items.push").
    let resolve_container = |recv: &Option<SsaValue>| -> Option<SsaValue> {
        if let Some(v) = *recv {
            return Some(v);
        }
        // Go append: no receiver, arg 0 is the slice
        if lang == Lang::Go {
            return args.first().and_then(|a| a.first().copied());
        }
        // For dotted callees like "items.push", find the SSA value for "items"
        let dot_pos = callee.rfind('.')?;
        let receiver_name = &callee[..dot_pos];
        // Search all arg groups for an SSA value with matching var_name
        for arg_group in args {
            for &v in arg_group {
                if let Some(def) = ssa.value_defs.get(v.0 as usize) {
                    if def.var_name.as_deref() == Some(receiver_name) {
                        return Some(v);
                    }
                }
            }
        }
        None
    };

    match op {
        ContainerOp::Store {
            value_args,
            index_arg,
        } => {
            let container_val = match resolve_container(receiver) {
                Some(v) => v,
                None => return false,
            };

            // For Go `append`, args[0] is the slice itself and value args
            // follow at index 1.  For method-style container ops the receiver
            // is a separate channel on `SsaOp::Call.receiver`, so `args`
            // contains positional arguments only.
            let arg_offset = if lang == Lang::Go && receiver.is_none() {
                1usize
            } else {
                0
            };

            // Resolve index argument to HeapSlot (Index(n) or Elements).
            let slot = resolve_op_slot(index_arg, arg_offset, args, transfer);

            // Collect taint from value argument(s)
            let mut val_caps = Cap::empty();
            let mut val_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            for &arg_idx in &value_args {
                let effective_idx = arg_idx + arg_offset;
                if let Some(arg_vals) = args.get(effective_idx) {
                    for &v in arg_vals {
                        if let Some(taint) = state.get(v) {
                            val_caps |= taint.caps;
                            for orig in &taint.origins {
                                if val_origins.len() < MAX_ORIGINS
                                    && !val_origins.iter().any(|o| o.node == orig.node)
                                {
                                    val_origins.push(*orig);
                                }
                            }
                        }
                    }
                }
            }

            if val_caps.is_empty() {
                return true; // Container op handled, but no taint to propagate
            }

            // When points-to info available, store through heap objects
            if let Some(pts) = lookup_pts(transfer, container_val) {
                state.heap.store_set(&pts, slot, val_caps, &val_origins);
                // For Go append, result also points to same heap objects
                if lang == Lang::Go && receiver.is_none() {
                    if let Some(ht) = state.heap.load_set(&pts, HeapSlot::Elements) {
                        state.set(
                            inst.value,
                            VarTaint {
                                caps: ht.caps,
                                origins: ht.origins,
                                uses_summary: false,
                            },
                        );
                    }
                }
                return true;
            }
            // Fallback: direct SSA value taint (no pts info for this container)
            merge_taint_into(state, container_val, val_caps, &val_origins);

            // For Go append, the result is the new slice — propagate merged taint
            if lang == Lang::Go && receiver.is_none() {
                if let Some(merged) = state.get(container_val) {
                    state.set(inst.value, merged.clone());
                }
            }

            true
        }
        ContainerOp::Load { index_arg } => {
            let container_val = match resolve_container(receiver) {
                Some(v) => v,
                None => return false,
            };

            // Resolve index argument to HeapSlot.
            // For Go container ops, args[0] is the container itself (value args
            // start at 1).  For method-style calls the receiver is a separate
            // channel, so `args` holds positional arguments from index 0.
            let arg_offset = if lang == Lang::Go && receiver.is_none() {
                1usize
            } else {
                0
            };
            let slot = resolve_op_slot(index_arg, arg_offset, args, transfer);

            // When points-to info available, load from heap objects
            if let Some(pts) = lookup_pts(transfer, container_val) {
                if let Some(ht) = state.heap.load_set(&pts, slot) {
                    state.set(
                        inst.value,
                        VarTaint {
                            caps: ht.caps,
                            origins: ht.origins,
                            uses_summary: false,
                        },
                    );
                }
                return true;
            }
            // Fallback: direct SSA value taint
            if let Some(taint) = state.get(container_val) {
                state.set(inst.value, taint.clone());
            }
            true
        }
    }
}

/// Find the container receiver SSA value for a container operation.
/// Reuses the same logic as `try_container_propagation`'s resolve_container.
fn find_container_receiver(
    callee: &str,
    receiver: &Option<SsaValue>,
    args: &[SmallVec<[SsaValue; 2]>],
    ssa: &SsaBody,
    lang: Lang,
) -> Option<SsaValue> {
    if let Some(v) = *receiver {
        return Some(v);
    }
    if lang == Lang::Go {
        return args.first().and_then(|a| a.first().copied());
    }
    let dot_pos = callee.rfind('.')?;
    let receiver_name = &callee[..dot_pos];
    for arg_group in args {
        for &v in arg_group {
            if let Some(def) = ssa.value_defs.get(v.0 as usize) {
                if def.var_name.as_deref() == Some(receiver_name) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Look up points-to set for an SSA value, checking both the static
/// pre-pass result and the dynamic inter-procedural set.
fn lookup_pts(transfer: &SsaTaintTransfer, v: SsaValue) -> Option<PointsToSet> {
    if let Some(pts_result) = transfer.points_to {
        if let Some(pts) = pts_result.get(v) {
            return Some(pts.clone());
        }
    }
    if let Some(dyn_ref) = transfer.dynamic_pts {
        if let Some(pts) = dyn_ref.borrow().get(&v) {
            return Some(pts.clone());
        }
    }
    None
}

/// Merge taint caps and origins into an existing SSA value's taint (monotone).
fn merge_taint_into(
    state: &mut SsaTaintState,
    target: SsaValue,
    caps: Cap,
    origins: &SmallVec<[TaintOrigin; 2]>,
) {
    match state.get(target) {
        Some(existing) => {
            let mut merged = existing.clone();
            merged.caps |= caps;
            for orig in origins {
                if merged.origins.len() < MAX_ORIGINS
                    && !merged.origins.iter().any(|o| o.node == orig.node)
                {
                    merged.origins.push(*orig);
                }
            }
            state.set(target, merged);
        }
        None => {
            state.set(
                target,
                VarTaint {
                    caps,
                    origins: origins.clone(),
                    uses_summary: false,
                },
            );
        }
    }
}

/// Resolve sink caps from labels or callee summary.
/// Resolved sink information: aggregate caps plus optional per-parameter detail.
struct SinkInfo {
    caps: Cap,
    /// When non-empty, only these caller argument positions flow to sinks.
    /// Each entry is (param_index, per_param_sink_caps).
    /// Empty = check all arguments (label-based sinks, or no per-param info).
    param_to_sink: Vec<(usize, Cap)>,
    /// Per-parameter [`SinkSite`] records carried from the callee summary,
    /// mirroring `param_to_sink` by parameter index.  Empty for label-based
    /// sinks and for cap-only summaries that do not retain source
    /// coordinates.  Phase 2 uses this to attribute findings to the
    /// dangerous callee-internal instruction.
    param_to_sink_sites: Vec<(usize, SmallVec<[SinkSite; 1]>)>,
}

fn resolve_sink_info(info: &NodeInfo, transfer: &SsaTaintTransfer) -> SinkInfo {
    let label_sink_caps = info.taint.labels.iter().fold(Cap::empty(), |acc, lbl| {
        if let DataLabel::Sink(caps) = lbl {
            acc | *caps
        } else {
            acc
        }
    });
    if !label_sink_caps.is_empty() {
        return SinkInfo {
            caps: label_sink_caps,
            param_to_sink: vec![],
            param_to_sink_sites: vec![],
        };
    }

    let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
    // The sink-label path needs an arity hint so we do not match a
    // same-name/different-arity overload in another namespace.
    // `arg_uses.len()` is the positional-argument count — the receiver is a
    // separate channel on `info.call.receiver`, not prepended to `arg_uses`.
    let arity_hint = if info.call.arg_uses.is_empty() {
        None
    } else {
        Some(info.call.arg_uses.len())
    };
    info.call
        .callee
        .as_ref()
        .and_then(|c| {
            resolve_callee_hinted(transfer, c, caller_func, info.call.call_ordinal, arity_hint)
        })
        .filter(|r| !r.sink_caps.is_empty())
        .map(|r| SinkInfo {
            caps: r.sink_caps,
            param_to_sink: r.param_to_sink,
            param_to_sink_sites: r.param_to_sink_sites,
        })
        .unwrap_or(SinkInfo {
            caps: Cap::empty(),
            param_to_sink: vec![],
            param_to_sink_sites: vec![],
        })
}

/// Collect tainted SSA values at a sink instruction.
///
/// When `param_to_sink` is non-empty, only arguments at those positions are
/// checked — enables per-parameter sink precision from cross-file summaries.
fn collect_tainted_sink_values(
    inst: &SsaInst,
    info: &NodeInfo,
    state: &SsaTaintState,
    sink_caps: Cap,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    param_to_sink: &[(usize, Cap)],
) -> Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> {
    let mut result = Vec::new();

    // Helper: check heap taint for an SSA value that may point to container(s).
    // At sinks we use Elements to conservatively see all indexed taint.
    let check_heap_taint =
        |v: SsaValue, result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>| {
            if let Some(pts) = lookup_pts(transfer, v) {
                if let Some(ht) = state.heap.load_set(&pts, HeapSlot::Elements) {
                    let effective = ht.caps & sink_caps;
                    if !effective.is_empty() && !result.iter().any(|&(rv, _, _)| rv == v) {
                        result.push((v, ht.caps, ht.origins));
                    }
                }
            }
        };

    // Collect SSA values used by this instruction
    let used_values = inst_use_values(inst);

    // Priority 1: gated sink filtering (CFG-level sink_payload_args).
    // `sink_payload_args` indexes into positional args (no receiver offset);
    // the receiver is a separate channel via `SsaOp::Call.receiver`.
    //
    // Destination-aware narrowing: when `destination_uses` is also set by
    // the CFG (outbound HTTP gate with an object-literal destination arg),
    // restrict sink-taint checks to SSA values whose `var_name` matches one
    // of the listed destination field identifiers. This silences
    // `fetch({url: fixed, body: tainted})` while still firing on
    // `fetch({url: tainted, body: fixed})`.
    if let Some(ref positions) = info.call.sink_payload_args {
        if let SsaOp::Call { args, .. } = &inst.op {
            let destination_filter = info.call.destination_uses.as_deref();
            for &pos in positions {
                if let Some(arg_vals) = args.get(pos) {
                    for &v in arg_vals {
                        if let Some(names) = destination_filter {
                            // Only proceed when this SSA value corresponds to
                            // a declared destination field identifier.
                            let var_name = ssa.def_of(v).var_name.as_deref();
                            let matches = var_name.is_some_and(|vn| names.iter().any(|n| n == vn));
                            if !matches {
                                continue;
                            }
                        }
                        if let Some(taint) = state.get(v) {
                            if (taint.caps & sink_caps) != Cap::empty() {
                                result.push((v, taint.caps, taint.origins.clone()));
                            }
                        }
                        check_heap_taint(v, &mut result);
                    }
                }
            }
            apply_field_aware_suppression(&mut result, inst, state, sink_caps, ssa);
            return result;
        }
    }

    // Priority 2: summary-based per-parameter sink filtering.
    // `param_to_sink` indices refer to the callee's positional parameter
    // positions and map directly onto `args`.  The receiver channel is
    // handled via `receiver_to_sink` in the summary.
    if !param_to_sink.is_empty() {
        if let SsaOp::Call { args, .. } = &inst.op {
            for &(param_idx, per_param_caps) in param_to_sink {
                let effective_caps = per_param_caps & sink_caps;
                if effective_caps.is_empty() {
                    continue;
                }
                if let Some(arg_vals) = args.get(param_idx) {
                    for &v in arg_vals {
                        if let Some(taint) = state.get(v) {
                            if (taint.caps & effective_caps) != Cap::empty()
                                && !result.iter().any(|&(rv, _, _)| rv == v)
                            {
                                result.push((v, taint.caps, taint.origins.clone()));
                            }
                        }
                        check_heap_taint(v, &mut result);
                    }
                }
            }
            apply_field_aware_suppression(&mut result, inst, state, sink_caps, ssa);
            return result;
        }
    }

    // Priority 3: aggregate fallback — check all used values
    for v in used_values {
        if let Some(taint) = state.get(v) {
            if (taint.caps & sink_caps) != Cap::empty() {
                result.push((v, taint.caps, taint.origins.clone()));
            }
        }
        check_heap_taint(v, &mut result);
    }

    apply_field_aware_suppression(&mut result, inst, state, sink_caps, ssa);
    result
}

/// Suppress plain-ident taint when a dotted-path field value used by the same
/// instruction is untainted. Prevents false positives from base-ident bleed
/// (e.g. `obj.safe = "const"; sink(obj.safe)` where `obj` is tainted).
fn apply_field_aware_suppression(
    result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    inst: &SsaInst,
    state: &SsaTaintState,
    sink_caps: Cap,
    ssa: &SsaBody,
) {
    if result.is_empty() {
        return;
    }
    let all_used = inst_use_values(inst);
    result.retain(|(v, _, _)| {
        let Some(base) = ssa.def_of(*v).var_name.as_deref() else {
            return true;
        };
        // Only suppress plain idents (no dots)
        if base.contains('.') {
            return true;
        }
        let prefix = format!("{}.", base);
        // Collect callee-like names to exclude from field suppression.
        // Method call expressions like "items.join" (from inner calls within
        // this node's arguments) should NOT be treated as field accesses.
        let callee_name = match &inst.op {
            SsaOp::Call { callee, .. } => Some(callee.as_str()),
            _ => None,
        };
        // Collect all field values matching "base.X" (excluding method-call
        // expressions and the callee itself).
        let field_values: SmallVec<[SsaValue; 4]> = all_used
            .iter()
            .copied()
            .filter(|&u| {
                u != *v
                    && ssa.def_of(u).var_name.as_deref().is_some_and(|uname| {
                        uname.starts_with(&prefix)
                            && callee_name.map_or(true, |cn| uname != cn)
                            && !is_likely_method_expression(uname)
                    })
            })
            .collect();
        // Suppress base only if there ARE field values AND ALL of them
        // are untainted for the relevant sink caps.
        let all_fields_clean = !field_values.is_empty()
            && field_values.iter().all(|&u| match state.get(u) {
                None => true,
                Some(t) => (t.caps & sink_caps).is_empty(),
            });
        !all_fields_clean
    });
}

/// Check if a dotted var_name looks like a method call expression rather than
/// a field access. E.g., "items.join" where "join" is a method name, vs
/// "obj.data" which is a field access.
///
/// Used by field-aware suppression to avoid treating method call expressions
/// as untainted field accesses (which would incorrectly suppress base-ident taint).
fn is_likely_method_expression(name: &str) -> bool {
    // Check if the dotted name matches any Call callee in the SSA body,
    // or if its suffix is a known function/method name.
    let suffix = name.rsplit('.').next().unwrap_or(name);
    // Common method names that are unlikely to be data field names.
    // This is a heuristic; it doesn't need to be exhaustive because
    // false negatives just mean slightly more conservative (no suppression).
    matches!(
        suffix,
        "push"
            | "pop"
            | "shift"
            | "unshift"
            | "join"
            | "split"
            | "concat"
            | "slice"
            | "splice"
            | "map"
            | "filter"
            | "reduce"
            | "forEach"
            | "find"
            | "some"
            | "every"
            | "get"
            | "set"
            | "has"
            | "delete"
            | "add"
            | "remove"
            | "clear"
            | "keys"
            | "values"
            | "entries"
            | "toString"
            | "valueOf"
            | "send"
            | "write"
            | "end"
            | "render"
            | "redirect"
            | "append"
            | "extend"
            | "insert"
            | "update"
            | "items"
            | "call"
            | "apply"
            | "bind"
            | "then"
            | "catch"
            | "trim"
            | "replace"
            | "match"
            | "search"
            | "test"
            | "log"
            | "warn"
            | "error"
            | "info"
            | "debug"
            | "execute"
            | "query"
            | "fetch"
            | "request"
    )
}

/// Get all SSA values used by an instruction.
fn inst_use_values(inst: &SsaInst) -> Vec<SsaValue> {
    match &inst.op {
        SsaOp::Phi(operands) => operands.iter().map(|(_, v)| *v).collect(),
        SsaOp::Assign(uses) => uses.to_vec(),
        SsaOp::Call { args, receiver, .. } => {
            let mut vals = Vec::new();
            if let Some(rv) = receiver {
                vals.push(*rv);
            }
            for arg in args {
                vals.extend(arg.iter());
            }
            vals
        }
        SsaOp::Source
        | SsaOp::Const(_)
        | SsaOp::Param { .. }
        | SsaOp::SelfParam
        | SsaOp::CatchParam
        | SsaOp::Nop => Vec::new(),
    }
}

// ── Alias-Aware Sanitization ────────────────────────────────────────────

/// After sanitizing `inst`, propagate the sanitization to must-aliased field paths.
///
/// When `alias.data` is sanitized and `alias` and `obj` are base aliases (from
/// copy propagation), this function also sanitizes `obj.data` in the taint state.
/// For plain idents (no dot), sanitizing `alias` also sanitizes `obj`.
fn propagate_sanitization_to_aliases(
    inst: &SsaInst,
    state: &mut SsaTaintState,
    sanitizer_bits: Cap,
    aliases: &crate::ssa::alias::BaseAliasResult,
    ssa: &SsaBody,
) {
    let var_name = match inst.var_name.as_deref() {
        Some(n) => n,
        None => return,
    };

    // Split into base and suffix: "alias.data" → ("alias", ".data"); "alias" → ("alias", "")
    let (base, suffix) = match var_name.find('.') {
        Some(pos) => (&var_name[..pos], &var_name[pos..]),
        None => (var_name, ""),
    };

    let alias_bases = match aliases.aliases_of(base) {
        Some(bases) => bases,
        None => return,
    };

    // Collect SsaValues to sanitize (avoid borrowing state while iterating).
    let to_sanitize: SmallVec<[SsaValue; 8]> = state
        .values
        .iter()
        .filter_map(|&(v, ref t)| {
            if t.caps.is_empty() {
                return None;
            }
            let vdef_name = ssa.value_defs.get(v.0 as usize)?.var_name.as_deref()?;

            // For each alias base, check if the value's var_name matches
            // the aliased field path.
            for alias_base in alias_bases {
                if alias_base == base {
                    continue; // skip self — already sanitized
                }
                let target = if suffix.is_empty() {
                    // Plain ident: look for exact match on alias base
                    alias_base.as_str()
                } else {
                    // Can't construct target without allocation; check inline
                    ""
                };

                if suffix.is_empty() {
                    if vdef_name == target {
                        return Some(v);
                    }
                } else {
                    // Dotted path: check if vdef_name == "{alias_base}{suffix}"
                    if vdef_name.len() == alias_base.len() + suffix.len()
                        && vdef_name.starts_with(alias_base.as_str())
                        && vdef_name.ends_with(suffix)
                    {
                        return Some(v);
                    }
                }
            }
            None
        })
        .collect();

    for v in to_sanitize {
        if let Some(taint) = state.get(v) {
            let new_caps = taint.caps & !sanitizer_bits;
            if new_caps.is_empty() {
                state.remove(v);
            } else {
                state.set(
                    v,
                    VarTaint {
                        caps: new_caps,
                        origins: taint.origins.clone(),
                        uses_summary: taint.uses_summary,
                    },
                );
            }
        }
    }
}

// ── Alias-Aware Taint Propagation ───────────────────────────────────────

/// After taint assignment to `inst`, propagate taint to must-aliased field paths.
///
/// When `obj.data` receives taint and `obj` and `alias` are base aliases (from
/// copy propagation), this function also taints `alias.data` in the taint state.
/// For plain idents (no dot), tainting `obj` also taints `alias`.
///
/// Uses only the existing `BaseAliasResult` alias groups — no new alias inference.
fn propagate_taint_to_aliases(
    inst: &SsaInst,
    state: &mut SsaTaintState,
    taint_caps: Cap,
    taint_origins: &SmallVec<[TaintOrigin; 2]>,
    aliases: &crate::ssa::alias::BaseAliasResult,
    ssa: &SsaBody,
) {
    let var_name = match inst.var_name.as_deref() {
        Some(n) => n,
        None => return,
    };

    // Split into base and suffix: "obj.data" → ("obj", ".data"); "obj" → ("obj", "")
    let (base, suffix) = match var_name.find('.') {
        Some(pos) => (&var_name[..pos], &var_name[pos..]),
        None => (var_name, ""),
    };

    let alias_bases = match aliases.aliases_of(base) {
        Some(bases) => bases,
        None => return,
    };

    // Collect SsaValues to taint. Iterate value_defs (not state.values) because
    // target alias values may not yet be in the taint state.
    let to_taint: SmallVec<[SsaValue; 8]> = ssa
        .value_defs
        .iter()
        .enumerate()
        .filter_map(|(idx, vdef)| {
            let vdef_name = vdef.var_name.as_deref()?;
            for alias_base in alias_bases {
                if alias_base == base {
                    continue; // skip self — already tainted
                }
                if suffix.is_empty() {
                    // Plain ident: look for exact match on alias base
                    if vdef_name == alias_base.as_str() {
                        return Some(SsaValue(idx as u32));
                    }
                } else {
                    // Dotted path: check if vdef_name == "{alias_base}{suffix}"
                    if vdef_name.len() == alias_base.len() + suffix.len()
                        && vdef_name.starts_with(alias_base.as_str())
                        && vdef_name.ends_with(suffix)
                    {
                        return Some(SsaValue(idx as u32));
                    }
                }
            }
            None
        })
        .collect();

    for v in to_taint {
        if let Some(existing) = state.get(v) {
            // Union caps and origins into existing taint
            let merged_caps = existing.caps | taint_caps;
            let mut merged_origins = existing.origins.clone();
            for orig in taint_origins {
                if merged_origins.len() < MAX_ORIGINS
                    && !merged_origins.iter().any(|o| o.node == orig.node)
                {
                    merged_origins.push(*orig);
                }
            }
            state.set(
                v,
                VarTaint {
                    caps: merged_caps,
                    origins: merged_origins,
                    uses_summary: existing.uses_summary,
                },
            );
        } else {
            // No existing taint — set fresh
            state.set(
                v,
                VarTaint {
                    caps: taint_caps,
                    origins: taint_origins.clone(),
                    uses_summary: false,
                },
            );
        }
    }
}

// ── SSA-Level Precision Helpers ──────────────────────────────────────────

/// Check if all argument SSA values of a call instruction are known constants.
fn all_args_const(
    inst: &SsaInst,
    const_values: &HashMap<SsaValue, crate::ssa::const_prop::ConstLattice>,
) -> bool {
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false; // no args → not a call or nothing to suppress
    }
    used.iter().all(|v| {
        matches!(
            const_values.get(v),
            Some(
                crate::ssa::const_prop::ConstLattice::Str(_)
                    | crate::ssa::const_prop::ConstLattice::Int(_)
                    | crate::ssa::const_prop::ConstLattice::Bool(_)
                    | crate::ssa::const_prop::ConstLattice::Null
            )
        )
    })
}

/// Try to resolve a callee using the receiver's inferred type.
///
/// When the callee string is `"client.send"` and the receiver SSA value is typed
/// as `HttpClient`, constructs `"HttpClient.send"` and checks label rules.
/// Returns the matched labels (source/sanitizer/sink) if any.
///
/// Resolution order:
/// 1. Static type from [`TypeFactResult`] (constructor/const inference)
/// 2. Flow-sensitive type from [`PathEnv`] (branch narrowing, casts)
fn resolve_type_qualified_labels(
    callee: &str,
    receiver: SsaValue,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    path_env: Option<&constraint::PathEnv>,
    lang: Lang,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa: Option<&SsaBody>,
) -> SmallVec<[DataLabel; 2]> {
    // Candidate method names: the last segment after `.`, plus segments peeled
    // back through trailing identity-preserving methods (`unwrap`, `expect`,
    // `await`, etc.).  For chain text like `conn.execute(&sql, []).unwrap` the
    // direct last segment is `unwrap`; the real sink verb is `execute`.
    // `normalize_chained_call_for_classify` strips paren groups; the walk
    // peels back through identity methods.
    let method_candidates = method_candidates_from_chain(callee, lang);

    // Receiver candidates: the immediate SSA receiver, plus any ancestor
    // reached by walking back through intermediate `SsaOp::Call.receiver`
    // chains (Rust parses `conn.execute(&sql, []).unwrap()` as one outer
    // call whose receiver is another call, and so on).  We stop once we find
    // a typed value or run out of receivers.
    let receiver_candidates = receiver_candidates_for_type_lookup(receiver, ssa, lang);

    // 1. Try static type first (existing behavior)
    if let Some(tf) = type_facts {
        for rv in &receiver_candidates {
            if let Some(receiver_type) = tf.get_type(*rv) {
                if let Some(prefix) = receiver_type.label_prefix() {
                    for method in &method_candidates {
                        let qualified = format!("{}.{}", prefix, method);
                        let labels =
                            crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                        if !labels.is_empty() {
                            return labels;
                        }
                    }
                }
            }
        }
    }

    // 2. Try flow-sensitive type from PathEnv (Phase 16)
    if let Some(env) = path_env {
        for rv in &receiver_candidates {
            let types = env.get(*rv).types;
            if let Some(kind) = types.as_singleton() {
                if let Some(prefix) = kind.label_prefix() {
                    for method in &method_candidates {
                        let qualified = format!("{}.{}", prefix, method);
                        let labels =
                            crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                        if !labels.is_empty() {
                            return labels;
                        }
                    }
                }
            }
        }
    }

    SmallVec::new()
}

/// Walk back through `SsaOp::Call.receiver` chains to collect candidate SSA
/// values for type-fact lookup.  Needed for languages (Rust) where a chain
/// like `conn.execute(x).unwrap()` is represented as a single outer call
/// whose receiver is itself a call expression — the stable base identifier
/// (`conn`) is several receivers up.
fn receiver_candidates_for_type_lookup(
    start: SsaValue,
    ssa: Option<&SsaBody>,
    lang: Lang,
) -> SmallVec<[SsaValue; 4]> {
    let mut out: SmallVec<[SsaValue; 4]> = SmallVec::new();
    out.push(start);
    if !matches!(lang, Lang::Rust) {
        return out;
    }
    let Some(body) = ssa else {
        return out;
    };
    let mut current = start;
    for _ in 0..8 {
        // Find the instruction defining `current`.
        let mut next_receiver: Option<SsaValue> = None;
        'scan: for block in &body.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if inst.value == current {
                    if let SsaOp::Call {
                        receiver: Some(rv), ..
                    } = &inst.op
                    {
                        next_receiver = Some(*rv);
                    }
                    break 'scan;
                }
            }
        }
        match next_receiver {
            Some(rv) if !out.contains(&rv) => {
                out.push(rv);
                current = rv;
            }
            _ => break,
        }
    }
    out
}

/// Extract candidate method names from a chained-call callee text.
///
/// Tree-sitter constructs `a.foo(x).bar()` as nested method-call nodes.  The
/// CFG records the outermost callee text (here `a.foo(x).bar`), which means
/// the last `.`-segment is the terminal method (`bar`).  When the terminal
/// is an identity-preserving method (`.unwrap()`, `.expect()`, `.await`,
/// `.clone()`, etc.), the *real* sink verb is the preceding segment.  This
/// helper walks back through identity methods to return all plausible
/// terminals in priority order (most-specific first).
fn method_candidates_from_chain(callee: &str, lang: Lang) -> SmallVec<[String; 4]> {
    let mut out: SmallVec<[String; 4]> = SmallVec::new();
    // Normalize: strip `(...)` groups so we index into `.`-segments directly.
    // Use the same normalization used for label classification so this mirrors
    // matcher behavior.
    let normalized = crate::labels::normalize_chained_call_for_classify(callee);
    let segments: Vec<&str> = normalized.split('.').collect();
    if segments.is_empty() {
        return out;
    }
    // Walk from the end, peeling identity methods.
    let mut i = segments.len();
    while i > 0 {
        let seg = segments[i - 1];
        if !seg.is_empty() {
            out.push(seg.to_string());
        }
        if matches!(lang, Lang::Rust) && crate::ssa::type_facts::is_identity_method(seg) {
            i -= 1;
            continue;
        }
        break;
    }
    out
}

/// Suppress sinks from known non-sink callees (e.g., `System.out.println` in Java).
///
/// These are callees whose suffix matches a broad sink rule but whose
/// receiver is known to be safe (console output, not HTTP response).
fn suppress_known_safe_callees(sink_caps: Cap, callee: &str, lang: Lang) -> Cap {
    match lang {
        Lang::Java => {
            if callee.starts_with("System.out.") || callee.starts_with("System.err.") {
                sink_caps & !Cap::HTML_ESCAPE
            } else {
                sink_caps
            }
        }
        _ => sink_caps,
    }
}

/// Check if a sink is type-safe (e.g., SQL injection or path traversal with int-typed argument).
///
/// Suppresses findings when all argument values are known to be integer-typed,
/// since integer values cannot carry SQL injection or path traversal payloads.
/// Delegates to the shared [`crate::ssa::type_facts::is_type_safe_for_sink`]
/// helper so the structural `cfg-unguarded-sink` analysis agrees on the
/// suppression rule.
fn is_type_safe_for_sink(
    inst: &SsaInst,
    sink_caps: Cap,
    type_facts: &crate::ssa::type_facts::TypeFactResult,
) -> bool {
    let used = inst_use_values(inst);
    crate::ssa::type_facts::is_type_safe_for_sink(&used, sink_caps, type_facts)
}

// ── Phase 16: Centralized Type-Sink Compatibility Helpers ────────────────

/// Check if a [`TypeKind`] is safe for a given sink capability.
///
/// Returns `true` if the type cannot carry the payload required by the sink.
/// Policy: Int/Bool values cannot carry injection payloads (SQL, code, path).
/// String-typed values CAN carry injection payloads — casts to String do NOT
/// make a value safe.
fn type_safe_for_taint_sink(kind: &crate::ssa::type_facts::TypeKind, cap: Cap) -> bool {
    use crate::ssa::type_facts::TypeKind;
    match kind {
        TypeKind::Int | TypeKind::Bool => {
            cap.intersects(Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC | Cap::SHELL_ESCAPE)
        }
        _ => false,
    }
}

/// Check if a receiver type is incompatible with a sink label's requirements.
///
/// Returns the Cap bits that should be REMOVED because the receiver type
/// proves the sink doesn't apply. For example, `HTML_ESCAPE` sinks require
/// an HTTP-response-like receiver — if the receiver is known to be
/// Int/Bool/String, `HTML_ESCAPE` doesn't apply.
fn receiver_incompatible_sink_caps(kind: &crate::ssa::type_facts::TypeKind, sink_caps: Cap) -> Cap {
    use crate::ssa::type_facts::TypeKind;
    let mut remove = Cap::empty();
    // HTML_ESCAPE requires HTTP response-like receiver
    if sink_caps.intersects(Cap::HTML_ESCAPE) {
        match kind {
            TypeKind::HttpResponse => {}               // compatible
            TypeKind::Unknown | TypeKind::Object => {} // could be response
            _ => {
                remove |= Cap::HTML_ESCAPE;
            }
        }
    }
    // Injection sinks require string-like payload
    if type_safe_for_taint_sink(kind, sink_caps) {
        remove |= sink_caps & (Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC);
    }
    remove
}

/// Check if all argument values of an instruction have types that are safe
/// for the given sink (path-sensitive, via [`PathEnv`]).
fn is_path_type_safe_for_sink(inst: &SsaInst, sink_caps: Cap, env: &constraint::PathEnv) -> bool {
    let type_suppressible = Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC;
    if !sink_caps.intersects(type_suppressible) {
        return false;
    }
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }
    used.iter().all(|v| match env.get(*v).types.as_singleton() {
        Some(ref kind) => type_safe_for_taint_sink(kind, sink_caps),
        None => false, // Multiple possible types → not safe
    })
}

// ── Phase 17: Abstract-Domain Sink Suppression ─────────────────────────

/// Check if abstract domain facts prove a sink is safe.
///
/// SSRF: string prefix with locked host.
/// SQL_QUERY / FILE_IO: dual gate — type-proven Int AND bounded interval on all
/// tainted leaf values. Traces back through Assign chains to find original
/// tainted data (e.g., `parseInt(x)` inside `"SELECT ..." + parseInt(x) * 10`).
///
/// NOTE: FILE_IO string prefix suppression intentionally omitted.
/// A prefix like "/app/static/" does not prevent path traversal
/// (e.g., "/app/static/../../etc/passwd"). The string domain cannot
/// prove absence of "../" in the attacker-controlled suffix.
fn is_abstract_safe_for_sink(
    inst: &SsaInst,
    sink_caps: Cap,
    abs: &AbstractState,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    static_map: Option<&crate::ssa::static_map::StaticMapResult>,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }

    // SSRF — string prefix with locked host
    if sink_caps.intersects(Cap::SSRF) {
        // Inline template-literal prefix attached to the CFG node directly
        // (covers sinks whose URL is a template literal argument without an
        // intermediate Assign to seed the abstract domain).
        let node_info = &cfg[inst.cfg_node];
        if let Some(prefix) = node_info.string_prefix.as_deref() {
            let synthetic = crate::abstract_interp::StringFact::from_prefix(prefix);
            if is_string_safe_for_ssrf(&synthetic) {
                return true;
            }
        }
        if used
            .iter()
            .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string))
        {
            return true;
        }
    }

    // SHELL_ESCAPE — static-map finite-domain safety.  When every tainted
    // payload value is proved by the static-HashMap-lookup analysis to come
    // from a bounded set of metacharacter-free literals, the call cannot
    // carry shell injection regardless of how the attacker influenced the
    // lookup key.  Only fires when the value appears in `static_map.finite_
    // string_values`, not for arbitrary single-literal exact facts — those
    // already have their own constant-argument suppression path and we
    // must not over-apply shell-safety to unrelated const-prop bare-string
    // artefacts (e.g. Python `commands = []`).
    if sink_caps.intersects(Cap::SHELL_ESCAPE) && is_static_map_shell_safe(&used, static_map) {
        return true;
    }

    // HTML_ESCAPE type-only gate: an integer's decimal representation is
    // always digits (with optional leading `-`), which never contain HTML
    // metacharacters (`<`, `>`, `"`, `'`, `&`, `/`, `:`) in either text or
    // attribute context.  The interval bound is irrelevant here — a large
    // magnitude doesn't introduce metachars — so HTML_ESCAPE uses a
    // type-only leaf check rather than the SQL/FILE/SHELL dual gate below.
    if sink_caps.intersects(Cap::HTML_ESCAPE) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty() && leaves.iter().all(|v| tf.is_int(*v)) {
                return true;
            }
        }
    }

    // Dual gate: SQL_QUERY / FILE_IO / SHELL_ESCAPE with proven Int type AND
    // bounded interval.  Both conditions required: type proves the value IS
    // an integer (not a string that happened to parse), interval proves it's
    // bounded (not arbitrary).  Traces through Assign chains so
    // "const_string + tainted_int" is caught.  SHELL_ESCAPE is included
    // because a bounded integer's decimal representation can't contain shell
    // metacharacters.
    if sink_caps.intersects(Cap::SQL_QUERY | Cap::FILE_IO | Cap::SHELL_ESCAPE) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty()
                && leaves
                    .iter()
                    .all(|v| tf.is_int(*v) && abs.get(*v).interval.is_proven_bounded())
            {
                return true;
            }
        }
    }

    false
}

/// Check if call arguments prove a sink is safe via abstract domain.
fn is_call_abstract_safe(
    inst: &SsaInst,
    args: &[SmallVec<[SsaValue; 2]>],
    sink_caps: Cap,
    abs: &AbstractState,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    static_map: Option<&crate::ssa::static_map::StaticMapResult>,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    // SSRF — check if the URL argument (first arg) has a safe prefix.
    if sink_caps.intersects(Cap::SSRF) {
        // Inline template-literal prefix from the call AST itself
        // (e.g. `axios.get(\`https://host/…${x}\`)` has no intermediate Assign
        // to seed a StringFact — check the node-attached prefix directly).
        let node_info = &cfg[inst.cfg_node];
        if let Some(prefix) = node_info.string_prefix.as_deref() {
            let synthetic = crate::abstract_interp::StringFact::from_prefix(prefix);
            if is_string_safe_for_ssrf(&synthetic) {
                return true;
            }
        }
        if let Some(first_arg) = args.first() {
            if !first_arg.is_empty()
                && first_arg
                    .iter()
                    .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string))
            {
                return true;
            }
        }
    }

    // SHELL_ESCAPE — static-map finite-domain safety on every non-empty arg
    // group.  Mirrors the non-Call path so suppression fires regardless of
    // which branch the sink detector took.
    if sink_caps.intersects(Cap::SHELL_ESCAPE) && !args.is_empty() {
        let all_values: Vec<SsaValue> = args.iter().flat_map(|g| g.iter().copied()).collect();
        if !all_values.is_empty() && is_static_map_shell_safe(&all_values, static_map) {
            return true;
        }
    }

    // HTML_ESCAPE type-only gate (same as non-Call path): digits never
    // contain HTML metacharacters regardless of magnitude, so an integer
    // payload is safe for an HTML sink without requiring a bounded interval.
    if sink_caps.intersects(Cap::HTML_ESCAPE) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty() && leaves.iter().all(|v| tf.is_int(*v)) {
                return true;
            }
        }
    }

    // Dual gate for Call sinks (same as non-Call path)
    if sink_caps.intersects(Cap::SQL_QUERY | Cap::FILE_IO | Cap::SHELL_ESCAPE) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty()
                && leaves
                    .iter()
                    .all(|v| tf.is_int(*v) && abs.get(*v).interval.is_proven_bounded())
            {
                return true;
            }
        }
    }

    false
}

/// Maximum backwards trace depth through Assign chains.
const MAX_TRACE_DEPTH: usize = 8;

/// Trace backwards through Assign chains to find the leaf tainted SSA values.
///
/// When a tainted value is a binary operation (e.g., string concatenation of
/// `"SELECT ..." + offset`), the concat result is String-typed but the tainted
/// operand (`offset`) may be Int-typed and bounded. This function finds those
/// leaf tainted values so dual-gate suppression can check them directly.
fn trace_tainted_leaf_values(
    inst: &SsaInst,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> SmallVec<[SsaValue; 4]> {
    let mut leaves = SmallVec::new();
    let used = inst_use_values(inst);
    for &v in &used {
        if state.get(v).is_some() {
            trace_single_leaf(v, state, ssa, cfg, &mut leaves, 0);
        }
    }
    leaves
}

fn trace_single_leaf(
    v: SsaValue,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
    leaves: &mut SmallVec<[SsaValue; 4]>,
    depth: usize,
) {
    if depth >= MAX_TRACE_DEPTH || leaves.len() >= 16 {
        leaves.push(v);
        return;
    }
    // Find the instruction defining v by scanning its block.
    let vd = &ssa.value_defs[v.0 as usize];
    let block = &ssa.blocks[vd.block.0 as usize];
    let inst = match block.body.iter().find(|i| i.value == v) {
        Some(i) => i,
        None => {
            // Phi or not found in body — treat as leaf
            leaves.push(v);
            return;
        }
    };
    // Numeric-length reads (`arr.length`, `map.size`, `vec.len()`, ...) yield
    // an integer whose decimal representation cannot contain injection
    // metacharacters.  Treat the result as a leaf so the dual-gate / HTML-
    // escape type check sees the Int-typed length value rather than tracing
    // through to the underlying container (which is typically String-typed
    // and would defeat suppression).
    if cfg
        .node_weight(inst.cfg_node)
        .is_some_and(|ni| ni.is_numeric_length_access)
    {
        leaves.push(v);
        return;
    }
    match &inst.op {
        SsaOp::Assign(uses) if uses.len() >= 2 => {
            // Numeric binary operations (bitwise, arithmetic except Add, comparisons)
            // always produce integers — treat the result as a leaf rather than tracing
            // through to the string-typed operands. Add is excluded because it may be
            // string concatenation.
            let bin_op = cfg.node_weight(inst.cfg_node).and_then(|ni| ni.bin_op);
            let is_numeric_op = matches!(
                bin_op,
                Some(
                    crate::cfg::BinOp::Sub
                        | crate::cfg::BinOp::Mul
                        | crate::cfg::BinOp::Div
                        | crate::cfg::BinOp::Mod
                        | crate::cfg::BinOp::BitAnd
                        | crate::cfg::BinOp::BitOr
                        | crate::cfg::BinOp::BitXor
                        | crate::cfg::BinOp::LeftShift
                        | crate::cfg::BinOp::RightShift
                        | crate::cfg::BinOp::Eq
                        | crate::cfg::BinOp::NotEq
                        | crate::cfg::BinOp::Lt
                        | crate::cfg::BinOp::LtEq
                        | crate::cfg::BinOp::Gt
                        | crate::cfg::BinOp::GtEq
                )
            );
            if is_numeric_op {
                leaves.push(v);
                return;
            }

            let mut found = false;
            for &u in uses {
                if state.get(u).is_some() {
                    trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
                    found = true;
                }
            }
            if !found {
                leaves.push(v);
            }
        }
        SsaOp::Call { callee, args, .. } if is_stringify_callee(callee) => {
            // String-producing conversion of already-bounded values.  Trace
            // through the arguments so the dual-gate check sees the upstream
            // Int/bounded leaves.  Examples: `x.to_string()`, `format!(...)`.
            let mut found = false;
            for arg in args {
                for &u in arg {
                    if state.get(u).is_some() {
                        trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
                        found = true;
                    }
                }
            }
            if !found {
                leaves.push(v);
            }
        }
        SsaOp::Call { args, .. } => {
            // For a Call whose node is not itself a Source (so the Call
            // introduces no fresh attacker-controlled taint), trace through
            // the arguments to find the upstream tainted leaves.  The Call's
            // return taint is a function of its args under this
            // classification, so the leaves are the Call's inputs.  Source-
            // labeled Calls keep the default leaf behavior — tracing past
            // them would erase the Source and over-suppress.
            let is_source = cfg
                .node_weight(inst.cfg_node)
                .map(|ni| {
                    ni.taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
                })
                .unwrap_or(false);
            if is_source {
                leaves.push(v);
            } else {
                let mut found = false;
                for arg in args {
                    for &u in arg {
                        if state.get(u).is_some() {
                            trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
                            found = true;
                        }
                    }
                }
                if !found {
                    leaves.push(v);
                }
            }
        }
        SsaOp::Assign(uses) if uses.len() == 1 => {
            // Single-use Assign: pass through to the source value's leaf.
            // Covers the common pattern where SSA lowering emits both a Call
            // form carrying a sink expression and an outer Assign that binds
            // the Call's value to the defined variable — without this, the
            // Assign's tracing stops at the wrapped Call (String-typed by
            // default) and loses the Int / bounded leaf already known through
            // the Call's args.
            let u = uses[0];
            if state.get(u).is_some() {
                trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
            } else {
                leaves.push(v);
            }
        }
        _ => {
            leaves.push(v);
        }
    }
}

/// Call verbs that convert a value to a String without introducing attacker-
/// controlled metacharacters.  Used by [`trace_single_leaf`] to peek past the
/// String-typed result when the upstream value is Int/bounded.
///
/// Normalizes the callee (strips `(…)` groups) and peels trailing identity
/// methods so chains like `.to_string().as_str()` resolve correctly.
fn is_stringify_callee(callee: &str) -> bool {
    let base = crate::ssa::type_facts::peel_identity_suffix(callee);
    let suffix = base.rsplit(['.', ':']).next().unwrap_or(&base);
    matches!(
        suffix,
        "to_string" | "to_owned" | "format" | "String" | "str"
    )
}

/// Return `true` when every value in `values` was proved by the static-map
/// analysis to be drawn from a finite set of metacharacter-free literals.
/// Returns `false` when `static_map` is `None`, when any value is missing,
/// or when any value's bounded set contains a shell metacharacter — the
/// predicate is conservative, so a missing entry never suppresses.
fn is_static_map_shell_safe(
    values: &[SsaValue],
    static_map: Option<&crate::ssa::static_map::StaticMapResult>,
) -> bool {
    let Some(sm) = static_map else {
        return false;
    };
    if values.is_empty() {
        return false;
    }
    values.iter().all(|v| match sm.finite_string_values.get(v) {
        Some(set) if !set.is_empty() => set
            .iter()
            .all(|s| crate::abstract_interp::string_domain::is_shell_safe_literal(s)),
        _ => false,
    })
}

/// SSRF safety: prefix includes scheme + full host + path separator.
///
/// Soundness: if the prefix contains `scheme://host/`, the attacker cannot
/// control the destination host. They can only influence the path/query,
/// which is not SSRF.
fn is_string_safe_for_ssrf(sf: &crate::abstract_interp::StringFact) -> bool {
    let prefix = match &sf.prefix {
        Some(p) => p.as_str(),
        None => return false,
    };
    // Absolute-path prefix (e.g. "/projects/...") — internal redirect, not open redirect.
    // The leading "/" locks the path to the same origin; the attacker cannot control the scheme
    // or host, so this is not an SSRF vector.
    if prefix.starts_with('/') {
        return true;
    }
    if let Some(after_scheme) = prefix.find("://") {
        let host_and_rest = &prefix[after_scheme + 3..];
        if let Some(slash_pos) = host_and_rest.find('/') {
            return slash_pos > 0; // non-empty host + path separator
        }
    }
    false
}

/// Resolve a bare or qualified callee string to a local [`FuncKey`] by
/// scanning `local_summaries` (already FuncKey-keyed).
///
/// Resolution is deliberately identity-aware:
///
/// 1. Filter by `(lang, namespace, name)` — these always participate in the
///    identity hash, so the candidate set is guaranteed to be the
///    same-file same-leaf-name definitions.
/// 2. If `container_hint` is supplied (e.g. the `obj` in `obj.method`),
///    narrow to candidates whose [`FuncKey::container`] matches.
/// 3. If exactly one candidate remains, return its key.
///
/// Returns `None` when zero or multiple candidates remain — callers should
/// then fall through to their own ambiguity policy instead of accidentally
/// picking an arbitrary definition.
/// Split a raw callee string into a `(namespace_qualifier, receiver_var)`
/// pair.
///
/// * `"env::var"`    → `(Some("env"), None)`
/// * `"std::io::File::open"` → `(Some("File"), None)` — leaf's immediate
///   container is kept so qualified lookup can match
///   `File::open`.  Deeper module prefixes are discarded here; the call
///   graph's Rust-specific resolver handles full paths via the use map.
/// * `"obj.method"` → `(None, Some("obj"))`
/// * `"a.b.method"` → `(None, Some("b"))` — immediate object hop.
/// * `"foo"`         → `(None, None)`
///
/// `::` is treated as a namespace separator and produces a
/// `namespace_qualifier`; `.` is treated as a method receiver and
/// produces a `receiver_var`.  When both separators appear, the
/// last-used one wins — matching the leaf-extraction rule in
/// [`callee_leaf_name`].
fn split_qualifier(raw: &str) -> (Option<&str>, Option<&str>) {
    if let Some(pos) = raw.rfind("::") {
        let prefix = &raw[..pos];
        let last = prefix.rsplit("::").next().unwrap_or(prefix);
        return (if last.is_empty() { None } else { Some(last) }, None);
    }
    if let Some(pos) = raw.rfind('.') {
        let prefix = &raw[..pos];
        let last = prefix.rsplit('.').next().unwrap_or(prefix);
        return (None, if last.is_empty() { None } else { Some(last) });
    }
    (None, None)
}

/// Look up the caller's own container by matching its name in
/// `local_summaries`.  Used so bare self-calls (`foo()` inside a class
/// method) prefer same-class candidates over free functions.
fn caller_container_for(transfer: &SsaTaintTransfer, caller_func: &str) -> Option<String> {
    if caller_func.is_empty() {
        return None;
    }
    let mut containers: Vec<&str> = transfer
        .local_summaries
        .keys()
        .filter(|k| k.lang == transfer.lang && k.name == caller_func)
        .map(|k| k.container.as_str())
        .filter(|c| !c.is_empty())
        .collect();
    containers.sort();
    containers.dedup();
    if containers.len() == 1 {
        Some(containers[0].to_string())
    } else {
        None
    }
}

/// Query-based equivalent of [`resolve_local_func_key`].
///
/// Prefers `receiver_type` → `namespace_qualifier` → `caller_container`
/// in that order before falling back to a uniqueness check on the leaf
/// name.  Keeps behaviour parity with the top-level resolver so
/// intra-file lookups apply the same qualified-first policy.
pub(crate) fn resolve_local_func_key_query(
    local_summaries: &FuncSummaries,
    q: &CalleeQuery<'_>,
) -> Option<FuncKey> {
    let all: Vec<&FuncKey> = local_summaries
        .keys()
        .filter(|k| k.name == q.name && k.lang == q.caller_lang)
        .collect();
    if all.is_empty() {
        return None;
    }

    let arity_matches = |k: &FuncKey| match q.arity {
        Some(a) => k.arity == Some(a),
        None => true,
    };

    let pick_with_container = |container: &str| -> Option<FuncKey> {
        if container.is_empty() {
            return None;
        }
        let narrowed: Vec<&FuncKey> = all
            .iter()
            .copied()
            .filter(|k| k.container == container)
            .filter(|k| arity_matches(k))
            .collect();
        if narrowed.len() == 1 {
            Some(narrowed[0].clone())
        } else {
            None
        }
    };

    if let Some(rt) = q.receiver_type {
        if let Some(k) = pick_with_container(rt) {
            return Some(k);
        }
        // Authoritative miss — do not silently pick a different container.
        return None;
    }

    if let Some(nq) = q.namespace_qualifier {
        if let Some(k) = pick_with_container(nq) {
            return Some(k);
        }
    }

    if let Some(cc) = q.caller_container {
        if let Some(k) = pick_with_container(cc) {
            return Some(k);
        }
    }

    let arity_filtered: Vec<&FuncKey> = all.iter().copied().filter(|k| arity_matches(k)).collect();
    if arity_filtered.len() == 1 {
        return Some(arity_filtered[0].clone());
    }

    if let Some(rv) = q.receiver_var {
        if let Some(k) = pick_with_container(rv) {
            return Some(k);
        }
    }

    // Bare-call free-function preference — mirrors
    // `GlobalSummaries::resolve_callee` step 5.5.  When the call is
    // syntactically bare (no receiver, no namespace qualifier, no
    // authoritative receiver type) and exactly one arity-matched local
    // candidate is a free function (empty container), it is the
    // unambiguous target: class methods cannot be invoked with
    // bare-call syntax from outside their own class (self-calls are
    // handled by the `caller_container` branch above).
    if q.receiver_type.is_none() && q.namespace_qualifier.is_none() && q.receiver_var.is_none() {
        let empty: Vec<&FuncKey> = arity_filtered
            .iter()
            .copied()
            .filter(|k| k.container.is_empty())
            .collect();
        if empty.len() == 1 {
            return Some(empty[0].clone());
        }
    }

    None
}

pub(crate) fn resolve_local_func_key(
    local_summaries: &FuncSummaries,
    lang: Lang,
    _namespace: &str,
    leaf_name: &str,
    container_hint: Option<&str>,
) -> Option<FuncKey> {
    // `local_summaries` is file-local; every entry shares the same namespace
    // (raw file path from `build_cfg`). We do not filter by namespace here so
    // callers can pass whichever form they have (raw or normalized).
    let mut candidates: Vec<&FuncKey> = local_summaries
        .keys()
        .filter(|k| k.name == leaf_name && k.lang == lang)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() > 1 {
        if let Some(container) = container_hint {
            let narrowed: Vec<&FuncKey> = candidates
                .iter()
                .copied()
                .filter(|k| k.container == container)
                .collect();
            if narrowed.len() == 1 {
                return Some(narrowed[0].clone());
            }
            candidates = narrowed;
        }
    }
    if candidates.len() == 1 {
        Some(candidates[0].clone())
    } else {
        None
    }
}

// ── Callee Resolution (mirrors TaintTransfer::resolve_callee) ───────────

struct ResolvedSummary {
    source_caps: Cap,
    sanitizer_caps: Cap,
    sink_caps: Cap,
    /// Per-parameter sink caps: (param_index, caps). When non-empty, only
    /// arguments at these positions flow to internal sinks — enables positional
    /// and capability-aware filtering instead of aggregate-only detection.
    param_to_sink: Vec<(usize, Cap)>,
    /// Per-parameter [`SinkSite`] records mirroring `param_to_sink` by index.
    /// Populated when the underlying summary carried source-coordinate
    /// context (SSA and global `FuncSummary` paths).  Empty for label,
    /// local-summary, and interop paths where no [`SinkSite`] was
    /// retained; in that case `param_to_sink` alone still drives sink
    /// detection.
    param_to_sink_sites: Vec<(usize, SmallVec<[SinkSite; 1]>)>,
    propagates_taint: bool,
    propagating_params: Vec<usize>,
    /// Parameter indices whose container identity flows to return value.
    param_container_to_return: Vec<usize>,
    /// (src_param, container_param) pairs: src taint stored into container.
    param_to_container_store: Vec<(usize, usize)>,
    /// Inferred return type from cross-file SSA summary.
    return_type: Option<crate::ssa::type_facts::TypeKind>,
    /// Abstract domain fact for the return value (Phase 17 hardening).
    return_abstract: Option<crate::abstract_interp::AbstractValue>,
    /// Internal source taint flows to a call of parameter N with these caps.
    source_to_callback: Vec<(usize, Cap)>,
    /// How receiver (`self`/`this`) taint flows to the return value.
    /// Matches `SsaFuncSummary::receiver_to_return` semantics.
    #[allow(dead_code)]
    receiver_to_return: Option<crate::summary::ssa_summary::TaintTransform>,
    /// Caps that receiver taint reaches at internal sinks.
    #[allow(dead_code)]
    receiver_to_sink: Cap,
    /// Phase CF-3: per-parameter abstract-domain transfer channels.
    ///
    /// Populated only when the callee was resolved via an SSA summary
    /// (`convert_ssa_to_resolved`).  The label, local-summary, interop
    /// and coarse `FuncSummary` paths carry `Vec::new()` because those
    /// forms do not record abstract-domain behaviour.  Applied at the
    /// call site to synthesise an abstract return value from the
    /// caller's knowledge of each argument.
    abstract_transfer: Vec<(usize, crate::abstract_interp::AbstractTransfer)>,
    /// Phase CF-4: per-parameter return-path decomposition.
    ///
    /// Populated only when the callee was resolved via an SSA summary
    /// and the summary carries ≥2 distinct return-path predicate gates.
    /// When present, summary application at the call site consults the
    /// caller's [`SsaTaintState::predicates`] and applies only entries
    /// whose predicate gate is consistent with the caller's validated
    /// set — recovering callee-internal path splits that the aggregate
    /// [`Self::sanitizer_caps`] / [`Self::propagating_params`] view
    /// otherwise erases.  Empty for non-SSA resolution paths.
    param_return_paths: Vec<(
        usize,
        smallvec::SmallVec<[crate::summary::ssa_summary::ReturnPathTransform; 2]>,
    )>,
}

fn resolve_callee(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
) -> Option<ResolvedSummary> {
    resolve_callee_hinted(transfer, callee, caller_func, call_ordinal, None)
}

/// Like [`resolve_callee`] but accepts an `arity_hint` that narrows the
/// candidate set to functions with a matching parameter count.
///
/// Used by the call-graph / SSA-transfer paths when the caller knows the
/// number of positional arguments at this site — this eliminates false
/// resolution to same-name siblings with different arities (e.g.
/// `encode(x)` vs `encode(x, opts)` in the same namespace).
fn resolve_callee_hinted(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
) -> Option<ResolvedSummary> {
    resolve_callee_full(
        transfer,
        callee,
        caller_func,
        call_ordinal,
        arity_hint,
        None,
    )
}

/// Like [`resolve_callee_hinted`] but accepts an authoritative
/// `receiver_type` (class/impl name) derived from the SSA receiver
/// value's [`TypeKind::label_prefix`].  When supplied, qualified
/// lookup uses this name first and refuses to fall through to a
/// leaf-name collision on miss (see
/// [`GlobalSummaries::resolve_callee`] step 1).
fn resolve_callee_typed(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver: Option<SsaValue>,
) -> Option<ResolvedSummary> {
    let receiver_type = receiver_type_prefix(transfer, receiver);
    resolve_callee_full(
        transfer,
        callee,
        caller_func,
        call_ordinal,
        arity_hint,
        receiver_type,
    )
}

/// Extract a qualified receiver-type name (e.g. `"HttpClient"`) for the
/// SSA receiver value, when type facts can infer it.  Returns `None`
/// for built-in `Int`/`String`/unknown types that have no class prefix.
fn receiver_type_prefix(
    transfer: &SsaTaintTransfer,
    receiver: Option<SsaValue>,
) -> Option<&'static str> {
    let v = receiver?;
    let tf = transfer.type_facts?;
    let kind = tf.get_type(v)?;
    kind.label_prefix()
}

fn resolve_callee_full(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver_type: Option<&str>,
) -> Option<ResolvedSummary> {
    // Use leaf name for map/index lookups (FuncKey.name is always leaf).
    let normalized = callee_leaf_name(callee);
    // Split the raw callee into structured qualifier hints.  A `::`
    // prefix is a namespace qualifier (authoritative-ish); a `.`
    // prefix is the syntactic receiver variable, which we treat as a
    // soft hint.
    let (namespace_qualifier, receiver_var) = split_qualifier(callee);

    // -2) Import alias resolution: if the callee matches an aliased import
    // (e.g. `fetchUserCmd` → `getInput` from `./source`), resolve using the
    // original exported name instead.  This fires before all other resolution
    // so that downstream steps see the canonical symbol name.
    if let Some(bindings) = transfer.import_bindings {
        if let Some(binding) = bindings.get(normalized) {
            // Recursively resolve using the original name, preserving the
            // arity hint (the import alias does not change call arity).
            return resolve_callee_hinted(
                transfer,
                &binding.original,
                caller_func,
                call_ordinal,
                arity_hint,
            );
        }
    }

    // -1) Callback resolution: if the callee name matches a parameter that was
    // bound to a specific function at the call site, resolve that function instead.
    if let Some(cb) = transfer.callback_bindings {
        if let Some(real_key) = cb.get(normalized) {
            // Try to resolve the actual function via FuncKey-keyed SSA summaries
            if let Some(ssa_sums) = transfer.ssa_summaries {
                if let Some(ssa_sum) = ssa_sums.get(real_key) {
                    return Some(convert_ssa_to_resolved(ssa_sum));
                }
            }
            // Try local summaries (already FuncKey-keyed)
            if let Some(ls) = transfer.local_summaries.get(real_key) {
                return Some(ResolvedSummary {
                    source_caps: ls.source_caps,
                    sanitizer_caps: ls.sanitizer_caps,
                    sink_caps: ls.sink_caps,
                    param_to_sink: ls
                        .tainted_sink_params
                        .iter()
                        .map(|&i| (i, ls.sink_caps))
                        .collect(),
                    param_to_sink_sites: vec![],
                    propagates_taint: !ls.propagating_params.is_empty(),
                    propagating_params: ls.propagating_params.clone(),
                    param_container_to_return: vec![],
                    param_to_container_store: vec![],
                    return_type: None,
                    return_abstract: None,
                    source_to_callback: vec![],

                    receiver_to_return: None,

                    receiver_to_sink: Cap::empty(),

                    abstract_transfer: vec![],
                    param_return_paths: vec![],
                });
            }
            // Try label classification for the bound function (by leaf name)
            let labels = crate::labels::classify_all(
                transfer.lang.as_str(),
                &real_key.name,
                transfer.extra_labels,
            );
            if !labels.is_empty() {
                let mut source_caps = Cap::empty();
                let mut sanitizer_caps = Cap::empty();
                let mut sink_caps = Cap::empty();
                for lbl in &labels {
                    match lbl {
                        DataLabel::Source(bits) => source_caps |= *bits,
                        DataLabel::Sanitizer(bits) => sanitizer_caps |= *bits,
                        DataLabel::Sink(bits) => sink_caps |= *bits,
                    }
                }
                return Some(ResolvedSummary {
                    source_caps,
                    sanitizer_caps,
                    sink_caps,
                    param_to_sink: vec![],
                    param_to_sink_sites: vec![],
                    propagates_taint: false,
                    propagating_params: vec![],
                    param_container_to_return: vec![],
                    param_to_container_store: vec![],
                    return_type: None,
                    return_abstract: None,
                    source_to_callback: vec![],

                    receiver_to_return: None,

                    receiver_to_sink: Cap::empty(),

                    abstract_transfer: vec![],
                    param_return_paths: vec![],
                });
            }
        }
    }

    // Caller-container hint: when the caller lives inside a class/impl,
    // its own container resolves bare self-calls correctly instead of
    // collapsing into an unrelated same-leaf definition.
    let caller_container_opt = caller_container_for(transfer, caller_func);
    let caller_container: Option<&str> = caller_container_opt.as_deref();

    // Build the structured query once and reuse across the same-language
    // resolution steps (0.5 and 2).
    let build_query = || CalleeQuery {
        name: normalized,
        caller_lang: transfer.lang,
        caller_namespace: transfer.namespace,
        caller_container,
        receiver_type,
        namespace_qualifier,
        receiver_var,
        arity: arity_hint,
    };

    // 0) Precise SSA summaries (intra-file, per-parameter transforms).
    //
    // Resolve the callee string to a local `FuncKey` via the already-
    // FuncKey-keyed `local_summaries` index, then consult `ssa_summaries` by
    // the same key.  This preserves container/arity/disambig identity so two
    // same-name definitions in the same file never share an SSA summary.
    if let Some(ssa_sums) = transfer.ssa_summaries {
        if let Some(key) = resolve_local_func_key_query(transfer.local_summaries, &build_query()) {
            if let Some(ssa_sum) = ssa_sums.get(&key) {
                return Some(convert_ssa_to_resolved(ssa_sum));
            }
        }
    }

    // 0.5) Cross-file SSA summaries (GlobalSummaries.ssa_by_key)
    if let Some(gs) = transfer.global_summaries {
        match gs.resolve_callee(&build_query()) {
            CalleeResolution::Resolved(target_key) => {
                if let Some(ssa_sum) = gs.get_ssa(&target_key) {
                    return Some(convert_ssa_to_resolved(ssa_sum));
                }
            }
            _ => {}
        }
    }

    // 1) Local (same-file) — lookup via canonical FuncKey using the
    // same qualified-first policy as the global resolver.
    if let Some(key) = resolve_local_func_key_query(transfer.local_summaries, &build_query()) {
        if let Some(ls) = transfer.local_summaries.get(&key) {
            return Some(ResolvedSummary {
                source_caps: ls.source_caps,
                sanitizer_caps: ls.sanitizer_caps,
                sink_caps: ls.sink_caps,
                param_to_sink: ls
                    .tainted_sink_params
                    .iter()
                    .map(|&i| (i, ls.sink_caps))
                    .collect(),
                param_to_sink_sites: vec![],
                propagates_taint: !ls.propagating_params.is_empty(),
                propagating_params: ls.propagating_params.clone(),
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
            });
        }
    } else {
        // Multiple same-name local candidates with no disambiguating
        // container hint: refuse to pick one rather than fall through to a
        // less precise global summary that might be the wrong definition.
        let ambiguous_local = transfer
            .local_summaries
            .keys()
            .filter(|k| k.name == normalized && k.lang == transfer.lang)
            .count()
            > 1;
        if ambiguous_local {
            return None;
        }
    }

    // 2) Global same-language
    if let Some(gs) = transfer.global_summaries {
        match gs.resolve_callee(&build_query()) {
            CalleeResolution::Resolved(target_key) => {
                if let Some(fs) = gs.get(&target_key) {
                    return Some(ResolvedSummary {
                        source_caps: fs.source_caps(),
                        sanitizer_caps: fs.sanitizer_caps(),
                        sink_caps: fs.sink_caps(),
                        param_to_sink: fs
                            .tainted_sink_params
                            .iter()
                            .map(|&i| (i, fs.sink_caps()))
                            .collect(),
                        // Phase 1/2: carry [`SinkSite`]s from the global
                        // FuncSummary so cross-file findings can attribute
                        // to the callee-internal dangerous instruction.
                        param_to_sink_sites: fs.param_to_sink.clone(),
                        propagates_taint: fs.propagates_any(),
                        propagating_params: fs.propagating_params.clone(),
                        param_container_to_return: vec![],
                        param_to_container_store: vec![],
                        return_type: None,
                        return_abstract: None,
                        source_to_callback: vec![],

                        receiver_to_return: None,

                        receiver_to_sink: Cap::empty(),

                        abstract_transfer: vec![],
                        param_return_paths: vec![],
                    });
                }
            }
            CalleeResolution::NotFound | CalleeResolution::Ambiguous(_) => {}
        }
    }

    // 3) Interop edges
    for edge in transfer.interop_edges {
        if edge.from.caller_lang == transfer.lang
            && edge.from.caller_namespace == transfer.namespace
            && edge.from.callee_symbol == callee
            && (edge.from.caller_func.is_empty() || edge.from.caller_func == caller_func)
            && (edge.from.ordinal == 0 || edge.from.ordinal == call_ordinal)
            && let Some(gs) = transfer.global_summaries
            && let Some(fs) = gs.get_for_interop(&edge.to)
        {
            return Some(ResolvedSummary {
                source_caps: fs.source_caps(),
                sanitizer_caps: fs.sanitizer_caps(),
                sink_caps: fs.sink_caps(),
                param_to_sink: fs
                    .tainted_sink_params
                    .iter()
                    .map(|&i| (i, fs.sink_caps()))
                    .collect(),
                param_to_sink_sites: fs.param_to_sink.clone(),
                propagates_taint: fs.propagates_any(),
                propagating_params: fs.propagating_params.clone(),
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
            });
        }
    }

    None
}

/// Phase CF-4: compute the effective sanitizer bits that apply at the call
/// site for a specific parameter, narrowed by the caller's predicate state.
///
/// When the resolved summary carries `param_return_paths` for `param_idx`:
/// filter the entries by predicate consistency with the caller's current
/// `SsaTaintState` (`validated_must` + `predicates`).  Compatible entries
/// are joined with the **intersection-of-strip-bits** rule: the caller does
/// not know which return path the callee took, so only bits stripped on
/// EVERY compatible path can be considered cleared.
///
/// Falls back to `resolved.sanitizer_caps` (the aggregate) when:
///   * the summary has no per-path data for this parameter;
///   * every path is predicate-compatible (the narrowing adds no information);
///   * no path is predicate-compatible (conservative: keep aggregate).
fn effective_param_sanitizer(
    resolved: &ResolvedSummary,
    param_idx: usize,
    state: &SsaTaintState,
) -> Cap {
    use crate::summary::ssa_summary::TaintTransform;

    let paths = match resolved
        .param_return_paths
        .iter()
        .find(|(i, _)| *i == param_idx)
    {
        Some((_, p)) => p,
        None => return resolved.sanitizer_caps,
    };

    // Caller-side predicate envelope: union of known_true / known_false bits
    // observed across the caller's tracked variables.  A path is
    // compatible if its required bits (known_true / known_false) do not
    // contradict this envelope.
    let mut caller_kt: u8 = 0;
    let mut caller_kf: u8 = 0;
    for (_, pred) in &state.predicates {
        caller_kt |= pred.known_true;
        caller_kf |= pred.known_false;
    }

    let mut compatible: smallvec::SmallVec<[&_; 2]> = smallvec::SmallVec::new();
    for path in paths {
        // Contradiction tests:
        //   * path demands bit B true while caller has evidence B is false
        //   * path demands bit B false while caller has evidence B is true
        // In either case the caller cannot possibly be on this return path.
        if path.known_true & caller_kf != 0 {
            continue;
        }
        if path.known_false & caller_kt != 0 {
            continue;
        }
        compatible.push(path);
    }

    if compatible.is_empty() {
        // No path applies — the caller's predicate state contradicts every
        // recorded return.  Fall back to the aggregate rather than
        // synthesise a sanitiser from zero data.
        return resolved.sanitizer_caps;
    }

    // Intersection of strip-bits across compatible paths.  Identity
    // contributes the empty set (nothing stripped); AddBits contributes
    // nothing to the sanitiser either.
    let mut common = Cap::all();
    let mut saw_any = false;
    for path in &compatible {
        match &path.transform {
            TaintTransform::StripBits(bits) => {
                common &= *bits;
                saw_any = true;
            }
            TaintTransform::Identity => {
                common = Cap::empty();
                saw_any = true;
            }
            TaintTransform::AddBits(_) => {
                // AddBits doesn't contribute to sanitation; the intersection
                // is still taken over zero strip contribution.
                common = Cap::empty();
                saw_any = true;
            }
        }
    }
    if !saw_any {
        resolved.sanitizer_caps
    } else {
        common
    }
}

/// Convert an `SsaFuncSummary` to the existing `ResolvedSummary` format.
fn convert_ssa_to_resolved(
    ssa_sum: &crate::summary::ssa_summary::SsaFuncSummary,
) -> ResolvedSummary {
    use crate::summary::ssa_summary::TaintTransform;

    let propagating_params: Vec<usize> = ssa_sum
        .param_to_return
        .iter()
        .map(|(idx, _)| *idx)
        .collect();

    // Compute effective sanitizer caps: union of StripBits across all params
    let mut sanitizer_caps = Cap::empty();
    for (_, transform) in &ssa_sum.param_to_return {
        if let TaintTransform::StripBits(bits) = transform {
            sanitizer_caps |= *bits;
        }
    }

    // Compute effective sink caps: union across all params
    let sink_caps = ssa_sum.total_param_sink_caps();
    let param_to_sink = ssa_sum.param_to_sink_caps();
    // Carry the full SinkSite lists through so the taint engine can
    // attribute cross-file findings to the callee-internal sink.  Sites
    // with coordinates of `(0, 0)` (cap-only, no tree/bytes context at
    // extraction time) remain in the list but contribute no primary
    // location — the emission site filters by `SinkSite::line != 0`.
    let param_to_sink_sites = ssa_sum.param_to_sink.clone();

    ResolvedSummary {
        source_caps: ssa_sum.source_caps,
        sanitizer_caps,
        sink_caps,
        param_to_sink,
        param_to_sink_sites,
        propagates_taint: !propagating_params.is_empty(),
        propagating_params,
        param_container_to_return: ssa_sum.param_container_to_return.clone(),
        param_to_container_store: ssa_sum.param_to_container_store.clone(),
        return_type: ssa_sum.return_type.clone(),
        return_abstract: ssa_sum.return_abstract.clone(),
        source_to_callback: ssa_sum.source_to_callback.clone(),
        receiver_to_return: ssa_sum.receiver_to_return.clone(),
        receiver_to_sink: ssa_sum.receiver_to_sink,
        abstract_transfer: ssa_sum.abstract_transfer.clone(),
        param_return_paths: ssa_sum.param_return_paths.clone(),
    }
}

/// BFS distance (in SSA blocks) from the source node's block to the sink
/// node's block.  Returns 0 if same block or if lookup fails.  Capped at 255.
fn block_distance(ssa: &SsaBody, source_node: NodeIndex, sink_node: NodeIndex) -> u16 {
    let src_block = match ssa.cfg_node_map.get(&source_node) {
        Some(v) => ssa.def_of(*v).block,
        None => return 0,
    };
    let sink_block = match ssa.cfg_node_map.get(&sink_node) {
        Some(v) => ssa.def_of(*v).block,
        None => return 0,
    };
    if src_block == sink_block {
        return 0;
    }

    // BFS from src_block to sink_block
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(src_block);
    queue.push_back((src_block, 0u16));

    while let Some((blk, dist)) = queue.pop_front() {
        for &succ in &ssa.block(blk).succs {
            if succ == sink_block {
                return (dist + 1).min(255);
            }
            if visited.insert(succ) && dist + 1 < 255 {
                queue.push_back((succ, dist + 1));
            }
        }
    }
    0 // unreachable or not connected — conservative default
}

// ── Flow Path Reconstruction ─────────────────────────────────────────────

/// Reconstruct the taint flow path from source to sink by walking backward
/// through the SSA def-use chain.
///
/// Returns steps in source→sink order.
fn reconstruct_flow_path(
    tainted_val: SsaValue,
    origin: &crate::taint::domain::TaintOrigin,
    sink_node: NodeIndex,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Vec<crate::taint::FlowStepRaw> {
    use crate::evidence::FlowStepKind;
    use crate::taint::FlowStepRaw;

    const MAX_STEPS: usize = 64;

    let mut steps = Vec::new();
    let mut visited = HashSet::new();

    // 1. Add sink step
    steps.push(FlowStepRaw {
        cfg_node: sink_node,
        var_name: cfg
            .node_weight(sink_node)
            .and_then(|n| n.call.callee.clone()),
        op_kind: FlowStepKind::Sink,
    });

    // 2. Walk backward from tainted_val
    let mut current = tainted_val;
    for _ in 0..MAX_STEPS {
        if !visited.insert(current) {
            break;
        }

        let def = ssa.def_of(current);
        let block = ssa.block(def.block);

        // Find the instruction for this value
        let inst = block
            .phis
            .iter()
            .chain(block.body.iter())
            .find(|i| i.value == current);

        let inst = match inst {
            Some(i) => i,
            None => break,
        };

        // Skip if same cfg_node as previous step (dedup consecutive same-line)
        if let Some(prev) = steps.last() {
            if prev.cfg_node == inst.cfg_node {
                // Still follow the chain, just don't add a duplicate step
                match &inst.op {
                    SsaOp::Source | SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam => {
                        break;
                    }
                    SsaOp::Assign(uses) => {
                        current = pick_tainted_operand(uses, origin, ssa);
                        continue;
                    }
                    SsaOp::Call { args, receiver, .. } => {
                        current = pick_tainted_operand_call(args, receiver, origin, ssa);
                        continue;
                    }
                    SsaOp::Phi(operands) => {
                        let vals: SmallVec<[SsaValue; 4]> =
                            operands.iter().map(|(_, v)| *v).collect();
                        current = pick_tainted_operand(&vals, origin, ssa);
                        continue;
                    }
                    _ => break,
                }
            }
        }

        match &inst.op {
            SsaOp::Source | SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Source,
                });
                break;
            }
            SsaOp::Assign(uses) => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Assignment,
                });
                if uses.is_empty() {
                    break;
                }
                current = pick_tainted_operand(uses, origin, ssa);
            }
            SsaOp::Call { args, receiver, .. } => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Call,
                });
                current = pick_tainted_operand_call(args, receiver, origin, ssa);
            }
            SsaOp::Phi(operands) => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Phi,
                });
                let vals: SmallVec<[SsaValue; 4]> = operands.iter().map(|(_, v)| *v).collect();
                if vals.is_empty() {
                    break;
                }
                current = pick_tainted_operand(&vals, origin, ssa);
            }
            SsaOp::Const(_) | SsaOp::Nop => break,
        }
    }

    // 3. Reverse: was built sink→source, need source→sink
    steps.reverse();
    steps
}

/// Pick the operand whose definition is closest to the origin node (direct match preferred).
fn pick_tainted_operand(
    operands: &[SsaValue],
    origin: &crate::taint::domain::TaintOrigin,
    ssa: &SsaBody,
) -> SsaValue {
    // Prefer operand defined at the origin node
    for &op in operands {
        if ssa.def_of(op).cfg_node == origin.node {
            return op;
        }
    }
    // Fallback: pick first (heuristic)
    operands.first().copied().unwrap_or(SsaValue(0))
}

/// Pick tainted operand for Call instructions (flatten args + receiver).
fn pick_tainted_operand_call(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    origin: &crate::taint::domain::TaintOrigin,
    ssa: &SsaBody,
) -> SsaValue {
    let mut all_vals: SmallVec<[SsaValue; 8]> = SmallVec::new();
    for arg in args {
        all_vals.extend_from_slice(arg);
    }
    if let Some(r) = receiver {
        all_vals.push(*r);
    }
    pick_tainted_operand(&all_vals, origin, ssa)
}

/// Convert SSA taint events to the standard Finding struct.
///
/// # Invariants enforced by debug_assert!
///
/// The `primary_location` field carries Phase 2's primary sink-location
/// attribution.  One invariant must hold across every emitted Finding:
///
/// * A populated `primary_location` implies the attribution came from a
///   [`SinkSite`] with resolved coordinates (`line != 0` AND `file_rel`
///   non-empty).  Cap-only sites are filtered to `None` here; they never
///   reach downstream formatters claiming a `(0, 0)` origin.
///
/// Note: this invariant is intentionally independent of `uses_summary`.
/// The taint-chain flag tracks summary-propagated *taint*, not summary-
/// resolved *sinks* — a local source can reach a cross-file sink, so
/// `primary_location.is_some()` does not imply `uses_summary == true`.
pub fn ssa_events_to_findings(
    events: &[SsaTaintEvent],
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Vec<crate::taint::Finding> {
    use std::collections::HashSet;

    type FindingDedupKey = (usize, usize, Option<(String, u32, u32)>);
    let mut findings = Vec::new();
    let mut seen: HashSet<FindingDedupKey> = HashSet::new();

    for event in events {
        // Suppress findings where all tainted variables were validated
        // (passed through an allowlist, type-check, or validation branch).
        if event.all_validated {
            continue;
        }

        let primary_location = event.primary_sink_site.as_ref().and_then(|s| {
            // Only promote to a Finding.primary_location when the site has
            // resolved coordinates (cap-only sites at (0, 0) carry no
            // attribution and would just add noise).
            if s.line == 0 {
                None
            } else {
                Some(crate::taint::SinkLocation {
                    file_rel: s.file_rel.clone(),
                    line: s.line,
                    col: s.col,
                    snippet: s.snippet.clone(),
                })
            }
        });

        // Data-integrity invariant: a populated primary_location must at least
        // carry resolved line coordinates.  `file_rel` may legitimately be
        // empty — when the scan root is the caller file itself (single-file
        // scans), every namespace normalizes to `""` and the callee's site
        // inherits that empty path; consumers resolve it against the file
        // under analysis.  Line==0 is the only filter-worthy invariant.
        debug_assert!(
            primary_location.as_ref().is_none_or(|l| l.line != 0),
            "primary_location must carry a resolved line coordinate",
        );

        // Dedup key includes primary location so multi-site events that
        // share a single (source, sink) pair still produce distinct findings
        // — one per resolved callee-internal site.
        let loc_key = primary_location
            .as_ref()
            .map(|l| (l.file_rel.clone(), l.line, l.col));
        for (val, caps, origins) in &event.tainted_values {
            let cap_specificity = (*caps & event.sink_caps).bits().count_ones() as u8;
            for origin in origins {
                if seen.insert((
                    origin.node.index(),
                    event.sink_node.index(),
                    loc_key.clone(),
                )) {
                    let hop_count = block_distance(ssa, origin.node, event.sink_node);
                    let flow_steps = reconstruct_flow_path(*val, origin, event.sink_node, ssa, cfg);
                    findings.push(crate::taint::Finding {
                        body_id: crate::cfg::BodyId(0), // set by caller
                        sink: event.sink_node,
                        source: origin.node,
                        path: vec![origin.node, event.sink_node],
                        source_kind: origin.source_kind,
                        path_validated: event.all_validated,
                        guard_kind: event.guard_kind,
                        hop_count,
                        cap_specificity,
                        uses_summary: event.uses_summary,
                        flow_steps,
                        symbolic: None,
                        source_span: origin.source_span.map(|(start, _)| start),
                        primary_location: primary_location.clone(),
                    });
                }
            }
        }
    }

    findings
}

// ── SSA Function Summary Extraction ──────────────────────────────────────

/// Given an SSA taint event at a sink, find which argument positions of the
/// sink call instruction were tainted.
fn extract_sink_arg_positions(event: &SsaTaintEvent, ssa: &SsaBody) -> Vec<usize> {
    let ssa_val = match ssa.cfg_node_map.get(&event.sink_node) {
        Some(v) => *v,
        None => return vec![],
    };

    let def = ssa.def_of(ssa_val);
    let block = &ssa.blocks[def.block.0 as usize];

    let inst = block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|i| i.value == ssa_val);

    let inst = match inst {
        Some(i) => i,
        None => return vec![],
    };

    if let SsaOp::Call { args, .. } = &inst.op {
        let tainted_vals: HashSet<SsaValue> =
            event.tainted_values.iter().map(|(v, _, _)| *v).collect();

        let mut positions = Vec::new();
        for (i, arg_vals) in args.iter().enumerate() {
            if arg_vals.iter().any(|v| tainted_vals.contains(v)) {
                positions.push(i);
            }
        }
        positions
    } else {
        vec![]
    }
}

/// Maximum number of parameters to probe for summary extraction.
/// Functions with more params fall back to legacy `FuncSummary`.
const MAX_PROBE_PARAMS: usize = 8;

/// Extract a precise per-parameter `SsaFuncSummary` from an already-lowered SSA body.
///
/// For each parameter (up to [`MAX_PROBE_PARAMS`]), runs a taint probe by seeding
/// that parameter with `Cap::all()` via `global_seed` and observing what caps
/// survive to return positions and which sinks fire.  A final probe with no params
/// tainted detects intrinsic source caps.
#[allow(clippy::too_many_arguments)]
pub fn extract_ssa_func_summary(
    ssa: &SsaBody,
    cfg: &Cfg,
    local_summaries: &crate::cfg::FuncSummaries,
    global_summaries: Option<&crate::summary::GlobalSummaries>,
    lang: Lang,
    namespace: &str,
    interner: &crate::state::symbol::SymbolInterner,
    param_count: usize,
    module_aliases: Option<&HashMap<SsaValue, smallvec::SmallVec<[String; 2]>>>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
) -> crate::summary::ssa_summary::SsaFuncSummary {
    use crate::summary::SinkSite;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let effective_params = param_count.min(MAX_PROBE_PARAMS);

    // Collect (param_index, var_name, ssa_value) from the SSA body
    let mut param_info: Vec<(usize, String, SsaValue)> = Vec::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = &inst.op {
                if *index < effective_params {
                    if let Some(name) = inst.var_name.as_ref() {
                        param_info.push((*index, name.clone(), inst.value));
                    }
                }
            }
        }
    }

    // Identify return-reaching blocks
    let return_blocks: Vec<usize> = ssa
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b.terminator, Terminator::Return(_)))
        .map(|(i, _)| i)
        .collect();

    // Collect all param SSA values to exclude from return cap collection.
    // Param values persist with their seeded taint throughout the function —
    // we only want caps on derived values (call results, assigns) at return.
    let all_param_values: std::collections::HashSet<SsaValue> =
        param_info.iter().map(|(_, _, v)| *v).collect();

    // Phase CF-4: per-return-block observation captured alongside the
    // aggregate return caps.  Each entry records one return block's exit
    // state — caps contributed on that path, path-predicate hash,
    // known_true/false bits, and the return SSA value's abstract fact —
    // so the per-param loop can emit one [`ReturnPathTransform`] per
    // distinct predicate gate.
    struct ReturnBlockObs {
        /// Caps at the return SSA value (or joined live values for
        /// implicit returns) on this block's exit.
        derived_caps: Cap,
        /// Caps collected from parameter values reaching this return
        /// (passthrough fallback).
        param_caps: Cap,
        /// Deterministic hash of the predicate gate at this return.
        /// `0` means "no predicate gate" — an unguarded return.
        predicate_hash: u64,
        /// `PredicateSummary::known_true` bits intersected across all
        /// tracked variables at this return.  Encoded via
        /// [`predicate_kind_bit`].
        known_true: u8,
        /// `PredicateSummary::known_false` bits at this return.
        known_false: u8,
        /// Abstract fact on the return SSA value at this return (None
        /// when Top or abstract interp disabled).
        abstract_value: Option<crate::abstract_interp::AbstractValue>,
    }

    // Helper: run a taint probe with a given global_seed and return
    // the aggregate return caps, sink events, joined return abstract,
    // and the per-return-block observation list used by CF-4 to derive
    // per-return-path transforms.
    let run_probe = |seed: HashMap<BindingKey, VarTaint>| -> (
        Cap,
        Vec<SsaTaintEvent>,
        Option<crate::abstract_interp::AbstractValue>,
        Vec<ReturnBlockObs>,
    ) {
        let seed_ref = if seed.is_empty() { None } else { Some(&seed) };
        let transfer = SsaTaintTransfer {
            lang,
            namespace,
            interner,
            local_summaries,
            global_summaries,
            interop_edges: &[],
            global_seed: seed_ref,
            const_values: None,
            type_facts: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
        };

        let (events, block_states) = run_ssa_taint_full(ssa, cfg, &transfer);

        // Collect surviving caps at return blocks.
        // Separate param values from derived values: derived values give
        // more precise transforms (they reflect function-internal sanitization).
        // If only param values reach return → pure passthrough (Identity).
        let mut total_derived_caps = Cap::empty();
        let mut total_param_caps = Cap::empty();
        // Extract abstract value of the return SSA value.
        let mut return_abstract: Option<crate::abstract_interp::AbstractValue> = None;
        // Phase CF-4: per-return-block observations for per-path transforms.
        let mut per_return: Vec<ReturnBlockObs> = Vec::with_capacity(return_blocks.len());
        for &bid in &return_blocks {
            if let Some(entry) = &block_states[bid] {
                let empty_induction = HashSet::new();
                let exit = transfer_block(
                    &ssa.blocks[bid],
                    cfg,
                    ssa,
                    &transfer,
                    entry.clone(),
                    &empty_induction,
                    None,
                );

                let ret_val = match &ssa.blocks[bid].terminator {
                    Terminator::Return(rv) => rv.as_ref().copied(),
                    _ => None,
                };

                let mut block_derived_caps = Cap::empty();
                let mut block_param_caps = Cap::empty();

                if let Some(rv) = ret_val {
                    // Explicit return value: use only its taint for derived_caps.
                    // If rv has no taint entry, this block contributes no derived caps.
                    if let Some(taint) = exit.get(rv) {
                        if all_param_values.contains(&rv) {
                            block_param_caps |= taint.caps;
                        } else {
                            block_derived_caps |= taint.caps;
                        }
                    }
                    // When rv is not a param value, also collect param taint as a
                    // fallback. The SSA terminator's rv may point to the last body
                    // instruction (e.g. push/append result) rather than the actual
                    // return expression (the container parameter itself). This fires
                    // both when rv is tainted (derived) and when rv is untainted
                    // (the push result may have no taint but the param does).
                    // Skip when rv IS a param (already handled above) or when rv is
                    // a Const (provably untainted constant return).
                    let rv_is_const = ssa.blocks[bid]
                        .body
                        .iter()
                        .chain(ssa.blocks[bid].phis.iter())
                        .any(|inst| inst.value == rv && matches!(inst.op, SsaOp::Const(_)));
                    if !all_param_values.contains(&rv) && !rv_is_const {
                        for (val, taint) in &exit.values {
                            if all_param_values.contains(val) {
                                block_param_caps |= taint.caps;
                            }
                        }
                    }
                } else {
                    // Return(None): implicit return — fall back to all live values.
                    for (val, taint) in &exit.values {
                        if all_param_values.contains(val) {
                            block_param_caps |= taint.caps;
                        } else {
                            block_derived_caps |= taint.caps;
                        }
                    }
                }

                total_derived_caps |= block_derived_caps;
                total_param_caps |= block_param_caps;

                // Abstract return: use terminator's return value when available,
                // fall back to last instruction heuristic for Return(None).
                let mut block_abs: Option<crate::abstract_interp::AbstractValue> = None;
                if let Some(ref abs) = exit.abstract_state {
                    let abs_rv = ret_val.or_else(|| {
                        ssa.blocks[bid]
                            .body
                            .last()
                            .or_else(|| ssa.blocks[bid].phis.last())
                            .map(|inst| inst.value)
                    });
                    if let Some(rv) = abs_rv {
                        let av = abs.get(rv);
                        if !av.is_top() {
                            block_abs = Some(av.clone());
                            return_abstract = Some(match return_abstract {
                                None => av,
                                Some(prev) => prev.join(&av),
                            });
                        }
                    }
                }

                // Phase CF-4: derive a predicate hash + known-true/false
                // intersection across tracked variables at this return.
                // The hash is stable across runs for a given predicate
                // shape so call sites can compare paths deterministically.
                let (predicate_hash, known_true, known_false) = summarise_return_predicates(&exit);
                per_return.push(ReturnBlockObs {
                    derived_caps: block_derived_caps,
                    param_caps: block_param_caps,
                    predicate_hash,
                    known_true,
                    known_false,
                    abstract_value: block_abs,
                });
            }
        }

        // Prefer derived caps; fall back to param caps for passthrough functions
        let return_caps = if !total_derived_caps.is_empty() {
            total_derived_caps
        } else {
            total_param_caps
        };

        // Drop return_abstract if it joined to Top
        let return_abstract = return_abstract.filter(|v| !v.is_top());

        (return_caps, events, return_abstract, per_return)
    };

    // Probe with no params tainted → detect source_caps + return abstract.
    // Abstract values don't depend on taint seeding, so the baseline probe
    // captures the function's intrinsic abstract return value.
    let (baseline_return_caps, _baseline_events, return_abstract, _baseline_obs) =
        run_probe(HashMap::new());
    let source_caps = baseline_return_caps;

    // Probe each param
    let mut param_to_return = Vec::new();
    let mut param_to_sink: Vec<(usize, SmallVec<[SinkSite; 1]>)> = Vec::new();
    let mut param_to_sink_param = Vec::new();
    // Phase CF-4: per-param return-path decomposition.  Populated only
    // when the param has ≥2 distinct return-block predicate hashes —
    // a single-return-path callee is already precise via `param_to_return`.
    let mut param_return_paths: Vec<(
        usize,
        SmallVec<[crate::summary::ssa_summary::ReturnPathTransform; 2]>,
    )> = Vec::new();

    for &(idx, ref var_name, _ssa_val) in &param_info {
        let mut seed = HashMap::new();
        let origin = TaintOrigin {
            node: NodeIndex::new(0), // synthetic origin for probing
            source_kind: SourceKind::UserInput,
            source_span: None,
        };
        seed.insert(
            BindingKey::new(var_name.as_str()),
            VarTaint {
                caps: Cap::all(),
                origins: SmallVec::from_elem(origin, 1),
                uses_summary: false,
            },
        );

        let (return_caps, events, _, per_return_obs) = run_probe(seed);

        // Subtract baseline source_caps — we only want param-contributed caps
        let param_return_caps = return_caps & !source_caps;

        if !param_return_caps.is_empty() {
            let stripped = Cap::all() & !param_return_caps;
            let transform = if stripped.is_empty() {
                TaintTransform::Identity
            } else {
                TaintTransform::StripBits(stripped)
            };
            param_to_return.push((idx, transform));
        }

        // Phase CF-4: derive per-return-path decomposition.  For each
        // observed return block, derive a `ReturnPathTransform` mirroring
        // the aggregate logic (prefer derived caps, fall back to param
        // caps, strip baseline source caps).  Only emit when ≥2 distinct
        // predicate hashes are present — a single-hash summary adds no
        // signal over the aggregate `param_to_return`.
        if per_return_obs.len() >= 2 {
            let mut per_path: SmallVec<[crate::summary::ssa_summary::ReturnPathTransform; 2]> =
                SmallVec::new();
            for obs in &per_return_obs {
                let block_return_caps = if !obs.derived_caps.is_empty() {
                    obs.derived_caps
                } else {
                    obs.param_caps
                };
                let block_contributed = block_return_caps & !source_caps;
                let transform_kind = if block_contributed.is_empty() {
                    // No caps on this path — param does not reach return
                    // under this predicate.  A `StripBits(all)` records
                    // "all bits cleared" so downstream join preserves the
                    // disparity with other paths.
                    TaintTransform::StripBits(Cap::all())
                } else {
                    let stripped = Cap::all() & !block_contributed;
                    if stripped.is_empty() {
                        TaintTransform::Identity
                    } else {
                        TaintTransform::StripBits(stripped)
                    }
                };
                crate::summary::ssa_summary::merge_return_paths(
                    &mut per_path,
                    &[crate::summary::ssa_summary::ReturnPathTransform {
                        transform: transform_kind,
                        path_predicate_hash: obs.predicate_hash,
                        known_true: obs.known_true,
                        known_false: obs.known_false,
                        abstract_contribution: obs.abstract_value.clone(),
                    }],
                );
            }
            // Only record when ≥2 distinct predicate gates survived
            // the dedup (a single-entry vector is no finer than the
            // aggregate `param_to_return` and wastes bytes on disk).
            let distinct_hashes = per_path
                .iter()
                .map(|e| e.path_predicate_hash)
                .collect::<std::collections::HashSet<_>>();
            if distinct_hashes.len() >= 2 {
                param_return_paths.push((idx, per_path));
            }
        }

        // Collect sink caps + primary-location sites from events + per-arg-position detail
        let mut param_sites: SmallVec<[SinkSite; 1]> = SmallVec::new();
        for event in &events {
            for pos in extract_sink_arg_positions(event, ssa) {
                param_to_sink_param.push((idx, pos, event.sink_caps));
            }
            if event.sink_caps.is_empty() {
                continue;
            }
            let site = match locator {
                Some(loc) => {
                    loc.site_for_span(cfg[event.sink_node].classification_span(), event.sink_caps)
                }
                None => SinkSite::cap_only(event.sink_caps),
            };
            let key = site.dedup_key();
            if !param_sites.iter().any(|s| s.dedup_key() == key) {
                param_sites.push(site);
            }
        }
        if !param_sites.is_empty() {
            param_to_sink.push((idx, param_sites));
        }
    }

    let (param_container_to_return, param_to_container_store) =
        extract_container_flow_summary(ssa, lang, effective_params);

    // Infer return type: scan return-reaching blocks for constructor calls.
    let return_type = infer_summary_return_type(ssa, lang);

    // Detect source_to_callback: internal source taint flowing to calls of
    // parameter functions (e.g., `fn apply(f) { let x = source(); f(x); }`).
    // Re-runs the baseline probe internally to get accurate taint state.
    let source_to_callback = if !source_caps.is_empty() && !param_info.is_empty() {
        let baseline_transfer = SsaTaintTransfer {
            lang,
            namespace,
            interner,
            local_summaries,
            global_summaries,
            interop_edges: &[],
            global_seed: None,
            const_values: None,
            type_facts: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
        };
        detect_source_to_callback_from_states(
            ssa,
            cfg,
            source_caps,
            &param_info,
            &baseline_transfer,
        )
    } else {
        vec![]
    };

    // Phase CF-3: per-parameter abstract-domain transfers.
    //
    // Derived structurally from the SSA body — no additional taint probes.
    // Three-step inference per parameter:
    //   1. Identity: return SSA value at every return block traces back to
    //      this parameter (possibly through assigns / phi merges all feeding
    //      from the same param).
    //   2. Callee-intrinsic bound: baseline `return_abstract` carries a
    //      concrete fact (bounded interval or known prefix) that holds
    //      regardless of caller input — record it once per parameter as
    //      `Clamped` / `LiteralPrefix` so the caller sees the bound even
    //      when it has no abstract info on its own argument.
    //   3. Top: default; the entry is omitted (empty transfer is meaningless).
    let abstract_transfer = derive_abstract_transfer(ssa, &param_info, return_abstract.as_ref());

    SsaFuncSummary {
        param_to_return,
        param_to_sink,
        source_caps,
        param_to_sink_param,
        param_container_to_return,
        param_to_container_store,
        return_type,
        return_abstract,
        source_to_callback,
        receiver_to_return: None,
        receiver_to_sink: Cap::empty(),
        abstract_transfer,
        param_return_paths,
    }
}

/// Phase CF-4: derive a deterministic predicate-hash + known-true/false
/// intersection for a return-block exit state.
///
/// The hash combines the sorted `(SymbolId, known_true, known_false)` tuples
/// from the state's `predicates` list with the validated_must bitmask.  Two
/// return blocks whose predicate gates are observationally identical produce
/// the same hash; the intersection of known_true/false gives the bits that
/// hold on every path into each return block.
///
/// Returns `(0, 0, 0)` for a Top state (no predicates tracked).
fn summarise_return_predicates(state: &SsaTaintState) -> (u64, u8, u8) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    if state.predicates.is_empty() && state.validated_must.is_empty() {
        return (0, 0, 0);
    }

    let mut h = DefaultHasher::new();
    // Validated-must contributes deterministically via bits().
    state.validated_must.bits().hash(&mut h);
    // Sort by SymbolId (predicates list is already sorted by SsaTaintState
    // invariants, but hash-input stability matters here).
    let mut sorted: smallvec::SmallVec<[(u32, u8, u8); 4]> = state
        .predicates
        .iter()
        .map(|(id, s)| (id.0, s.known_true, s.known_false))
        .collect();
    sorted.sort_by_key(|(id, _, _)| *id);
    for (id, kt, kf) in &sorted {
        id.hash(&mut h);
        kt.hash(&mut h);
        kf.hash(&mut h);
    }
    let hash = h.finish();
    // Intersect known_true / known_false across all tracked variables:
    // the bits that hold for EVERY predicate-tracked var at this return.
    let known_true = sorted
        .iter()
        .map(|(_, kt, _)| *kt)
        .fold(u8::MAX, |a, b| a & b);
    let known_false = sorted
        .iter()
        .map(|(_, _, kf)| *kf)
        .fold(u8::MAX, |a, b| a & b);
    // Use `1` for the "no predicates but validated_must non-empty" case to
    // avoid colliding with the unguarded sentinel (0).
    let hash = if hash == 0 { 1 } else { hash };
    (hash, known_true, known_false)
}

/// Phase CF-3: Derive per-parameter [`AbstractTransfer`] entries for a
/// function's SSA body.
///
/// `return_abstract` is the callee's intrinsic baseline (from the no-seed
/// probe).  When present, it describes a fact that holds for the return
/// regardless of parameter input — so it can be attached as a
/// `Clamped` / `LiteralPrefix` transform to every parameter that flows to
/// the return.
///
/// Identity detection is structural: walk the return values back through
/// [`SsaOp::Assign`] / [`SsaOp::Phi`] chains (bounded) and check whether
/// every leaf resolves to the same [`SsaOp::Param`].  The trace is cheap
/// and can only produce `Identity` for passthrough callees — anything
/// more complex degrades to the baseline fact or `Top`.
fn derive_abstract_transfer(
    ssa: &SsaBody,
    param_info: &[(usize, String, SsaValue)],
    return_abstract: Option<&crate::abstract_interp::AbstractValue>,
) -> Vec<(usize, crate::abstract_interp::AbstractTransfer)> {
    use crate::abstract_interp::{AbstractTransfer, IntervalTransfer, StringTransfer};

    if param_info.is_empty() {
        return Vec::new();
    }

    // Build a lookup from SsaValue → defining op by scanning the body once.
    let mut defs: HashMap<SsaValue, &SsaOp> = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            defs.insert(inst.value, &inst.op);
        }
    }

    // Trace an SSA value backwards to the single source parameter index it
    // resolves to, if any.  Returns `None` when the trace diverges, hits a
    // non-pass-through op, or exceeds the depth bound.
    fn trace_to_param(
        v: SsaValue,
        defs: &HashMap<SsaValue, &SsaOp>,
        depth: usize,
    ) -> Option<usize> {
        const MAX_DEPTH: usize = 8;
        if depth > MAX_DEPTH {
            return None;
        }
        match defs.get(&v)? {
            SsaOp::Param { index } => Some(*index),
            SsaOp::Assign(ops) if ops.len() == 1 => trace_to_param(ops[0], defs, depth + 1),
            SsaOp::Phi(preds) => {
                let mut result: Option<usize> = None;
                for (_, pv) in preds {
                    let p = trace_to_param(*pv, defs, depth + 1)?;
                    match result {
                        None => result = Some(p),
                        Some(existing) if existing == p => {}
                        Some(_) => return None,
                    }
                }
                result
            }
            _ => None,
        }
    }

    // For every return block, trace its return value and record which
    // parameter (if any) it resolves to.  If all return blocks agree on the
    // same parameter index, that parameter has `Identity`.  If they disagree
    // (or some don't resolve), no parameter gets `Identity` and we fall
    // back to baseline-derived forms.
    let mut identity_param: Option<usize> = None;
    let mut identity_consistent = true;
    for block in &ssa.blocks {
        if let Terminator::Return(Some(rv)) = &block.terminator {
            let traced = trace_to_param(*rv, &defs, 0);
            match (identity_param, traced) {
                (None, Some(p)) => identity_param = Some(p),
                (Some(existing), Some(p)) if existing == p => {}
                _ => {
                    identity_consistent = false;
                    break;
                }
            }
        }
    }

    // Derive a baseline-invariant transform from `return_abstract`.  This is
    // the "callee intrinsic" fact that always holds — each parameter that
    // flows to the return gets it attached as the conservative transfer.
    let baseline_invariant: Option<AbstractTransfer> = return_abstract.map(|av| {
        let interval = match (av.interval.lo, av.interval.hi) {
            (Some(lo), Some(hi)) if lo <= hi => IntervalTransfer::Clamped { lo, hi },
            _ => IntervalTransfer::Top,
        };
        let string = match &av.string.prefix {
            Some(p) if !p.is_empty() => StringTransfer::literal_prefix(p),
            _ => StringTransfer::Unknown,
        };
        AbstractTransfer { interval, string }
    });

    let mut result: Vec<(usize, AbstractTransfer)> = Vec::new();

    for (idx, _, _) in param_info {
        let mut transfer = AbstractTransfer::top();

        if identity_consistent && identity_param == Some(*idx) {
            transfer.interval = IntervalTransfer::Identity;
            transfer.string = StringTransfer::Identity;
        } else if let Some(base) = baseline_invariant.as_ref() {
            // Baseline intrinsic bound applies to every parameter that could
            // reach the return.  We conservatively attach it to all params
            // — at apply time the caller meets it with the real return
            // abstract (also from this same summary), so double-counting
            // would collapse to the tighter of the two.
            transfer = base.clone();
        }

        if !transfer.is_top() {
            result.push((*idx, transfer));
        }
    }

    result
}

/// Detect callback patterns where internal source taint flows to a call of a
/// parameter function. Re-runs the baseline probe internally to get accurate
/// taint state at each instruction point.
///
/// Returns `(param_index_of_callee, source_caps)` pairs.
fn detect_source_to_callback_from_states(
    ssa: &SsaBody,
    cfg: &Cfg,
    source_caps: Cap,
    param_info: &[(usize, String, SsaValue)],
    transfer: &SsaTaintTransfer,
) -> Vec<(usize, Cap)> {
    use crate::ssa::ir::SsaOp;

    // Map param var_name → param_index
    let param_name_to_index: HashMap<&str, usize> = param_info
        .iter()
        .map(|(idx, name, _)| (name.as_str(), *idx))
        .collect();

    // Run taint analysis to get converged block states
    let (_events, block_states) = run_ssa_taint_full(ssa, cfg, transfer);

    let mut result: Vec<(usize, Cap)> = vec![];
    for (bid, block) in ssa.blocks.iter().enumerate() {
        let Some(entry_state) = &block_states[bid] else {
            continue;
        };
        // Replay block transfer to get accurate taint state at each instruction
        let mut state = entry_state.clone();
        for inst in &block.body {
            // Apply transfer for this instruction to advance state
            transfer_inst(inst, cfg, ssa, transfer, &mut state);

            // After transfer: check if this is a call to a param with tainted args
            if let SsaOp::Call { callee, args, .. } = &inst.op {
                if let Some(&param_idx) = param_name_to_index.get(callee.as_str()) {
                    let any_arg_tainted = args.iter().any(|arg_vals| {
                        arg_vals
                            .iter()
                            .any(|v| state.get(*v).is_some_and(|t| !t.caps.is_empty()))
                    });
                    if any_arg_tainted && !result.iter().any(|(idx, _)| *idx == param_idx) {
                        result.push((param_idx, source_caps));
                    }
                }
            }
        }
    }

    result
}

/// Infer the return type of a function from its SSA body by checking whether
/// return-reaching blocks produce values from known constructor/factory calls.
fn infer_summary_return_type(
    ssa: &SsaBody,
    lang: Lang,
) -> Option<crate::ssa::type_facts::TypeKind> {
    use crate::ssa::ir::Terminator;

    // Find blocks with Return terminators, then look at the last defined value
    // in those blocks — if it's a Call with a known constructor, that's our type.
    for block in &ssa.blocks {
        if !matches!(block.terminator, Terminator::Return(_)) {
            continue;
        }
        // Only inspect the very last instruction in the returning block.
        if let Some(inst) = block.body.last()
            && let SsaOp::Call { callee, .. } = &inst.op
            && let Some(ty) = crate::ssa::type_facts::constructor_type(lang, callee)
        {
            return Some(ty);
        }
    }
    None
}

// ── Inter-procedural container flow detection (structural SSA analysis) ──

/// Build a map from SsaValue to its defining instruction.
fn build_inst_map(ssa: &SsaBody) -> HashMap<SsaValue, (SsaOp, Option<SsaValue>)> {
    let mut map = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            // Store the op and optionally the receiver for calls
            map.insert(inst.value, (inst.op.clone(), None));
        }
    }
    map
}

/// Trace an SSA value back through Assign/Phi chains to find if it originates
/// from a `Param { index }`. Returns `Some(index)` if a param is found.
/// Does NOT trace through Call, Const, Source, or other non-identity ops.
fn trace_to_param(
    v: SsaValue,
    ssa: &SsaBody,
    inst_map: &HashMap<SsaValue, (SsaOp, Option<SsaValue>)>,
    visited: &mut HashSet<SsaValue>,
) -> Option<usize> {
    if !visited.insert(v) {
        return None;
    }
    let (op, _) = inst_map.get(&v)?;
    match op {
        SsaOp::Param { index } => Some(*index),
        SsaOp::Assign(uses) => {
            for u in uses {
                if let Some(idx) = trace_to_param(*u, ssa, inst_map, visited) {
                    return Some(idx);
                }
            }
            None
        }
        SsaOp::Phi(operands) => {
            for (_, op_val) in operands {
                if let Some(idx) = trace_to_param(*op_val, ssa, inst_map, visited) {
                    return Some(idx);
                }
            }
            None
        }
        // Don't trace through Call (new identity), Const, Source, Nop, CatchParam
        _ => None,
    }
}

/// Detect inter-procedural container flow patterns from SSA structure:
/// - `param_container_to_return`: params whose container identity flows to return
/// - `param_to_container_store`: (src_param, container_param) pairs where src taint
///   is stored into container_param's contents
pub(crate) fn extract_container_flow_summary(
    ssa: &SsaBody,
    lang: Lang,
    formal_param_count: usize,
) -> (Vec<usize>, Vec<(usize, usize)>) {
    use crate::ssa::pointsto::{ContainerOp, classify_container_op};

    let inst_map = build_inst_map(ssa);
    let mut container_to_return: HashSet<usize> = HashSet::new();
    let mut container_store: Vec<(usize, usize)> = Vec::new();

    // 1. param_container_to_return: trace Assign/Phi ops in return blocks to params.
    //
    // `trace_to_param` will happily return any `SsaOp::Param { index }`, but
    // scoped lowering synthesises `Param` ops for external captures (module
    // imports, free identifiers) at indices beyond the formal parameter count.
    // Those must not enter the summary — the key's arity only covers formal
    // params, and an out-of-range index trips `ssa_summary_fits_arity`, forcing
    // the reconciliation probe to generate a synthetic disambiguator that no
    // caller will ever look up.
    for block in &ssa.blocks {
        if !matches!(block.terminator, Terminator::Return(_)) {
            continue;
        }
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                // Only trace identity-preserving ops (Assign, Phi).
                // Skip Param (would cause false positives in single-block functions),
                // Call (new identity), Const, Source, Nop, CatchParam.
                SsaOp::Assign(_) | SsaOp::Phi(_) => {
                    if let Some(idx) =
                        trace_to_param(inst.value, ssa, &inst_map, &mut HashSet::new())
                        && idx < formal_param_count
                    {
                        container_to_return.insert(idx);
                    }
                }
                _ => {}
            }
        }
    }

    // 2. param_to_container_store: find container Store calls, trace args to params
    for block in &ssa.blocks {
        for inst in block.body.iter() {
            if let SsaOp::Call {
                callee,
                args,
                receiver,
            } = &inst.op
            {
                let op = match classify_container_op(callee, lang) {
                    Some(ContainerOp::Store { value_args, .. }) => value_args,
                    _ => continue,
                };

                // Resolve container SSA value.  With the new call ABI, the
                // receiver is a separate channel and `args` contains only
                // positional arguments.  For Go, container ops are plain
                // function calls (no receiver), so args[0] is the container.
                let container_val = if let Some(v) = *receiver {
                    Some(v)
                } else if lang == Lang::Go {
                    args.first().and_then(|a| a.first().copied())
                } else if let Some(dot_pos) = callee.rfind('.') {
                    let receiver_name = &callee[..dot_pos];
                    args.iter()
                        .flat_map(|a| a.iter())
                        .find(|&&v| {
                            ssa.value_defs
                                .get(v.0 as usize)
                                .and_then(|d| d.var_name.as_deref())
                                == Some(receiver_name)
                        })
                        .copied()
                } else {
                    None
                };

                let container_val = match container_val {
                    Some(v) => v,
                    None => continue,
                };

                // Trace container to positional param (SelfParam → None, so
                // when the container is the receiver we skip — the caller
                // tracks that via `receiver_to_container_store` if needed).
                // Same arity filter as above: reject synthetic Param ops that
                // were injected for free captures.
                let container_param =
                    match trace_to_param(container_val, ssa, &inst_map, &mut HashSet::new()) {
                        Some(idx) if idx < formal_param_count => idx,
                        _ => continue,
                    };

                // Go container ops are plain function calls with the container
                // at args[0]; value args start at args[1].  Other languages
                // place the container on the receiver channel so args holds
                // only value args starting at index 0.
                let arg_offset = if lang == Lang::Go && receiver.is_none() {
                    1usize
                } else {
                    0
                };

                // Trace each value arg to param (same arity filter as above).
                for &va_idx in &op {
                    let effective_idx = va_idx + arg_offset;
                    if let Some(arg_vals) = args.get(effective_idx) {
                        for &av in arg_vals {
                            if let Some(src_param) =
                                trace_to_param(av, ssa, &inst_map, &mut HashSet::new())
                                && src_param < formal_param_count
                                && src_param != container_param
                                && !container_store.contains(&(src_param, container_param))
                            {
                                container_store.push((src_param, container_param));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut ctr: Vec<usize> = container_to_return.into_iter().collect();
    ctr.sort();
    container_store.sort();
    (ctr, container_store)
}

// ── Phase 30: populate_node_meta + CrossFileNodeMeta tests ───────────────

#[cfg(test)]
mod cross_file_tests {
    use super::*;
    use crate::cfg::{AstMeta, BinOp, CallMeta, EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::DataLabel;

    use petgraph::prelude::*;
    use smallvec::smallvec;

    fn make_test_cfg() -> crate::cfg::Cfg {
        let mut cfg = Graph::new();
        let n0 = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(crate::labels::Cap::all())],
                defines: Some("x".into()),
                ..Default::default()
            },
            call: CallMeta::default(),
            bin_op: Some(BinOp::Add),
            ..Default::default()
        });
        let n1 = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (10, 20),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("y".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        cfg.add_edge(n0, n1, EdgeKind::Seq);
        cfg
    }

    fn make_body_referencing_nodes(n0: NodeIndex, n1: NodeIndex) -> CalleeSsaBody {
        CalleeSsaBody {
            ssa: SsaBody {
                blocks: vec![SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![
                        SsaInst {
                            value: SsaValue(0),
                            op: SsaOp::Source,
                            cfg_node: n0,
                            var_name: Some("x".into()),
                            span: (0, 5),
                        },
                        SsaInst {
                            value: SsaValue(1),
                            op: SsaOp::Assign(smallvec![SsaValue(0)]),
                            cfg_node: n1,
                            var_name: Some("y".into()),
                            span: (5, 10),
                        },
                    ],
                    terminator: Terminator::Return(Some(SsaValue(1))),
                    preds: smallvec![],
                    succs: smallvec![],
                }],
                entry: BlockId(0),
                value_defs: vec![
                    ValueDef {
                        var_name: Some("x".into()),
                        cfg_node: n0,
                        block: BlockId(0),
                    },
                    ValueDef {
                        var_name: Some("y".into()),
                        cfg_node: n1,
                        block: BlockId(0),
                    },
                ],
                cfg_node_map: std::collections::HashMap::new(),
                exception_edges: vec![],
            },
            opt: crate::ssa::OptimizeResult {
                const_values: std::collections::HashMap::new(),
                type_facts: crate::ssa::type_facts::TypeFactResult {
                    facts: std::collections::HashMap::new(),
                },
                alias_result: crate::ssa::alias::BaseAliasResult::empty(),
                points_to: crate::ssa::heap::PointsToResult::empty(),
                module_aliases: std::collections::HashMap::new(),
                branches_pruned: 0,
                copies_eliminated: 0,
                dead_defs_removed: 0,
            },
            param_count: 0,
            node_meta: std::collections::HashMap::new(),
            body_graph: None,
        }
    }

    #[test]
    fn populate_node_meta_extracts_bin_op_and_labels() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);

        assert!(body.node_meta.is_empty());
        let ok = populate_node_meta(&mut body, &cfg);
        assert!(ok, "should succeed for valid nodes");

        assert_eq!(body.node_meta.len(), 2);

        // Node 0: has bin_op=Add and Source label
        let meta0 = &body.node_meta[&0];
        assert_eq!(meta0.info.bin_op, Some(BinOp::Add));
        assert_eq!(meta0.info.taint.labels.len(), 1);
        assert!(matches!(meta0.info.taint.labels[0], DataLabel::Source(_)));
        // Full NodeInfo round-trip: span, defines, and kind are preserved.
        assert_eq!(meta0.info.ast.span, (0, 10));
        assert_eq!(meta0.info.taint.defines.as_deref(), Some("x"));

        // Node 1: no bin_op, no labels
        let meta1 = &body.node_meta[&1];
        assert_eq!(meta1.info.bin_op, None);
        assert!(meta1.info.taint.labels.is_empty());
        assert_eq!(meta1.info.taint.defines.as_deref(), Some("y"));
    }

    #[test]
    fn populate_node_meta_fails_on_invalid_node() {
        let cfg = make_test_cfg(); // only has 2 nodes (0, 1)
        let bad_node = NodeIndex::new(999);
        let n0 = NodeIndex::new(0);

        let mut body = make_body_referencing_nodes(n0, bad_node);

        let ok = populate_node_meta(&mut body, &cfg);
        assert!(!ok, "should fail for out-of-bounds NodeIndex");
    }

    #[test]
    fn populate_node_meta_idempotent() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);

        populate_node_meta(&mut body, &cfg);
        let first_pass = body.node_meta.clone();

        populate_node_meta(&mut body, &cfg);
        assert_eq!(
            body.node_meta, first_pass,
            "second call should be idempotent"
        );
    }

    #[test]
    fn cross_file_node_meta_default() {
        let meta = CrossFileNodeMeta::default();
        assert_eq!(meta.info.bin_op, None);
        assert!(meta.info.taint.labels.is_empty());
    }

    // ── Phase CF-3: rebuild_body_graph ──────────────────────────────────

    #[test]
    fn rebuild_body_graph_synthesizes_proxy_cfg() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        populate_node_meta(&mut body, &cfg);
        // Simulate the indexed-scan load: body_graph is skipped by serde.
        body.body_graph = None;

        let rebuilt = rebuild_body_graph(&mut body);
        assert!(rebuilt, "rebuild should install a fresh graph");
        let graph = body.body_graph.as_ref().expect("graph rebuilt");
        assert_eq!(graph.node_count(), 2);
        let info0 = &graph[n0];
        assert_eq!(info0.bin_op, Some(BinOp::Add));
        assert_eq!(info0.taint.labels.len(), 1);
        assert!(matches!(info0.taint.labels[0], DataLabel::Source(_)));
    }

    #[test]
    fn rebuild_body_graph_is_idempotent() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        populate_node_meta(&mut body, &cfg);
        body.body_graph = None;

        assert!(rebuild_body_graph(&mut body));
        assert!(!rebuild_body_graph(&mut body), "second call must no-op");
    }

    #[test]
    fn rebuild_body_graph_noop_without_meta() {
        // Intra-file body: node_meta empty, body_graph comes from pass 1.
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        assert!(body.node_meta.is_empty());
        assert!(body.body_graph.is_none());
        assert!(!rebuild_body_graph(&mut body));
        assert!(body.body_graph.is_none());
    }
}

#[cfg(test)]
mod inline_cache_epoch_tests {
    //! Phase CF-5 hooks for cross-file SCC joint fixed-point iteration.
    //!
    //! These do not exercise the full inline pipeline — they lock down the
    //! semantic contract of [`inline_cache_clear_epoch`] and
    //! [`inline_cache_fingerprint`] so the SCC orchestrator can rely on:
    //!
    //! * `clear_epoch` drops every entry, leaving the cache empty.
    //! * `fingerprint` is deterministic across equivalent caches (same
    //!   keys → same bytes).  Two caches with identical entries produce
    //!   identical fingerprints regardless of insertion order.
    //! * `fingerprint` changes when return caps change — the signal the
    //!   orchestrator will use to detect inline-cache convergence.

    use super::*;
    use crate::labels::Cap;
    use crate::symbol::FuncKey;
    use crate::taint::domain::VarTaint;
    use smallvec::SmallVec;

    fn key(name: &str) -> FuncKey {
        FuncKey {
            name: name.into(),
            ..Default::default()
        }
    }

    fn sig() -> ArgTaintSig {
        ArgTaintSig(SmallVec::new())
    }

    fn result(caps_bits: u16) -> InlineResult {
        InlineResult {
            return_taint: Some(VarTaint {
                caps: Cap::from_bits_retain(caps_bits),
                origins: SmallVec::new(),
                uses_summary: false,
            }),
        }
    }

    #[test]
    fn clear_epoch_drops_all_entries() {
        let mut c: InlineCache = HashMap::new();
        c.insert((key("a"), sig()), result(1));
        c.insert((key("b"), sig()), result(2));
        assert_eq!(c.len(), 2);

        inline_cache_clear_epoch(&mut c);
        assert!(c.is_empty());
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let mut a: InlineCache = HashMap::new();
        a.insert((key("alpha"), sig()), result(3));
        a.insert((key("beta"), sig()), result(5));

        let mut b: InlineCache = HashMap::new();
        b.insert((key("beta"), sig()), result(5));
        b.insert((key("alpha"), sig()), result(3));

        assert_eq!(inline_cache_fingerprint(&a), inline_cache_fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_when_return_caps_change() {
        let mut c: InlineCache = HashMap::new();
        c.insert((key("f"), sig()), result(0));
        let before = inline_cache_fingerprint(&c);

        c.insert((key("f"), sig()), result(1));
        let after = inline_cache_fingerprint(&c);

        assert_ne!(before, after, "cap refinement must change fingerprint");
    }

    #[test]
    fn fingerprint_tracks_missing_return_taint_as_zero() {
        // A cached miss (no return taint) fingerprints as zero caps so
        // two converged iterations both producing "no return taint" are
        // recognised as equal.
        let mut c: InlineCache = HashMap::new();
        c.insert((key("f"), sig()), InlineResult { return_taint: None });
        let fp = inline_cache_fingerprint(&c);
        assert_eq!(*fp.get(&(key("f"), sig())).unwrap(), 0);
    }
}

#[cfg(test)]
mod binding_key_tests {
    use super::*;
    use crate::taint::domain::VarTaint;
    use smallvec::smallvec;
    use std::collections::HashMap;

    // ── PartialEq / Hash ───────────────────────────────────────────────

    #[test]
    fn same_name_both_none_match() {
        let a = BindingKey::new("x");
        let b = BindingKey::new("x");
        assert_eq!(a, b);
        assert!(a.matches(&b));
    }

    #[test]
    fn same_name_one_none_one_some_matches() {
        let none_key = BindingKey::new("x");
        let some_key = BindingKey::with_body_id("x", 1);
        // Standard PartialEq: different (body_id differs)
        assert_ne!(none_key, some_key);
        // Body-id-aware matching: None wildcard
        assert!(none_key.matches(&some_key));
        assert!(some_key.matches(&none_key));
    }

    #[test]
    fn same_name_same_body_id_matches() {
        let a = BindingKey::with_body_id("x", 1);
        let b = BindingKey::with_body_id("x", 1);
        assert_eq!(a, b);
        assert!(a.matches(&b));
    }

    #[test]
    fn same_name_different_body_id_no_match() {
        let a = BindingKey::with_body_id("x", 1);
        let b = BindingKey::with_body_id("x", 2);
        assert_ne!(a, b);
        assert!(!a.matches(&b));
    }

    #[test]
    fn different_name_no_match() {
        // None body_id
        assert!(!BindingKey::new("x").matches(&BindingKey::new("y")));
        // Same body_id
        assert!(!BindingKey::with_body_id("x", 1).matches(&BindingKey::with_body_id("y", 1)));
        // Mixed
        assert!(!BindingKey::new("x").matches(&BindingKey::with_body_id("y", 1)));
    }

    // ── seed_lookup ────────────────────────────────────────────────────

    fn taint(caps: u16) -> VarTaint {
        VarTaint {
            caps: Cap::from_bits_truncate(caps),
            origins: smallvec![],
            uses_summary: false,
        }
    }

    #[test]
    fn seed_lookup_exact_match() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        let key = BindingKey::new("x");
        assert!(seed_lookup(&seed, &key).is_some());
        assert_eq!(
            seed_lookup(&seed, &key).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
    }

    #[test]
    fn seed_lookup_none_finds_none() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        // Query with None body_id → exact match (both None)
        let key = BindingKey::new("x");
        assert!(seed_lookup(&seed, &key).is_some());
    }

    #[test]
    fn seed_lookup_some_falls_back_to_none() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1)); // body_id=None
        // Query with Some(1) → exact miss, but fallback matches None via wildcard
        let key = BindingKey::with_body_id("x", 1);
        assert!(seed_lookup(&seed, &key).is_some());
    }

    #[test]
    fn seed_lookup_none_falls_back_to_some() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(1)); // body_id=Some(1)
        // Query with None → exact miss, but fallback matches via wildcard
        let key = BindingKey::new("x");
        assert!(seed_lookup(&seed, &key).is_some());
    }

    #[test]
    fn seed_lookup_prefers_exact_over_wildcard() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1)); // None → caps=1
        seed.insert(BindingKey::with_body_id("x", 1), taint(2)); // Some(1) → caps=2
        // Exact match for Some(1) returns caps=2
        let key = BindingKey::with_body_id("x", 1);
        assert_eq!(
            seed_lookup(&seed, &key).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
    }

    #[test]
    fn seed_lookup_different_body_ids_distinct() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(1));
        seed.insert(BindingKey::with_body_id("x", 2), taint(2));
        // Query for body_id=1 → exact match
        let key1 = BindingKey::with_body_id("x", 1);
        assert_eq!(
            seed_lookup(&seed, &key1).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
        // Query for body_id=2 → exact match
        let key2 = BindingKey::with_body_id("x", 2);
        assert_eq!(
            seed_lookup(&seed, &key2).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
        // Query for body_id=3 → no exact match, no None entry, no wildcard → None
        let key3 = BindingKey::with_body_id("x", 3);
        assert!(seed_lookup(&seed, &key3).is_none());
    }

    #[test]
    fn seed_lookup_miss_different_name() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        let key = BindingKey::new("y");
        assert!(seed_lookup(&seed, &key).is_none());
    }

    // ── join_seed_maps ─────────────────────────────────────────────────

    #[test]
    fn join_seed_maps_does_not_merge_different_body_ids() {
        let mut a = HashMap::new();
        a.insert(BindingKey::with_body_id("x", 1), taint(1));
        let mut b = HashMap::new();
        b.insert(BindingKey::with_body_id("x", 2), taint(2));
        let joined = join_seed_maps(&a, &b);
        // Both entries preserved (different body_ids → different keys)
        assert_eq!(joined.len(), 2);
        assert_eq!(
            joined.get(&BindingKey::with_body_id("x", 1)).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
        assert_eq!(
            joined.get(&BindingKey::with_body_id("x", 2)).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
    }

    #[test]
    fn join_seed_maps_merges_same_body_id() {
        let mut a = HashMap::new();
        a.insert(BindingKey::with_body_id("x", 1), taint(1));
        let mut b = HashMap::new();
        b.insert(BindingKey::with_body_id("x", 1), taint(2));
        let joined = join_seed_maps(&a, &b);
        assert_eq!(joined.len(), 1);
        let caps = joined.get(&BindingKey::with_body_id("x", 1)).unwrap().caps;
        // OR of caps 1 and 2
        assert!(caps.contains(Cap::from_bits_truncate(1)));
        assert!(caps.contains(Cap::from_bits_truncate(2)));
    }

    // ── filter_seed_to_toplevel ────────────────────────────────────────

    #[test]
    fn filter_seed_retains_matching_body_ids() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::with_body_id("x", 1), taint(1));
        seed.insert(BindingKey::with_body_id("y", 2), taint(2));

        // Toplevel keys with None body_id should match any body_id (wildcard)
        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x")); // None matches body_id=1
        let filtered = filter_seed_to_toplevel(&seed, &toplevel);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&BindingKey::with_body_id("x", 1)));
    }

    #[test]
    fn filter_seed_excludes_non_toplevel() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x"), taint(1));
        seed.insert(BindingKey::new("y"), taint(2));

        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x"));
        let filtered = filter_seed_to_toplevel(&seed, &toplevel);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&BindingKey::new("x")));
    }
}

#[cfg(test)]
mod worklist_tests {
    use std::collections::{HashSet, VecDeque};

    /// Simulate the O(1) worklist membership pattern from run_ssa_taint_internal.
    /// Verifies that the HashSet stays in sync with the VecDeque.
    fn worklist_push(wl: &mut VecDeque<usize>, in_wl: &mut HashSet<usize>, idx: usize) -> bool {
        if in_wl.insert(idx) {
            wl.push_back(idx);
            true
        } else {
            false
        }
    }

    fn worklist_pop(wl: &mut VecDeque<usize>, in_wl: &mut HashSet<usize>) -> Option<usize> {
        let val = wl.pop_front()?;
        in_wl.remove(&val);
        Some(val)
    }

    #[test]
    fn duplicate_enqueue_produces_single_entry() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        assert!(worklist_push(&mut wl, &mut in_wl, 0));
        assert!(!worklist_push(&mut wl, &mut in_wl, 0)); // duplicate
        assert_eq!(wl.len(), 1);
        assert_eq!(in_wl.len(), 1);
    }

    #[test]
    fn pop_removes_from_set() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 5);
        worklist_push(&mut wl, &mut in_wl, 10);
        let val = worklist_pop(&mut wl, &mut in_wl);
        assert_eq!(val, Some(5));
        assert!(!in_wl.contains(&5));
        assert!(in_wl.contains(&10));
    }

    #[test]
    fn re_enqueue_after_pop() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);
        let _ = worklist_pop(&mut wl, &mut in_wl);
        // After popping, we should be able to re-enqueue
        assert!(worklist_push(&mut wl, &mut in_wl, 0));
        assert_eq!(wl.len(), 1);
    }

    #[test]
    fn empty_worklist() {
        let mut wl: VecDeque<usize> = VecDeque::new();
        let mut in_wl: HashSet<usize> = HashSet::new();
        assert_eq!(worklist_pop(&mut wl, &mut in_wl), None);
        assert!(in_wl.is_empty());
    }

    #[test]
    fn self_loop_pattern() {
        // Simulate a block that re-enqueues itself
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);

        let block = worklist_pop(&mut wl, &mut in_wl).unwrap();
        assert_eq!(block, 0);
        // Re-enqueue self (simulating state change)
        worklist_push(&mut wl, &mut in_wl, 0);
        // Also enqueue successor
        worklist_push(&mut wl, &mut in_wl, 1);
        assert_eq!(wl.len(), 2);
    }

    #[test]
    fn cycle_with_repeated_discovery() {
        // Simulate cycle: 0→1→2→0 with multiple state propagations
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);

        let mut iterations = 0;
        while let Some(block) = worklist_pop(&mut wl, &mut in_wl) {
            iterations += 1;
            if iterations > 10 {
                break; // safety net
            }
            let succ = (block + 1) % 3;
            // Only re-enqueue if "state changed" (simulate with iteration limit)
            if iterations < 6 {
                worklist_push(&mut wl, &mut in_wl, succ);
            }
        }
        assert!(iterations <= 10, "worklist should terminate");
        assert!(wl.is_empty());
        assert!(in_wl.is_empty());
    }

    #[test]
    fn dense_successors_no_duplicates() {
        // Many successors, some repeated — old O(n) contains() would be slow here
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();

        // Seed with one node
        worklist_push(&mut wl, &mut in_wl, 0);
        let _ = worklist_pop(&mut wl, &mut in_wl);

        // Try to add 100 successors, with many duplicates
        let mut total_enqueued = 0;
        for i in 0..100 {
            let succ = i % 10; // only 10 unique blocks
            if worklist_push(&mut wl, &mut in_wl, succ) {
                total_enqueued += 1;
            }
        }
        assert_eq!(total_enqueued, 10); // only 10 unique blocks enqueued
        assert_eq!(wl.len(), 10);
        assert_eq!(in_wl.len(), 10);
    }

    #[test]
    fn set_and_deque_stay_in_sync_throughout() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();

        // Push, pop, re-push cycle
        for i in 0..20 {
            worklist_push(&mut wl, &mut in_wl, i);
        }
        assert_eq!(wl.len(), in_wl.len());

        for _ in 0..10 {
            worklist_pop(&mut wl, &mut in_wl);
        }
        assert_eq!(wl.len(), in_wl.len());
        assert_eq!(wl.len(), 10);

        // Re-push some previously popped
        for i in 0..5 {
            worklist_push(&mut wl, &mut in_wl, i);
        }
        assert_eq!(wl.len(), in_wl.len());
        assert_eq!(wl.len(), 15);

        // Drain completely
        while worklist_pop(&mut wl, &mut in_wl).is_some() {}
        assert!(wl.is_empty());
        assert!(in_wl.is_empty());
    }
}

#[cfg(test)]
mod primary_sink_location_tests {
    //! Regression guard for the primary sink-location attribution contract
    //! introduced in phases 1-4: a [`SinkSite`] carried on an
    //! [`SsaFuncSummary`] must propagate unchanged through summary
    //! resolution → [`SsaTaintEvent::primary_sink_site`] →
    //! [`crate::taint::Finding::primary_location`].
    //!
    //! The test is deliberately low-level — it wires up synthetic SSA and
    //! drives the three emission stages directly — so any future refactor
    //! that drops the site on the floor between stages fails here rather
    //! than only at the corpus/benchmark layer.
    use super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, SourceKind};
    use crate::summary::SinkSite;
    use crate::summary::ssa_summary::SsaFuncSummary;
    use crate::taint::domain::TaintOrigin;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;
    use std::collections::HashMap;

    /// Build a caller CFG that models `sink(source())`: two nodes, where
    /// the sink node carries `callee = "dangerous_exec"` so
    /// [`reconstruct_flow_path`] can name the sink.
    fn caller_cfg() -> (Cfg, NodeIndex, NodeIndex) {
        let mut cfg = Graph::new();
        let source = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 5),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        let sink = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 30),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("dangerous_exec".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        (cfg, source, sink)
    }

    /// Build an SSA body for `v0 = source(); v1 = dangerous_exec(v0); ret`.
    fn caller_body(source_node: NodeIndex, sink_node: NodeIndex) -> SsaBody {
        let mut cfg_node_map = HashMap::new();
        cfg_node_map.insert(source_node, SsaValue(0));
        cfg_node_map.insert(sink_node, SsaValue(1));
        SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: source_node,
                        var_name: Some("x".into()),
                        span: (0, 5),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Call {
                            callee: "dangerous_exec".into(),
                            args: vec![smallvec![SsaValue(0)]],
                            receiver: None,
                        },
                        cfg_node: sink_node,
                        var_name: None,
                        span: (10, 30),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: source_node,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: None,
                    cfg_node: sink_node,
                    block: BlockId(0),
                },
            ],
            cfg_node_map,
            exception_edges: vec![],
        }
    }

    /// Locks in the end-to-end contract that a SinkSite on an
    /// SsaFuncSummary surfaces verbatim as `Finding.primary_location`.
    ///
    /// If this fails, something on the summary→event→finding path
    /// (`pick_primary_sink_sites`, `emit_ssa_taint_events`, or
    /// `ssa_events_to_findings`) has silently stopped forwarding
    /// coordinates.  Fixing that path — not this test — is the right
    /// response.
    #[test]
    fn ssa_summary_sinksite_surfaces_as_finding_primary_location() {
        let (cfg, source_node, sink_node) = caller_cfg();
        let ssa = caller_body(source_node, sink_node);

        // Synthetic summary: parameter 0 reaches a SHELL_ESCAPE sink inside
        // the callee at "other.rs":42:10.
        let site = SinkSite {
            file_rel: "other.rs".into(),
            line: 42,
            col: 10,
            snippet: "Command::new(cmd).status()".into(),
            cap: Cap::SHELL_ESCAPE,
        };
        let summary = SsaFuncSummary {
            param_to_sink: vec![(0usize, smallvec![site.clone()])],
            ..Default::default()
        };

        // Drive the three emission stages with the summary's own
        // `param_to_sink` — that is what summary resolution feeds in the
        // real pipeline.
        let tainted: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> = vec![(
            SsaValue(0),
            Cap::SHELL_ESCAPE,
            smallvec![TaintOrigin {
                node: source_node,
                source_kind: SourceKind::EnvironmentConfig,
                source_span: None,
            }],
        )];
        let call_inst = &ssa.blocks[0].body[1];
        let primary_sites = pick_primary_sink_sites(
            call_inst,
            &tainted,
            Cap::SHELL_ESCAPE,
            &summary.param_to_sink,
        );
        assert_eq!(
            primary_sites.len(),
            1,
            "summary site must survive pick filter (line != 0, cap ∩ sink_caps ≠ ∅)",
        );

        let mut events = Vec::new();
        emit_ssa_taint_events(
            &mut events,
            sink_node,
            tainted.clone(),
            Cap::SHELL_ESCAPE,
            /* all_validated */ false,
            /* guard_kind   */ None,
            /* uses_summary */ true,
            primary_sites,
        );
        assert_eq!(events.len(), 1, "single site → single event");
        let event_site = events[0]
            .primary_sink_site
            .as_ref()
            .expect("event must carry the primary SinkSite");
        assert_eq!(
            (
                event_site.file_rel.as_str(),
                event_site.line,
                event_site.col,
            ),
            ("other.rs", 42, 10),
        );

        let findings = ssa_events_to_findings(&events, &ssa, &cfg);
        assert_eq!(findings.len(), 1);
        let loc = findings[0]
            .primary_location
            .as_ref()
            .expect("Finding.primary_location must be populated from SinkSite");
        assert_eq!(loc.file_rel, "other.rs");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.col, 10);
        assert_eq!(loc.snippet, "Command::new(cmd).status()");
    }
}

#[cfg(test)]
mod goto_succ_propagation_tests {
    //! Regression guard for the 3-successor Goto collapse in
    //! `src/ssa/lower.rs` (see `three_successor_collapse_produces_goto`).
    //!
    //! Lowering collapses ≥3-successor blocks to `Terminator::Goto(first)`
    //! but preserves the full successor list on `block.succs`. Flow
    //! consumers (this module's `compute_succ_states`, SCCP's
    //! `process_terminator`) must treat `block.succs` as authoritative.
    //! Without that, taint exits only through the first successor and all
    //! downstream blocks on the other edges silently drop it.
    use super::*;
    use crate::cfg::Cfg;
    use crate::state::symbol::SymbolInterner;
    use petgraph::Graph;
    use smallvec::smallvec;

    #[test]
    fn goto_propagates_to_every_succ_on_three_way_collapse() {
        // Build a block with Terminator::Goto(1) but succs = [1, 2, 3] — the
        // shape lowering emits for a 3-way fanout.
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1), BlockId(2), BlockId(3)],
        };

        let ssa = SsaBody {
            blocks: vec![block.clone()],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
        };

        let cfg: Cfg = Graph::new();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = std::collections::HashMap::new();

        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            global_seed: None,
            const_values: None,
            type_facts: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
        };

        // A non-bottom exit state — the test only cares that *every* succ
        // receives a clone of it, so any distinguishable state works.
        let mut exit_state = SsaTaintState::initial();
        exit_state.values.push((
            SsaValue(42),
            VarTaint {
                caps: crate::labels::Cap::all(),
                origins: smallvec::SmallVec::new(),
                uses_summary: false,
            },
        ));

        let succ_states = compute_succ_states(&block, &cfg, &ssa, &transfer, &exit_state);

        assert_eq!(
            succ_states.len(),
            3,
            "Goto with 3 succs must propagate to all 3 successors, got {:?}",
            succ_states.iter().map(|(b, _)| *b).collect::<Vec<_>>()
        );

        let targets: Vec<BlockId> = succ_states.iter().map(|(b, _)| *b).collect();
        assert_eq!(targets, vec![BlockId(1), BlockId(2), BlockId(3)]);

        for (bid, state) in &succ_states {
            assert!(
                state.values.iter().any(|(v, _)| *v == SsaValue(42)),
                "succ {:?} did not receive the exit state taint",
                bid
            );
        }
    }

    #[test]
    fn goto_single_successor_still_works() {
        // Normal Goto with a single successor: behavior unchanged.
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1)],
        };
        let ssa = SsaBody {
            blocks: vec![block.clone()],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
        };
        let cfg: Cfg = Graph::new();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = std::collections::HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            global_seed: None,
            const_values: None,
            type_facts: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
        };
        let exit_state = SsaTaintState::initial();

        let succ_states = compute_succ_states(&block, &cfg, &ssa, &transfer, &exit_state);
        assert_eq!(succ_states.len(), 1);
        assert_eq!(succ_states[0].0, BlockId(1));
    }
}
