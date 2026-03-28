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
use crate::callgraph::callee_leaf_name;
use crate::cfg::{Cfg, FuncSummaries, NodeInfo};
use crate::constraint;
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, SourceKind};
use crate::ssa::heap::{HeapSlot, HeapState, PointsToResult, PointsToSet};
use crate::ssa::ir::*;
use crate::state::lattice::Lattice;
use crate::state::symbol::{SymbolId, SymbolInterner};
use crate::summary::{CalleeResolution, GlobalSummaries};
use crate::symbol::Lang;
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
    /// solving is disabled via `NYX_CONSTRAINT=0`.
    pub path_env: Option<constraint::PathEnv>,
    /// Per-SSA-value abstract domain state (Phase 17). `None` when
    /// abstract interpretation is disabled via `NYX_ABSTRACT_INTERP=0`.
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
            (Some(a), Some(b)) => {
                if !a.leq(b) {
                    return false;
                }
            }
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
}

// ── Context-Sensitive Inline Analysis ──────────────────────────────────

/// Maximum SSA blocks in a callee body before skipping inline analysis.
const MAX_INLINE_BLOCKS: usize = 500;

/// Compact cache key: per-arg-position cap bits (sorted, non-empty only).
/// Two calls with identical `ArgTaintSig` produce identical inline results.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ArgTaintSig(SmallVec<[(usize, u16); 4]>);

/// Cached result of inline-analyzing a callee with specific argument taint.
#[derive(Clone, Debug)]
pub(crate) struct InlineResult {
    /// Taint on the return value after inline analysis.
    return_taint: Option<VarTaint>,
}

/// Cache for context-sensitive inline analysis results.
pub(crate) type InlineCache = HashMap<(String, ArgTaintSig), InlineResult>;

/// Minimal CFG node metadata embedded in cross-file callee bodies.
///
/// The symex executor accesses `bin_op` (for binary-op detection in Assign
/// transfer) and `labels` (for internal sink detection) from the CFG.
/// Cross-file bodies store these per-NodeIndex so the original CFG is not needed.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CrossFileNodeMeta {
    pub bin_op: Option<crate::cfg::BinOp>,
    pub labels: smallvec::SmallVec<[crate::labels::DataLabel; 2]>,
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
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let idx = inst.cfg_node.index() as u32;
            if body.node_meta.contains_key(&idx) {
                continue;
            }
            if inst.cfg_node.index() >= cfg.node_count() {
                return false;
            }
            let info = &cfg[inst.cfg_node];
            body.node_meta.insert(
                idx,
                CrossFileNodeMeta {
                    bin_op: info.bin_op,
                    labels: info.taint.labels.clone(),
                },
            );
        }
    }
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
    pub ssa_summaries: Option<&'a HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>>,
    /// Extra label rules from user config (custom sources/sanitizers/sinks).
    /// Used as fallback when `resolve_callee` finds no summary for an inner
    /// arg callee — so label-only sanitizers still reduce sink caps.
    pub extra_labels: Option<&'a [RuntimeLabelRule]>,
    /// Pre-lowered + optimized SSA bodies for intra-file functions.
    /// When present, enables context-sensitive inline analysis at call sites.
    pub callee_bodies: Option<&'a HashMap<String, CalleeSsaBody>>,
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
    /// Callback bindings: maps callee parameter name → actual function name.
    /// Set during inline analysis when caller passes a function reference as arg.
    pub callback_bindings: Option<&'a HashMap<String, String>>,
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
    // so we snapshot each origin's span now.
    for taint in result.values_mut() {
        for origin in taint.origins.iter_mut() {
            if origin.source_span.is_none() {
                if let Some(info) = cfg.node_weight(origin.node) {
                    origin.source_span = Some(info.ast.span);
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
            let cond_info = &cfg[*cond];
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
        Terminator::Goto(target) => {
            smallvec::smallvec![(*target, exit_state.clone())]
        }
        Terminator::Return(_) | Terminator::Unreachable => SmallVec::new(),
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

    let callee_bodies = transfer.callee_bodies?;
    let cache_ref = transfer.inline_cache?;
    // Use leaf name for callee_bodies lookup (keyed by bare function name).
    let normalized = callee_leaf_name(callee);
    let callee_body = callee_bodies.get(normalized)?;

    // Skip very large function bodies
    if callee_body.ssa.blocks.len() > MAX_INLINE_BLOCKS {
        return None;
    }

    // Build cache key from actual argument taint
    let sig = build_arg_taint_sig(args, receiver, state);

    // Check cache
    {
        let cache = cache_ref.borrow();
        if let Some(cached) = cache.get(&(normalized.to_string(), sig.clone())) {
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
            if let SsaOp::Param { index } = &inst.op {
                if let Some(var_name) = inst.var_name.as_ref() {
                    // Collect taint from the corresponding caller argument.
                    // For zero-arg method calls, fallback to receiver taint for
                    // param 0 (matches collect_args_taint fallback behavior).
                    let mut combined_caps = Cap::empty();
                    let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

                    if *index < args.len() {
                        for v in &args[*index] {
                            if let Some(taint) = state.get(*v) {
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
                    } else if *index == 0 && args.is_empty() {
                        // Zero-arg method call: seed param 0 from receiver
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
        }
    }

    // Detect callback arguments: when a call argument refers to a known function
    // name (in callee_bodies or via label classification), record the mapping
    // so the callee's analysis can resolve calls through the parameter.
    let mut callback_bindings: HashMap<String, String> = HashMap::new();
    if let Some(callee_bodies) = transfer.callee_bodies {
        for block in &callee_body.ssa.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if let SsaOp::Param { index } = &inst.op {
                    if let Some(param_name) = inst.var_name.as_ref() {
                        if *index < args.len() {
                            // Look up the caller-side argument's var name
                            for v in &args[*index] {
                                if let Some(arg_var_name) = caller_ssa
                                    .value_defs
                                    .get(v.0 as usize)
                                    .and_then(|vd| vd.var_name.as_deref())
                                {
                                    // Check if the argument name matches a known callee body
                                    let norm = callee_leaf_name(arg_var_name);
                                    if callee_bodies.contains_key(norm) {
                                        callback_bindings
                                            .insert(param_name.clone(), norm.to_string());
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

    // Cache the result
    {
        let mut cache = cache_ref.borrow_mut();
        cache.insert((normalized.to_string(), sig), result.clone());
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
    _call_site_node: NodeIndex,
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
                        if target_origins.len() < MAX_ORIGINS
                            && !target_origins.iter().any(|o| o.node == orig.node)
                        {
                            target_origins.push(*orig);
                        }
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
                        if target_origins.len() < MAX_ORIGINS
                            && !target_origins.iter().any(|o| o.node == orig.node)
                        {
                            target_origins.push(*orig);
                        }
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

            // CFG-level receiver offset: 1 when the receiver was prepended to
            // arg_uses during CFG construction (CallMethod), 0 otherwise.
            let cfg_receiver_offset: usize = if info.call.receiver.is_some() { 1 } else { 0 };

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
            let callee_summary =
                resolve_callee(transfer, callee, caller_func, info.call.call_ordinal);

            // Capture container fields and return type regardless of whether
            // inline analysis handled the call
            if let Some(ref resolved) = callee_summary {
                resolved_container_to_return = resolved.param_container_to_return.clone();
                resolved_container_store = resolved.param_to_container_store.clone();

                // Phase 17 hardening: capture abstract return for post-transfer injection
                callee_return_abstract = resolved.return_abstract.clone();

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
                    if let Some(ref resolved) =
                        resolve_callee(transfer, oc, caller_func, info.call.call_ordinal)
                    {
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

                // Propagation: ALWAYS apply
                if resolved.propagates_taint {
                    // Only use positional filtering when original arg_uses is populated
                    let effective_params = if info.call.arg_uses.is_empty() {
                        &[] as &[usize]
                    } else {
                        &resolved.propagating_params
                    };
                    let (prop_caps, prop_origins) = collect_args_taint(
                        args,
                        receiver,
                        state,
                        effective_params,
                        cfg_receiver_offset,
                    );
                    return_bits |= prop_caps;
                    for orig in &prop_origins {
                        if return_origins.len() < MAX_ORIGINS
                            && !return_origins.iter().any(|o| o.node == orig.node)
                        {
                            return_origins.push(*orig);
                        }
                    }
                }

                // Summary sanitizer: ALWAYS apply
                return_bits &= !resolved.sanitizer_caps;
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

            // Apply explicit sanitizer labels
            if !sanitizer_bits.is_empty() {
                // Collect uses taint then strip bits
                let (use_caps, use_origins) =
                    collect_args_taint(args, receiver, state, &[], cfg_receiver_offset);
                return_bits |= use_caps;
                for orig in &use_origins {
                    if return_origins.len() < MAX_ORIGINS
                        && !return_origins.iter().any(|o| o.node == orig.node)
                    {
                        return_origins.push(*orig);
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
                    let (use_caps, use_origins) =
                        collect_args_taint(args, receiver, state, &[], cfg_receiver_offset);
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
                    if let Some(ref oc_sum) =
                        resolve_callee(transfer, oc, caller_func, info.call.call_ordinal)
                    {
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

            // Collect taint from operands
            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut inherited_summary = false;

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

        SsaOp::Param { .. } => {
            // Seed from enclosing/parent body scope (multi-body analysis).
            // Look up via BindingKey (name-based, interner-independent).
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

        SsaOp::Call { callee, .. } => {
            // Known integer-producing calls get a bounded interval so downstream
            // arithmetic transfer produces useful facts (e.g. parseInt(x) * 10).
            if is_int_producing_callee(callee) {
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
            // Unknown calls: implicit Top (don't store)
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
                    );
                    for lbl in &tq_labels {
                        if let DataLabel::Sink(bits) = lbl {
                            sink_caps |= *bits;
                        }
                    }
                }
            }
        }

        if sink_caps.is_empty() {
            // Callback pattern: check if callee has source_to_callback and the
            // actual callback argument has a matching param_to_sink.
            if let SsaOp::Call {
                callee, args: _, ..
            } = &inst.op
            {
                let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
                if let Some(resolved) =
                    resolve_callee(transfer, callee, caller_func, info.call.call_ordinal)
                {
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
                                    events.push(SsaTaintEvent {
                                        sink_node: inst.cfg_node,
                                        tainted_values: vec![(
                                            inst.value,
                                            src_caps & matching_sink_caps,
                                            SmallVec::from_elem(origin, 1),
                                        )],
                                        sink_caps: matching_sink_caps,
                                        all_validated: false,
                                        guard_kind: None,
                                        uses_summary: true,
                                    });
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
            events.push(SsaTaintEvent {
                sink_node: inst.cfg_node,
                tainted_values: tainted,
                sink_caps,
                all_validated,
                guard_kind,
                uses_summary: any_uses_summary,
            });
        }
    }
}

/// Collect taint from call arguments.
///
/// `receiver_offset` is the number of entries at the front of `args` that
/// correspond to the receiver (prepended by CFG construction for CallMethod
/// nodes).  Use `info.call.receiver.is_some()` to compute this — NOT the
/// SSA-level `receiver` field, which may be `None` when the receiver variable
/// is out of scope (e.g., Java class fields).
fn collect_args_taint(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    propagating_params: &[usize],
    receiver_offset: usize,
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
        // Collect only from propagating param positions
        for &param_idx in propagating_params {
            let adj = param_idx + receiver_offset;
            if let Some(arg_vals) = args.get(adj) {
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

            // For Go append, value args start after the slice (arg 0).
            // For CallMethod languages (Java, Ruby, PHP, Rust), the receiver
            // is prepended to arg_uses[0] by the CFG builder, so real args
            // start at index 1.
            let arg_offset = if lang == Lang::Go && receiver.is_none() {
                1usize
            } else if receiver.is_some() {
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
            let arg_offset = if lang == Lang::Go && receiver.is_none() {
                1usize
            } else if receiver.is_some() {
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
        };
    }

    let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
    info.call
        .callee
        .as_ref()
        .and_then(|c| resolve_callee(transfer, c, caller_func, info.call.call_ordinal))
        .filter(|r| !r.sink_caps.is_empty())
        .map(|r| SinkInfo {
            caps: r.sink_caps,
            param_to_sink: r.param_to_sink,
        })
        .unwrap_or(SinkInfo {
            caps: Cap::empty(),
            param_to_sink: vec![],
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

    // Receiver offset: for CallMethod nodes the receiver identifier is
    // prepended to arg_uses[0] during CFG construction (cfg.rs push_node),
    // regardless of whether the receiver could be resolved to an SSA value.
    // Use `info.call.receiver` (always set for CallMethod) instead of the
    // SSA-level `receiver` field so the offset is correct even when the
    // receiver variable is out of scope (e.g., Java class fields).
    let receiver_offset: usize = if info.call.receiver.is_some() { 1 } else { 0 };

    // Priority 1: gated sink filtering (CFG-level sink_payload_args)
    if let Some(ref positions) = info.call.sink_payload_args {
        if let SsaOp::Call { args, .. } = &inst.op {
            for &pos in positions {
                let adj = pos + receiver_offset;
                if let Some(arg_vals) = args.get(adj) {
                    for &v in arg_vals {
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
    // param_to_sink indices refer to the callee's formal parameter positions.
    // For CallMethod nodes the receiver is prepended to args[0] (see cfg.rs
    // push_node), so we offset using receiver_offset computed above.
    if !param_to_sink.is_empty() {
        if let SsaOp::Call { args, .. } = &inst.op {
            for &(param_idx, per_param_caps) in param_to_sink {
                let effective_caps = per_param_caps & sink_caps;
                if effective_caps.is_empty() {
                    continue;
                }
                let adj = param_idx + receiver_offset;
                if let Some(arg_vals) = args.get(adj) {
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
        SsaOp::Source | SsaOp::Const(_) | SsaOp::Param { .. } | SsaOp::CatchParam | SsaOp::Nop => {
            Vec::new()
        }
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
) -> SmallVec<[DataLabel; 2]> {
    // 1. Try static type first (existing behavior)
    if let Some(tf) = type_facts {
        if let Some(receiver_type) = tf.get_type(receiver) {
            if let Some(prefix) = receiver_type.label_prefix() {
                let method = callee.rsplit('.').next().unwrap_or(callee);
                let qualified = format!("{}.{}", prefix, method);
                let labels = crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                if !labels.is_empty() {
                    return labels;
                }
            }
        }
    }

    // 2. Try flow-sensitive type from PathEnv (Phase 16)
    if let Some(env) = path_env {
        let types = env.get(receiver).types;
        if let Some(kind) = types.as_singleton() {
            if let Some(prefix) = kind.label_prefix() {
                let method = callee.rsplit('.').next().unwrap_or(callee);
                let qualified = format!("{}.{}", prefix, method);
                return crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
            }
        }
    }

    SmallVec::new()
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
fn is_type_safe_for_sink(
    inst: &SsaInst,
    sink_caps: Cap,
    type_facts: &crate::ssa::type_facts::TypeFactResult,
) -> bool {
    // Suppress SQL injection and path traversal (FILE_IO) for int-typed values
    let type_suppressible = Cap::SQL_QUERY | Cap::FILE_IO;
    if !sink_caps.intersects(type_suppressible) {
        return false;
    }

    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }

    used.iter().all(|v| type_facts.is_int(*v))
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
            cap.intersects(Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC)
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
        if used
            .iter()
            .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string))
        {
            return true;
        }
    }

    // Dual gate: SQL_QUERY / FILE_IO with proven Int type AND bounded interval.
    // Both conditions required: type proves the value IS an integer (not a string
    // that happened to parse), interval proves it's bounded (not arbitrary).
    // Traces through Assign chains so "const_string + tainted_int" is caught.
    if sink_caps.intersects(Cap::SQL_QUERY | Cap::FILE_IO) {
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
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    // SSRF — check if the URL argument (first arg) has a safe prefix.
    if sink_caps.intersects(Cap::SSRF) {
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

    // Dual gate for Call sinks (same as non-Call path)
    if sink_caps.intersects(Cap::SQL_QUERY | Cap::FILE_IO) {
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
        _ => {
            leaves.push(v);
        }
    }
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
    if let Some(after_scheme) = prefix.find("://") {
        let host_and_rest = &prefix[after_scheme + 3..];
        if let Some(slash_pos) = host_and_rest.find('/') {
            return slash_pos > 0; // non-empty host + path separator
        }
    }
    false
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
}

fn resolve_callee(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
) -> Option<ResolvedSummary> {
    // Use leaf name for map/index lookups (FuncKey.name is always leaf).
    let normalized = callee_leaf_name(callee);

    // -2) Import alias resolution: if the callee matches an aliased import
    // (e.g. `fetchUserCmd` → `getInput` from `./source`), resolve using the
    // original exported name instead.  This fires before all other resolution
    // so that downstream steps see the canonical symbol name.
    if let Some(bindings) = transfer.import_bindings {
        if let Some(binding) = bindings.get(normalized) {
            // Recursively resolve using the original name.
            return resolve_callee(transfer, &binding.original, caller_func, call_ordinal);
        }
    }

    // -1) Callback resolution: if the callee name matches a parameter that was
    // bound to a specific function at the call site, resolve that function instead.
    if let Some(cb) = transfer.callback_bindings {
        if let Some(real_func) = cb.get(normalized) {
            // Try to resolve the actual function via SSA summaries
            if let Some(ssa_sums) = transfer.ssa_summaries {
                if let Some(ssa_sum) = ssa_sums.get(real_func.as_str()) {
                    return Some(convert_ssa_to_resolved(ssa_sum));
                }
            }
            // Try local summaries
            let local_matches: Vec<_> = transfer
                .local_summaries
                .iter()
                .filter(|(k, _)| {
                    k.name == real_func.as_str()
                        && k.lang == transfer.lang
                        && k.namespace == transfer.namespace
                })
                .collect();
            if local_matches.len() == 1 {
                let (_, ls) = local_matches[0];
                return Some(ResolvedSummary {
                    source_caps: ls.source_caps,
                    sanitizer_caps: ls.sanitizer_caps,
                    sink_caps: ls.sink_caps,
                    param_to_sink: ls
                        .tainted_sink_params
                        .iter()
                        .map(|&i| (i, ls.sink_caps))
                        .collect(),
                    propagates_taint: !ls.propagating_params.is_empty(),
                    propagating_params: ls.propagating_params.clone(),
                    param_container_to_return: vec![],
                    param_to_container_store: vec![],
                    return_type: None,
                    return_abstract: None,
                    source_to_callback: vec![],
                });
            }
            // Try label classification for the bound function
            let labels = crate::labels::classify_all(
                transfer.lang.as_str(),
                real_func,
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
                    propagates_taint: false,
                    propagating_params: vec![],
                    param_container_to_return: vec![],
                    param_to_container_store: vec![],
                    return_type: None,
                    return_abstract: None,
                    source_to_callback: vec![],
                });
            }
        }
    }

    // 0) Precise SSA summaries (intra-file, per-parameter transforms)
    if let Some(ssa_sums) = transfer.ssa_summaries {
        if let Some(ssa_sum) = ssa_sums.get(normalized) {
            return Some(convert_ssa_to_resolved(ssa_sum));
        }
    }

    // 0.5) Cross-file SSA summaries (GlobalSummaries.ssa_by_key)
    if let Some(gs) = transfer.global_summaries {
        match gs.resolve_callee_key(normalized, transfer.lang, transfer.namespace, None) {
            CalleeResolution::Resolved(target_key) => {
                if let Some(ssa_sum) = gs.get_ssa(&target_key) {
                    return Some(convert_ssa_to_resolved(ssa_sum));
                }
            }
            _ => {}
        }
    }

    // 1) Local (same-file)
    let local_matches: Vec<_> = transfer
        .local_summaries
        .iter()
        .filter(|(k, _)| {
            k.name == normalized && k.lang == transfer.lang && k.namespace == transfer.namespace
        })
        .collect();

    if local_matches.len() == 1 {
        let (_, ls) = local_matches[0];
        return Some(ResolvedSummary {
            source_caps: ls.source_caps,
            sanitizer_caps: ls.sanitizer_caps,
            sink_caps: ls.sink_caps,
            param_to_sink: ls
                .tainted_sink_params
                .iter()
                .map(|&i| (i, ls.sink_caps))
                .collect(),
            propagates_taint: !ls.propagating_params.is_empty(),
            propagating_params: ls.propagating_params.clone(),
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],
        });
    }
    if local_matches.len() > 1 {
        return None;
    }

    // 2) Global same-language
    if let Some(gs) = transfer.global_summaries {
        match gs.resolve_callee_key(normalized, transfer.lang, transfer.namespace, None) {
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
                        propagates_taint: fs.propagates_any(),
                        propagating_params: fs.propagating_params.clone(),
                        param_container_to_return: vec![],
                        param_to_container_store: vec![],
                        return_type: None,
                        return_abstract: None,
                        source_to_callback: vec![],
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
            && let Some(fs) = gs.get(&edge.to)
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
                propagates_taint: fs.propagates_any(),
                propagating_params: fs.propagating_params.clone(),
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],
            });
        }
    }

    None
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
    let mut sink_caps = Cap::empty();
    for (_, caps) in &ssa_sum.param_to_sink {
        sink_caps |= *caps;
    }

    ResolvedSummary {
        source_caps: ssa_sum.source_caps,
        sanitizer_caps,
        sink_caps,
        param_to_sink: ssa_sum.param_to_sink.clone(),
        propagates_taint: !propagating_params.is_empty(),
        propagating_params,
        param_container_to_return: ssa_sum.param_container_to_return.clone(),
        param_to_container_store: ssa_sum.param_to_container_store.clone(),
        return_type: ssa_sum.return_type.clone(),
        return_abstract: ssa_sum.return_abstract.clone(),
        source_to_callback: ssa_sum.source_to_callback.clone(),
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
                    SsaOp::Source | SsaOp::Param { .. } | SsaOp::CatchParam => break,
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
            SsaOp::Source | SsaOp::Param { .. } | SsaOp::CatchParam => {
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
pub fn ssa_events_to_findings(
    events: &[SsaTaintEvent],
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Vec<crate::taint::Finding> {
    use std::collections::HashSet;

    let mut findings = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();

    for event in events {
        // Suppress findings where all tainted variables were validated
        // (passed through an allowlist, type-check, or validation branch).
        if event.all_validated {
            continue;
        }
        for (val, caps, origins) in &event.tainted_values {
            let cap_specificity = (*caps & event.sink_caps).bits().count_ones() as u8;
            for origin in origins {
                if seen.insert((origin.node.index(), event.sink_node.index())) {
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
pub fn extract_ssa_func_summary(
    ssa: &SsaBody,
    cfg: &Cfg,
    local_summaries: &crate::cfg::FuncSummaries,
    global_summaries: Option<&crate::summary::GlobalSummaries>,
    lang: Lang,
    namespace: &str,
    interner: &crate::state::symbol::SymbolInterner,
    param_count: usize,
) -> crate::summary::ssa_summary::SsaFuncSummary {
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

    // Helper: run a taint probe with a given global_seed and return
    // (surviving_return_caps, sink_events, return_abstract).
    // The return_abstract is the joined abstract value of the return SSA value
    // across all return blocks (None if Top or abstract interp disabled).
    let run_probe = |seed: HashMap<BindingKey, VarTaint>| -> (
        Cap,
        Vec<SsaTaintEvent>,
        Option<crate::abstract_interp::AbstractValue>,
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
        };

        let (events, block_states) = run_ssa_taint_full(ssa, cfg, &transfer);

        // Collect surviving caps at return blocks.
        // Separate param values from derived values: derived values give
        // more precise transforms (they reflect function-internal sanitization).
        // If only param values reach return → pure passthrough (Identity).
        let mut derived_caps = Cap::empty();
        let mut param_caps = Cap::empty();
        // Extract abstract value of the return SSA value.
        let mut return_abstract: Option<crate::abstract_interp::AbstractValue> = None;
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

                if let Some(rv) = ret_val {
                    // Explicit return value: use only its taint for derived_caps.
                    // If rv has no taint entry, this block contributes no derived caps.
                    let _rv_tainted = if let Some(taint) = exit.get(rv) {
                        if all_param_values.contains(&rv) {
                            param_caps |= taint.caps;
                        } else {
                            derived_caps |= taint.caps;
                        }
                        true
                    } else {
                        false
                    };
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
                                param_caps |= taint.caps;
                            }
                        }
                    }
                } else {
                    // Return(None): implicit return — fall back to all live values.
                    for (val, taint) in &exit.values {
                        if all_param_values.contains(val) {
                            param_caps |= taint.caps;
                        } else {
                            derived_caps |= taint.caps;
                        }
                    }
                }

                // Abstract return: use terminator's return value when available,
                // fall back to last instruction heuristic for Return(None).
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
                            return_abstract = Some(match return_abstract {
                                None => av,
                                Some(prev) => prev.join(&av),
                            });
                        }
                    }
                }
            }
        }

        // Prefer derived caps; fall back to param caps for passthrough functions
        let return_caps = if !derived_caps.is_empty() {
            derived_caps
        } else {
            param_caps
        };

        // Drop return_abstract if it joined to Top
        let return_abstract = return_abstract.filter(|v| !v.is_top());

        (return_caps, events, return_abstract)
    };

    // Probe with no params tainted → detect source_caps + return abstract.
    // Abstract values don't depend on taint seeding, so the baseline probe
    // captures the function's intrinsic abstract return value.
    let (baseline_return_caps, _baseline_events, return_abstract) = run_probe(HashMap::new());
    let source_caps = baseline_return_caps;

    // Probe each param
    let mut param_to_return = Vec::new();
    let mut param_to_sink = Vec::new();
    let mut param_to_sink_param = Vec::new();

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

        let (return_caps, events, _) = run_probe(seed);

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

        // Collect sink caps from events + per-arg-position detail
        let mut sink_caps = Cap::empty();
        for event in &events {
            sink_caps |= event.sink_caps;
            for pos in extract_sink_arg_positions(event, ssa) {
                param_to_sink_param.push((idx, pos, event.sink_caps));
            }
        }
        if !sink_caps.is_empty() {
            param_to_sink.push((idx, sink_caps));
        }
    }

    let (param_container_to_return, param_to_container_store) =
        extract_container_flow_summary(ssa, lang);

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
    }
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
) -> (Vec<usize>, Vec<(usize, usize)>) {
    use crate::ssa::pointsto::{ContainerOp, classify_container_op};

    let inst_map = build_inst_map(ssa);
    let mut container_to_return: HashSet<usize> = HashSet::new();
    let mut container_store: Vec<(usize, usize)> = Vec::new();

    // 1. param_container_to_return: trace Assign/Phi ops in return blocks to params
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

                // Resolve container SSA value (same logic as try_container_propagation)
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

                // Trace container to param
                let container_param =
                    match trace_to_param(container_val, ssa, &inst_map, &mut HashSet::new()) {
                        Some(idx) => idx,
                        None => continue,
                    };

                // Compute arg offset (receiver-based languages prepend receiver to args)
                let arg_offset = if lang == Lang::Go && receiver.is_none() {
                    1usize
                } else if receiver.is_some() {
                    1usize
                } else {
                    0
                };

                // Trace each value arg to param
                for &va_idx in &op {
                    let effective_idx = va_idx + arg_offset;
                    if let Some(arg_vals) = args.get(effective_idx) {
                        for &av in arg_vals {
                            if let Some(src_param) =
                                trace_to_param(av, ssa, &inst_map, &mut HashSet::new())
                            {
                                if src_param != container_param
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
    use crate::ssa::ir::*;
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
        assert_eq!(meta0.bin_op, Some(BinOp::Add));
        assert_eq!(meta0.labels.len(), 1);
        assert!(matches!(meta0.labels[0], DataLabel::Source(_)));

        // Node 1: no bin_op, no labels
        let meta1 = &body.node_meta[&1];
        assert_eq!(meta1.bin_op, None);
        assert!(meta1.labels.is_empty());
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
        assert_eq!(meta.bin_op, None);
        assert!(meta.labels.is_empty());
    }
}

#[cfg(test)]
mod binding_key_tests {
    use super::*;
    use crate::taint::domain::{TaintOrigin, VarTaint};
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
