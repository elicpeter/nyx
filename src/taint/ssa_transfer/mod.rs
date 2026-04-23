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

mod events;
mod inline;
mod state;
mod summary_extract;

#[cfg(test)]
mod tests;

pub use events::{SsaTaintEvent, ssa_events_to_findings};
pub(crate) use inline::{ArgTaintSig, InlineCache};
use inline::{CachedInlineShape, InlineResult, MAX_INLINE_BLOCKS, ReturnShape};
pub use inline::{CalleeSsaBody, CrossFileNodeMeta, populate_node_meta, rebuild_body_graph};
#[allow(unused_imports)] // retained for future shared-cache refactor / tests
pub(crate) use inline::{inline_cache_clear_epoch, inline_cache_fingerprint};
pub use state::{
    BindingKey, SsaTaintState, max_worklist_iterations, origins_truncation_count,
    reset_origins_observability, reset_worklist_observability, seed_lookup,
    set_max_origins_override, set_worklist_cap_override, worklist_cap_hit_count,
};
use state::{
    MAX_WORKLIST_ITERATIONS, ORIGINS_TRUNCATION_COUNT, WORKLIST_CAP_HITS, effective_max_origins,
    effective_worklist_cap,
};
pub(crate) use state::{record_engine_note, reset_body_engine_notes, take_body_engine_notes};
pub use summary_extract::extract_ssa_func_summary;

use crate::abstract_interp::AbstractState;
use crate::callgraph::{callee_container_hint, callee_leaf_name};
use crate::cfg::{BodyId, Cfg, FuncSummaries, NodeInfo};
use crate::constraint;
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, SourceKind};
use crate::ssa::heap::{HeapObjectId, HeapSlot, PointsToResult, PointsToSet};
use crate::ssa::ir::*;
use crate::state::lattice::Lattice;
use crate::state::symbol::SymbolInterner;
use crate::summary::{CalleeQuery, CalleeResolution, GlobalSummaries, SinkSite};
use crate::symbol::{FuncKey, Lang};
use crate::taint::domain::{PredicateSummary, TaintOrigin, VarTaint, predicate_kind_bit};
use crate::taint::path_state::{PredicateKind, classify_condition_with_target};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

// ── SSA Taint Transfer ──────────────────────────────────────────────────

/// Configuration for SSA taint analysis.
pub struct SsaTaintTransfer<'a> {
    pub lang: Lang,
    pub namespace: &'a str,
    pub interner: &'a SymbolInterner,
    pub local_summaries: &'a FuncSummaries,
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub interop_edges: &'a [InteropEdge],
    /// The [`BodyId`] of the body currently being analysed.  Used as the
    /// owning scope when writing seed entries that leave this body
    /// (e.g. [`extract_ssa_exit_state`]) and as the identity recorded on
    /// engine notes.  Defaults to [`BodyId(0)`] (top-level) for inline
    /// probes and unit tests that analyse a single synthetic body.
    pub owner_body_id: BodyId,
    /// The [`BodyId`] of this body's lexical parent, if any.  Drives the
    /// `Param`-op reader's lookup into [`Self::global_seed`]: we read
    /// from the parent's scope first (the seed entries produced by
    /// [`extract_ssa_exit_state`] on the parent body), then fall back to
    /// [`BodyId(0)`] to pick up JS/TS two-level re-keyed entries (see
    /// [`filter_seed_to_toplevel`]).  `None` for the top-level body and
    /// for probes with no surrounding scope.
    pub parent_body_id: Option<BodyId>,
    /// Taint from enclosing/parent body scope, keyed by [`BindingKey`].
    /// Read-only fallback for `Param` ops representing captured or
    /// module-scope variables.  Used in multi-body analysis for lexical
    /// containment propagation (top-level → function → closure).
    pub global_seed: Option<&'a HashMap<BindingKey, VarTaint>>,
    /// Per-call-site parameter seed for context-sensitive inline
    /// analysis.  Indexed by callee's formal [`SsaOp::Param`] index: a
    /// `Some(taint)` at index `i` seeds the callee's formal param `i`
    /// with the caller's argument taint.  Out-of-range indices (e.g.
    /// synthetic capture params emitted by scoped lowering) fall back
    /// to [`Self::global_seed`].
    pub param_seed: Option<&'a [Option<VarTaint>]>,
    /// Per-call-site receiver seed for context-sensitive inline
    /// analysis.  Mirrors [`Self::param_seed`] for [`SsaOp::SelfParam`]
    /// reads — seeds the callee's implicit `this` / `self` slot with
    /// the caller's method-receiver taint.
    pub receiver_seed: Option<&'a VarTaint>,
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
    /// Cross-file callee bodies sourced from
    /// [`GlobalSummaries::bodies_iter`].  Populated in pass 2 to enable
    /// context-sensitive inline re-analysis across file boundaries the
    /// same way `callee_bodies` enables it intra-file.  `None` preserves
    /// non-cross-file behaviour for unit tests and non-cross-file
    /// construction sites.
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

    // Seed entry block's PathEnv from optimization results
    if let Some(ref mut entry_state) = block_states[ssa.entry.0 as usize] {
        if let Some(ref mut env) = entry_state.path_env {
            if let (Some(cv), Some(tf)) = (transfer.const_values, transfer.type_facts) {
                env.seed_from_optimization(cv, tf);
            }
        }
    }

    // Seed entry block's AbstractState from optimization results
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

    // Compute loop heads for widening
    let loop_heads: HashSet<usize> = back_edges
        .iter()
        .map(|(_, target)| target.0 as usize)
        .collect();

    // Per-predecessor exit states for path-sensitive phi evaluation
    let mut pred_states: PredStates = HashMap::new();

    // Fixed-point iteration
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
    let budget = effective_worklist_cap();
    let mut worklist_capped = false;

    while let Some(bid) = worklist.pop_front() {
        in_worklist.remove(&bid);
        iterations += 1;
        if iterations >= budget {
            tracing::warn!("SSA taint: worklist budget exceeded");
            worklist_capped = true;
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
                    // Widen abstract values at loop heads
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

    MAX_WORKLIST_ITERATIONS.fetch_max(iterations, std::sync::atomic::Ordering::Relaxed);
    if worklist_capped {
        WORKLIST_CAP_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        record_engine_note(crate::engine_notes::EngineNote::WorklistCapped {
            iterations: iterations as u32,
        });
    }

    // Post-hoc origin-truncation detection.  If any converged block state
    // has a `VarTaint` whose origin list reached the cap, assume at least
    // one origin was dropped during the fixed-point iteration.  Coarse
    // but useful signal — `merge_origins` already emits the precise-count
    // note on the merge path; this complements push sites inside transfer.
    let cap = effective_max_origins();
    let mut saturated = 0u32;
    for state in block_states.iter().flatten() {
        for (_v, taint) in &state.values {
            if taint.origins.len() >= cap {
                saturated = saturated.saturating_add(1);
            }
        }
    }
    if saturated > 0 {
        ORIGINS_TRUNCATION_COUNT
            .fetch_add(saturated as usize, std::sync::atomic::Ordering::Relaxed);
        record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated {
            dropped: saturated,
        });
    }

    // Single pass over converged states to collect events
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
///
/// `owner_body_id` is the id of the body being summarised; it tags
/// every key via [`BindingKey::new`] so that same-named bindings from
/// different bodies do not silently alias when the seed is later
/// merged (e.g. in the JS/TS two-level solve).
pub fn extract_ssa_exit_state(
    block_states: &[Option<SsaTaintState>],
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    owner_body_id: BodyId,
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

    // Map SsaValue → var_name → BindingKey, scoped to the owning body.
    let mut result: HashMap<BindingKey, VarTaint> = HashMap::new();
    for (val, taint) in &joined.values {
        let var_name = ssa
            .value_defs
            .get(val.0 as usize)
            .and_then(|vd| vd.var_name.as_deref());
        if let Some(name) = var_name {
            let key = BindingKey::new(name, owner_body_id);
            result
                .entry(key)
                .and_modify(|existing| {
                    existing.caps |= taint.caps;
                    for orig in &taint.origins {
                        if existing.origins.len() < effective_max_origins()
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
                    if existing.origins.len() < effective_max_origins()
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

/// Filter a per-body exit seed map down to the top-level scope.
///
/// `toplevel` is the set of binding names that appear syntactically at
/// the top level (always keyed with `BodyId(0)`).  Every matching entry
/// in `seed` is kept but **re-keyed** to `BodyId(0)` so the resulting
/// map is single-scope: same-name entries from different bodies merge
/// via the normal OR-and-push-origins path in
/// [`join_seed_maps`] instead of coexisting as distinct keys.
///
/// This is the one legitimate place where a binding's owning scope
/// changes: the JS/TS two-level solve joins exit states from many
/// sibling function bodies into a single `combined_exit`, and each
/// sibling's surviving bindings conceptually belong to the top-level
/// scope they all write into.  Every other writer in the pipeline
/// preserves the owner's id.
pub fn filter_seed_to_toplevel(
    seed: &HashMap<BindingKey, VarTaint>,
    toplevel: &HashSet<BindingKey>,
) -> HashMap<BindingKey, VarTaint> {
    let toplevel_names: HashSet<&str> = toplevel.iter().map(|k| k.name.as_str()).collect();
    let mut out: HashMap<BindingKey, VarTaint> = HashMap::new();
    for (key, taint) in seed.iter() {
        if !toplevel_names.contains(key.name.as_str()) {
            continue;
        }
        let rekeyed = BindingKey::new(key.name.clone(), BodyId(0));
        out.entry(rekeyed)
            .and_modify(|existing| {
                existing.caps |= taint.caps;
                for orig in &taint.origins {
                    if existing.origins.len() < effective_max_origins()
                        && !existing.origins.iter().any(|o| o.node == orig.node)
                    {
                        existing.origins.push(*orig);
                    }
                }
                existing.uses_summary |= taint.uses_summary;
            })
            .or_insert_with(|| taint.clone());
    }
    out
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
pub(super) fn transfer_block(
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

                // Skip predecessor operands from infeasible paths
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
                        if combined_origins.len() < effective_max_origins()
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

    // Abstract value phi join (from predecessor exit states)
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

                // Constraint refinement
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
        Terminator::Switch { .. } => {
            // Switch: all targets and default receive the same input state.
            // Per-target branch narrowing would require per-case literal
            // metadata on the terminator (a follow-up); for now, uniform
            // propagation across `block.succs` preserves soundness.
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
///    look up the body by canonical [`FuncKey`].  This is the intra-file
///    context-sensitive path.
/// 2. **Cross-file**: if (1) misses but
///    [`GlobalSummaries::resolve_callee`] resolves the call site to a
///    cross-file [`FuncKey`], look up the body in
///    `transfer.cross_file_bodies`.  Both in-memory and indexed-scan
///    bodies are usable here: the former arrives with `body_graph`
///    already set (pass 1), the latter has it rehydrated from
///    `node_meta` via [`rebuild_body_graph`] at load time.
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
    // Step 1: intra-file.  Step 2: cross-file.
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
        // Cross-file fallback.  Build a structured query mirroring
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
                // Indexed-scan bodies deserialized from SQLite
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

    // Check cache (keyed by FuncKey + arg signature).  The cached value
    // is a structural shape — re-attribute origins to the current call
    // site before returning so two callers with matching caps but
    // different origins see their own source chains.
    {
        let cache = cache_ref.borrow();
        if let Some(cached) = cache.get(&(callee_key.clone(), sig.clone())) {
            record_engine_note(crate::engine_notes::EngineNote::InlineCacheReused);
            return Some(apply_cached_shape(
                cached,
                args,
                receiver,
                state,
                call_inst.cfg_node,
            ));
        }
    }

    // Build per-call-site seed from actual argument taint, indexed by the
    // callee's formal parameter position (not by name).  A caller with N
    // arguments produces an N-entry `Vec<Option<VarTaint>>`; the callee's
    // `Param { index }` read picks up slot `index` directly via
    // `SsaTaintTransfer::param_seed`.  Receiver taint is carried on a
    // separate channel (`SsaTaintTransfer::receiver_seed`) consumed by
    // `SelfParam`.  Name-based keying is not needed here — the callee
    // analysis is scoped to this one call site and cannot merge with
    // another callee's param seed.

    // Cross-file note: `populate_span` lazily fills `source_span` from
    // the *caller's* CFG before the origin crosses into the callee.  The
    // Param-op branch of `transfer_inst` remaps `node` to the callee's
    // own `cfg_node` and preserves only `source_span`, so without this
    // pre-fill cross-file inline would lose the caller's source line
    // entirely (finding emission in `ast.rs` uses `source_span` first,
    // falls back to indexing the caller's CFG at `node` — which is now
    // the callee's NodeIndex and resolves to a wrong or missing span).
    let populate_span = |mut o: TaintOrigin| -> TaintOrigin {
        if o.source_span.is_none() {
            if let Some(info) = cfg.node_weight(o.node) {
                o.source_span = Some(info.classification_span());
            }
        }
        o
    };
    let combine_taint = |arg_vals: &SmallVec<[SsaValue; 2]>| -> Option<VarTaint> {
        let mut combined_caps = Cap::empty();
        let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        for v in arg_vals {
            if let Some(taint) = state.get(*v) {
                combined_caps |= taint.caps;
                for orig in &taint.origins {
                    if combined_origins.len() < effective_max_origins()
                        && !combined_origins.iter().any(|o| o.node == orig.node)
                    {
                        combined_origins.push(populate_span(*orig));
                    }
                }
            }
        }
        if combined_caps.is_empty() {
            None
        } else {
            Some(VarTaint {
                caps: combined_caps,
                origins: combined_origins,
                uses_summary: false,
            })
        }
    };

    let param_seed: Vec<Option<VarTaint>> = args.iter().map(combine_taint).collect();
    let receiver_seed: Option<VarTaint> = receiver.and_then(|rv| {
        state.get(rv).map(|taint| VarTaint {
            caps: taint.caps,
            origins: taint
                .origins
                .iter()
                .map(|o| populate_span(*o))
                .collect(),
            uses_summary: false,
        })
    });

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

    let cb_ref = if callback_bindings.is_empty() {
        None
    } else {
        Some(&callback_bindings)
    };
    let param_seed_slice: Option<&[Option<VarTaint>]> = if param_seed.is_empty() {
        None
    } else {
        Some(param_seed.as_slice())
    };
    let child_transfer = SsaTaintTransfer {
        lang: transfer.lang,
        namespace: transfer.namespace,
        interner: transfer.interner,
        local_summaries: transfer.local_summaries,
        global_summaries: transfer.global_summaries,
        interop_edges: transfer.interop_edges,
        owner_body_id: BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: param_seed_slice,
        receiver_seed: receiver_seed.as_ref(),
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

    // Extract the structural return shape from return-block exit states
    let empty_induction = HashSet::new();
    let shape = extract_inline_return_taint(
        &callee_body.ssa,
        callee_cfg,
        &child_transfer,
        &callee_block_states,
        &empty_induction,
    );

    // Cache the structural shape under the canonical FuncKey, then
    // re-attribute to this call site's actual arg/receiver origins.
    {
        let mut cache = cache_ref.borrow_mut();
        cache.insert((callee_key, sig), shape.clone());
    }

    Some(apply_cached_shape(
        &shape,
        args,
        receiver,
        state,
        call_inst.cfg_node,
    ))
}

/// Per-NodeIndex provenance bits for the callee's Param/SelfParam ops.
///
/// Multiple synthetic `Param` ops can share the same `cfg_node` (the
/// lowering emits them all at the function entry; see
/// [`crate::ssa::lower::reorder_external_vars`]).  When that happens, an
/// origin whose `node` points at the shared entry cannot be attributed to
/// a single param position from node identity alone.  This struct unions
/// the provenance of every Param/SelfParam sitting on the same node.
///
/// Over-attribution is safe: at apply time, set-bit indices beyond the
/// caller's actual argument count are skipped, and set bits whose param
/// contributed no taint union an empty set of caller origins.
#[derive(Copy, Clone, Debug, Default)]
struct CalleeParamNodeBits {
    /// Bit i = a `Param { index: i }` op sits on this node.
    params: u64,
    /// At least one `SelfParam` op sits on this node.
    receiver: bool,
}

/// Extract the structural shape of the return value taint from an
/// inline-analyzed callee.
///
/// Replays `transfer_block` on converged return-block states and classifies
/// each contributing origin as either **callee-internal** (originated from a
/// `Source`/`CatchParam` op inside the callee body) or **caller-seeded**
/// (propagated through a `Param`/`SelfParam` op; its `node` points at the
/// callee's Param NodeIndex).
///
/// Caller-seeded origins are *not* baked into the cached shape — their
/// identity depends on the caller's argument chain, which varies across call
/// sites with matching cap signatures.  Instead, the origin position is
/// recorded as a bit in [`ReturnShape::param_provenance`] (or the
/// `receiver_provenance` flag), and the actual caller origins are re-unioned
/// in by [`apply_cached_shape`] on each cache hit.
///
/// Callee-internal origins *are* baked in: they carry `source_span` from the
/// callee CFG (stable across callers) and a placeholder `node` that the
/// applying caller overwrites with its own call-site NodeIndex.
fn extract_inline_return_taint(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    block_states: &[Option<SsaTaintState>],
    induction_vars: &HashSet<SsaValue>,
) -> CachedInlineShape {
    // Collect all param SSA values to separate from derived values
    let param_values: HashSet<SsaValue> = ssa
        .blocks
        .iter()
        .flat_map(|b| b.phis.iter().chain(b.body.iter()))
        .filter(|i| matches!(i.op, SsaOp::Param { .. }))
        .map(|i| i.value)
        .collect();

    // Map callee Param/SelfParam NodeIndex → union of provenance bits so
    // we can identify caller-seeded origins by inspecting `orig.node`
    // (which was rewritten to the Param's cfg_node in
    // `transfer_inst::SsaOp::Param`).  Multiple Param ops may share a
    // cfg_node (synthetic external-var params emitted at the entry), so
    // a HashMap<NodeIndex, single-value> would lose information; we
    // union provenance bits per node instead.
    let mut param_node_map: HashMap<NodeIndex, CalleeParamNodeBits> = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                SsaOp::Param { index } => {
                    let entry = param_node_map.entry(inst.cfg_node).or_default();
                    if *index < 64 {
                        entry.params |= 1u64 << *index;
                    }
                }
                SsaOp::SelfParam => {
                    let entry = param_node_map.entry(inst.cfg_node).or_default();
                    entry.receiver = true;
                }
                _ => {}
            }
        }
    }

    // Callee-internal origins carry their span from the callee CFG (lazily
    // filled when missing) but have `node` set to a placeholder — the
    // applying call site fills in its own call-site NodeIndex via
    // `apply_cached_shape`.
    //
    // `node` is initialized to `NodeIndex::end()` (the max-u32 sentinel) so
    // a forgotten override is loud (indexing it later panics) rather than
    // silently rendering wrong spans.
    let placeholder_node = NodeIndex::end();
    let prep_internal = |o: &TaintOrigin| -> TaintOrigin {
        let mut out = *o;
        if out.source_span.is_none() {
            if let Some(info) = cfg.node_weight(o.node) {
                out.source_span = Some(info.classification_span());
            }
        }
        out.node = placeholder_node;
        out
    };

    let push_internal = |target: &mut SmallVec<[TaintOrigin; 2]>, orig: &TaintOrigin| {
        let new_orig = prep_internal(orig);
        if target.len() < effective_max_origins()
            && !target.iter().any(|o| {
                o.source_span == new_orig.source_span && o.source_kind == new_orig.source_kind
            })
        {
            target.push(new_orig);
        }
    };

    let mut derived_caps = Cap::empty();
    let mut derived_internal: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut derived_params: u64 = 0;
    let mut derived_receiver: bool = false;

    let mut param_caps = Cap::empty();
    let mut param_internal: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut param_params: u64 = 0;
    let mut param_receiver: bool = false;

    let classify_and_push = |orig: &TaintOrigin,
                             internal: &mut SmallVec<[TaintOrigin; 2]>,
                             provenance: &mut u64,
                             receiver_prov: &mut bool| {
        match param_node_map.get(&orig.node) {
            Some(bits) => {
                *provenance |= bits.params;
                if bits.receiver {
                    *receiver_prov = true;
                }
            }
            None => {
                push_internal(internal, orig);
            }
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
                if let Some(taint) = exit.get(rv) {
                    if param_values.contains(&rv) {
                        param_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut param_internal,
                                &mut param_params,
                                &mut param_receiver,
                            );
                        }
                    } else {
                        derived_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut derived_internal,
                                &mut derived_params,
                                &mut derived_receiver,
                            );
                        }
                    }
                }
            } else {
                // Return(None): implicit return / empty body.
                // Fall back to collecting all live values.
                for (val, taint) in &exit.values {
                    if param_values.contains(val) {
                        param_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut param_internal,
                                &mut param_params,
                                &mut param_receiver,
                            );
                        }
                    } else {
                        derived_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut derived_internal,
                                &mut derived_params,
                                &mut derived_receiver,
                            );
                        }
                    }
                }
            }
        }
    }

    // Prefer derived caps; fall back to param-return caps for passthrough functions.
    let (final_caps, final_internal, final_params, final_receiver) = if !derived_caps.is_empty() {
        (
            derived_caps,
            derived_internal,
            derived_params,
            derived_receiver,
        )
    } else {
        (param_caps, param_internal, param_params, param_receiver)
    };

    if final_caps.is_empty() && final_params == 0 && !final_receiver && final_internal.is_empty() {
        return CachedInlineShape(None);
    }

    CachedInlineShape(Some(ReturnShape {
        caps: final_caps,
        internal_origins: final_internal,
        param_provenance: final_params,
        receiver_provenance: final_receiver,
        uses_summary: true, // inline analysis is a form of summary
    }))
}

/// Re-attribute a [`CachedInlineShape`] to a specific call site.
///
/// Called on every inline-analysis return (both cache miss and cache hit) so
/// that `InlineResult.return_taint.origins` always reflect the *current*
/// caller's argument chain.  See the module-level note on cache-vs-origin
/// attribution.
///
/// # Attribution rules
///
/// * **Internal origins** (recorded by the callee's `Source` ops): cloned
///   with `node` overwritten to `call_site_node`; `source_span` preserved
///   from the callee CFG.
/// * **Param-provenance bits**: for each set bit `i`, union caller's arg
///   origins at position `i` into the result.  Receiver provenance does the
///   same for `receiver`.
/// * **Truncation**: the combined origin set is capped at
///   [`effective_max_origins`]; when any origins are dropped,
///   [`EngineNote::OriginsTruncated`] is recorded via
///   [`record_engine_note`].
fn apply_cached_shape(
    shape: &CachedInlineShape,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    call_site_node: NodeIndex,
) -> InlineResult {
    let Some(ret) = shape.0.as_ref() else {
        return InlineResult { return_taint: None };
    };

    let cap = effective_max_origins();
    let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut dropped: u32 = 0;

    let push =
        |origins: &mut SmallVec<[TaintOrigin; 2]>, dropped: &mut u32, new_orig: TaintOrigin| {
            if origins.iter().any(|o| {
                o.node == new_orig.node
                    && o.source_span == new_orig.source_span
                    && o.source_kind == new_orig.source_kind
            }) {
                return;
            }
            if origins.len() < cap {
                origins.push(new_orig);
            } else {
                *dropped += 1;
            }
        };

    // 1. Callee-internal origins: rewrite `node` to the current call site.
    for orig in &ret.internal_origins {
        let mut o = *orig;
        o.node = call_site_node;
        push(&mut origins, &mut dropped, o);
    }

    // 2. Caller-attributed origins from param-provenance bits.
    let mut bits = ret.param_provenance;
    while bits != 0 {
        let idx = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        if let Some(arg_vals) = args.get(idx) {
            for v in arg_vals {
                if let Some(taint) = state.get(*v) {
                    for orig in &taint.origins {
                        push(&mut origins, &mut dropped, *orig);
                    }
                }
            }
        }
    }

    // 3. Receiver-attributed origins (SelfParam provenance).
    if ret.receiver_provenance {
        if let Some(rv) = receiver {
            if let Some(taint) = state.get(*rv) {
                for orig in &taint.origins {
                    push(&mut origins, &mut dropped, *orig);
                }
            }
        }
    }

    if dropped > 0 {
        record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated { dropped });
    }

    InlineResult {
        return_taint: Some(VarTaint {
            caps: ret.caps,
            origins,
            uses_summary: ret.uses_summary,
        }),
    }
}

/// Transfer a single SSA instruction.
pub(super) fn transfer_inst(
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let info = &cfg[inst.cfg_node];

    // Cross-file abstract return fact from callee resolution.
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
                            if return_origins.len() < effective_max_origins()
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
            // Captured alongside container fields because the
            // callee_summary gets moved when the main taint branch takes it
            // below.  We only need the points_to summary itself — clone it
            // out before the move so application can still read it.
            let mut resolved_points_to: crate::summary::points_to::PointsToSummary =
                crate::summary::points_to::PointsToSummary::empty();

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
                resolved_points_to = resolved.points_to.clone();

                // Capture abstract return for post-transfer injection
                callee_return_abstract = resolved.return_abstract.clone();

                // Apply per-parameter abstract transfers.
                //
                // For each (param_idx, transfer) in the callee's summary,
                // apply the transfer to the caller's current abstract value
                // of the argument at that position.  Join the per-parameter
                // contributions (disjunctive: any transfer's output is a
                // valid over-approximation of the return), then `meet` with
                // the baseline `return_abstract` (both facts must hold).
                //
                // Runs regardless of whether inline analysis already
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

                // Per-parameter predicate-consistent transforms.
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
                                if return_origins.len() < effective_max_origins()
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
                            if return_origins.len() < effective_max_origins()
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
                        if return_origins.len() < effective_max_origins()
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
                                            if input_origins.len() < effective_max_origins()
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
                                    if src_origins.len() < effective_max_origins()
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

            // Parameter-granularity points-to summary application.
            //
            // Extends the container-store channel above (which catches
            // `arr.push(v)` / `map.set(k, v)`) to direct field writes like
            // `obj.x = val` that `classify_container_op` does not recognise.
            // The callee's `PointsToSummary` records May-alias edges between
            // parameter positions and the return; at the call site we replay
            // each edge against the caller's taint state.
            //
            //   * `Param(src) → Param(dst)` — union caller-arg[src]'s taint
            //     into caller-arg[dst]'s heap slot.  Sound because the
            //     callee *may* have stored data derived from arg[src] into
            //     an alias of arg[dst]; the caller must assume any later
            //     read from arg[dst] could surface that taint.
            //   * `Param(src) → Return` — union caller-arg[src]'s points-to
            //     set into the call's return value, giving the result the
            //     same heap identity as its input argument.  Overlaps with
            //     `param_container_to_return`; both channels are idempotent
            //     so re-propagation is safe.
            //
            // Fresh-container factory synthesis: when the callee's
            // `PointsToSummary` marks a return path as a fresh allocation
            // (container literal or known constructor not tracing to any
            // parameter), synthesise a `HeapObjectId` keyed on the call's
            // SSA value and seed it into `dynamic_pts`.  This closes the
            // factory-pattern cross-file gap — `const bag = makeBag()`
            // gives `bag` a stable heap identity so subsequent
            // `fillBag(bag, …)` / `bag[0]` operations have a heap cell
            // to store into or read from.
            //
            // Strictly additive: the existing `Param(i) → Return` edge
            // handling below joins the caller's argument pts when the
            // function also returns a parameter on some path, so a mixed
            // factory (`if (x) return []; else return arg`) carries both
            // the synthetic fresh cell and the aliased argument cells.
            if resolved_points_to.returns_fresh_alloc
                && let Some(dyn_ref) = transfer.dynamic_pts
            {
                let fresh = PointsToSet::singleton(HeapObjectId(inst.value));
                let mut dyn_pts = dyn_ref.borrow_mut();
                match dyn_pts.get(&inst.value) {
                    Some(existing) => {
                        let merged = existing.union(&fresh);
                        dyn_pts.insert(inst.value, merged);
                    }
                    None => {
                        dyn_pts.insert(inst.value, fresh);
                    }
                }
            }

            // Overflow (the callee's alias graph exceeded
            // `MAX_ALIAS_EDGES`): conservatively treat *every* parameter
            // as aliasing every other parameter and the return.
            if resolved_points_to.overflow || !resolved_points_to.edges.is_empty() {
                use crate::summary::points_to::AliasPosition;

                // Effective edge set: when overflow is signalled, synthesise
                // the conservative all-pairs graph instead of reading the
                // possibly-truncated edge vector.
                type ParamToParamEdges = SmallVec<[(usize, usize); 8]>;
                type ParamToReturnEdges = SmallVec<[usize; 4]>;
                let (param_to_param_edges, param_to_return_edges): (
                    ParamToParamEdges,
                    ParamToReturnEdges,
                ) = if resolved_points_to.overflow {
                    let n = args.len();
                    let mut p2p: SmallVec<[(usize, usize); 8]> = SmallVec::new();
                    let mut p2r: SmallVec<[usize; 4]> = SmallVec::new();
                    for i in 0..n {
                        p2r.push(i);
                        for j in 0..n {
                            if i != j {
                                p2p.push((i, j));
                            }
                        }
                    }
                    (p2p, p2r)
                } else {
                    let mut p2p: SmallVec<[(usize, usize); 8]> = SmallVec::new();
                    let mut p2r: SmallVec<[usize; 4]> = SmallVec::new();
                    for edge in &resolved_points_to.edges {
                        match (edge.source, edge.target) {
                            (AliasPosition::Param(s), AliasPosition::Param(t)) => {
                                p2p.push((s as usize, t as usize));
                            }
                            (AliasPosition::Param(s), AliasPosition::Return) => {
                                p2r.push(s as usize);
                            }
                            // Return → Param / Return → Return are not emitted
                            // by the points-to analysis; ignore defensively.
                            _ => {}
                        }
                    }
                    (p2p, p2r)
                };

                // Apply Param → Param edges: caller-arg[src] taint into
                // caller-arg[dst]'s heap objects *and* directly onto the
                // destination SSA value.  Store-into-heap handles later
                // container-style reads from `dst`'s pts set; the direct
                // taint ensures field reads expressed as `Assign uses=[dst]`
                // (the common case when the caller's heap analysis did
                // not register an allocation site for `dst`) still surface
                // the aliased taint.
                //
                // The loop must borrow `state` mutably (for the heap
                // store and the direct taint merge), so it is written
                // inline instead of split across helper closures.
                for (src, dst) in &param_to_param_edges {
                    // Collect src arg taint.
                    let mut src_caps = Cap::empty();
                    let mut src_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                    if let Some(arg_vals) = args.get(*src) {
                        for &v in arg_vals {
                            if let Some(taint) = state.get(v) {
                                src_caps |= taint.caps;
                                for orig in &taint.origins {
                                    if src_origins.len() < effective_max_origins()
                                        && !src_origins.iter().any(|o| o.node == orig.node)
                                    {
                                        src_origins.push(*orig);
                                    }
                                }
                            }
                        }
                    }
                    if src_caps.is_empty() {
                        continue;
                    }
                    // Collect dst arg points-to for heap-level
                    // propagation (cloned out so the mutable
                    // `state.heap` borrow below is independent of the
                    // immutable PTS lookup).
                    let mut dst_pts: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                    let mut dst_ssa_vals: SmallVec<[SsaValue; 2]> = SmallVec::new();
                    if let Some(arg_vals) = args.get(*dst) {
                        for &v in arg_vals {
                            dst_ssa_vals.push(v);
                            if let Some(pts) = lookup_pts(transfer, v) {
                                dst_pts.push(pts);
                            }
                        }
                    }
                    for pts in &dst_pts {
                        state
                            .heap
                            .store_set(pts, HeapSlot::Elements, src_caps, &src_origins);
                    }
                    // Direct-taint the dst SSA value(s).  Required when
                    // the caller's heap analysis has no allocation site
                    // for `dst` (common for plain class constructors in
                    // Python / JS / Java without fine-grained
                    // points-to).  Without this, later reads expressed
                    // as Assigns over `dst` would see no taint.
                    for dv in &dst_ssa_vals {
                        merge_taint_into(state, *dv, src_caps, &src_origins);
                    }
                }

                // Apply Param → Return edges: the call result inherits the
                // source argument's points-to set.  Re-runs the same
                // channel `resolved_container_to_return` drives a few
                // lines above — safe (idempotent union), and catches
                // cases where the callee returned a param through a
                // non-identity chain (e.g. `return Box::new(x)`).
                if !param_to_return_edges.is_empty()
                    && let Some(dyn_ref) = transfer.dynamic_pts
                {
                    for src in &param_to_return_edges {
                        let mut src_pts: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                        if let Some(arg_vals) = args.get(*src) {
                            for &v in arg_vals {
                                if let Some(pts) = lookup_pts(transfer, v) {
                                    src_pts.push(pts);
                                }
                            }
                        }
                        if src_pts.is_empty() {
                            continue;
                        }
                        let mut dyn_pts = dyn_ref.borrow_mut();
                        for pts in &src_pts {
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
                            if combined_origins.len() < effective_max_origins()
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
                    if combined_origins.len() < effective_max_origins()
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
            // Seeding order for inbound taint on this body's param:
            //   1. Per-call-site seed (inline analysis only).
            //      `param_seed[index]` for `Param { index }`, or
            //      `receiver_seed` for `SelfParam`.  Takes precedence
            //      because it reflects the exact caller argument taint
            //      for this specific call.
            //   2. Lexical-scope seed (`global_seed`), read in ancestor
            //      order: parent body first, then the top-level scope
            //      (`BodyId(0)`) to pick up re-keyed JS/TS combined_exit
            //      entries (see `filter_seed_to_toplevel`).
            //
            // `SelfParam` receives the same treatment as positional `Param`:
            // both represent inbound values whose taint comes from the
            // surrounding scope.
            let mut seeded_from_scope = false;

            // Step 1: per-call-site seed for inline analysis.
            let per_call_taint: Option<&VarTaint> = match &inst.op {
                SsaOp::Param { index } => transfer
                    .param_seed
                    .and_then(|ps| ps.get(*index))
                    .and_then(|slot| slot.as_ref()),
                SsaOp::SelfParam => transfer.receiver_seed,
                _ => None,
            };
            if let Some(taint) = per_call_taint {
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

            // Step 2: lexical-scope seed via ancestor-chain lookup.
            if !seeded_from_scope {
                if let Some(seed) = &transfer.global_seed {
                    if let Some(var_name) = ssa
                        .value_defs
                        .get(inst.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    {
                        // Ancestor chain: parent body first (for direct
                        // lexical captures), then BodyId(0) (for JS/TS
                        // pass-2 re-keyed entries).  Deduplicated so a
                        // body whose parent is already the top-level
                        // only looks up once.
                        let mut ancestors: SmallVec<[BodyId; 2]> = SmallVec::new();
                        if let Some(pid) = transfer.parent_body_id {
                            ancestors.push(pid);
                        }
                        if !ancestors.contains(&BodyId(0)) {
                            ancestors.push(BodyId(0));
                        }

                        for body_id in ancestors {
                            let key = BindingKey::new(var_name, body_id);
                            if let Some(taint) = seed_lookup(seed, &key) {
                                // Remap origins to this body's Param cfg_node:
                                // the meaningful anchor where taint enters
                                // this body.  Preserve source_span for
                                // diagnostics (captured in
                                // extract_ssa_exit_state).
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
                                break;
                            }
                        }
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

    // Constraint propagation through instructions
    if let Some(ref mut env) = state.path_env {
        match &inst.op {
            SsaOp::Assign(uses) if uses.len() == 1 => {
                // Copy: propagate facts from source to destination
                let src_fact = env.get(uses[0]);
                if !src_fact.is_top() {
                    env.refine(inst.value, &src_fact);
                    env.assert_equal(inst.value, uses[0]);
                }
                // Cast/assertion type narrowing.
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

    // Forward abstract value transfer
    if let Some(ref mut abs) = state.abstract_state {
        transfer_abstract(inst, cfg, abs);
    }

    // Cross-file abstract return injection.
    // Applied after transfer_abstract so summary-provided facts override the
    // default Top that transfer_abstract assigns to unknown callees.
    if let Some(ref abs_val) = callee_return_abstract {
        if let Some(ref mut abs) = state.abstract_state {
            abs.set(inst.value, abs_val.clone());
        }
    }
}

/// Compute abstract values for an SSA instruction.
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
            // Single-use Assign with bin_op + literal operand.
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

/// Collect events from a block.
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
                        if combined_origins.len() < effective_max_origins()
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

    // Replay abstract value phi join (from predecessor exit states).
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
                                    // Pick callback-path sink sites.
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

        // Receiver type incompatibility check.
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

        // Go interface satisfaction check.
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

        // Path-sensitive type-safe sink filtering.
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

        // Abstract-domain-aware sink suppression.
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
        // Call-site abstract suppression.
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

            // Pick primary sink sites (if any) from the resolved callee
            // summary.  Multi-site cases emit one event per matching
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

// ── Primary sink-site attribution ───────────────────────────────────────

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
                    if combined_origins.len() < effective_max_origins()
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
                        if combined_origins.len() < effective_max_origins()
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
                            if combined_origins.len() < effective_max_origins()
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
                    if url_origins.len() < effective_max_origins()
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
                    if url_origins.len() < effective_max_origins()
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
                if merged.origins.len() < effective_max_origins()
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
                                if val_origins.len() < effective_max_origins()
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
                if merged.origins.len() < effective_max_origins()
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
    /// coordinates.  Used to attribute findings to the dangerous
    /// callee-internal instruction.
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
                if merged_origins.len() < effective_max_origins()
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

    // 2. Try flow-sensitive type from PathEnv
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

// ── Centralized Type-Sink Compatibility Helpers ──────────────────────────

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

// ── Abstract-Domain Sink Suppression ────────────────────────────────────

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
    /// Abstract domain fact for the return value.
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
    /// Per-parameter abstract-domain transfer channels.
    ///
    /// Populated only when the callee was resolved via an SSA summary
    /// (`convert_ssa_to_resolved`).  The label, local-summary, interop
    /// and coarse `FuncSummary` paths carry `Vec::new()` because those
    /// forms do not record abstract-domain behaviour.  Applied at the
    /// call site to synthesise an abstract return value from the
    /// caller's knowledge of each argument.
    abstract_transfer: Vec<(usize, crate::abstract_interp::AbstractTransfer)>,
    /// Per-parameter return-path decomposition.
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
    /// Parameter-granularity points-to summary.
    ///
    /// Populated only via `convert_ssa_to_resolved`; other resolution
    /// paths leave it empty (they do not derive alias edges).  Empty /
    /// default means "no aliasing beyond what param_to_container_store
    /// already captures" — the caller treats the call as a pure
    /// taint-through-signature edge.
    points_to: crate::summary::points_to::PointsToSummary,
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
                    points_to: Default::default(),
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
                    points_to: Default::default(),
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
                points_to: Default::default(),
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
                        // Carry [`SinkSite`]s from the global FuncSummary
                        // so cross-file findings can attribute to the
                        // callee-internal dangerous instruction.
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
                        points_to: Default::default(),
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
                points_to: Default::default(),
            });
        }
    }

    None
}

/// Compute the effective sanitizer bits that apply at the call site for a
/// specific parameter, narrowed by the caller's predicate state.
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
        points_to: ssa_sum.points_to.clone(),
    }
}
