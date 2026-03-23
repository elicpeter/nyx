use crate::callgraph::normalize_callee_name;
use crate::cfg::{Cfg, FuncSummaries, NodeInfo};
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, SourceKind};
use crate::ssa::ir::*;
use crate::state::lattice::Lattice;
use crate::summary::{CalleeResolution, GlobalSummaries};
use crate::symbol::Lang;
use crate::state::symbol::{SymbolId, SymbolInterner};
use crate::taint::domain::{PredicateSummary, SmallBitSet, TaintOrigin, VarTaint, predicate_kind_bit};
use crate::taint::path_state::{PredicateKind, classify_condition_with_target};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum origins tracked per SSA value.
const MAX_ORIGINS: usize = 4;

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
}

impl SsaTaintState {
    pub fn initial() -> Self {
        Self {
            values: SmallVec::new(),
            validated_must: SmallBitSet::empty(),
            validated_may: SmallBitSet::empty(),
            predicates: SmallVec::new(),
        }
    }

    /// Check if any variable has contradictory predicates.
    pub fn has_contradiction(&self) -> bool {
        self.predicates.iter().any(|(_, s)| s.has_contradiction())
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
        SsaTaintState { values, validated_must, validated_may, predicates }
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
                result.push((a[i].0, VarTaint { caps, origins, uses_summary }));
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
            std::cmp::Ordering::Less => { i += 1; }
            std::cmp::Ordering::Greater => { j += 1; }
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

// ── SSA Taint Transfer ──────────────────────────────────────────────────

/// Configuration for SSA taint analysis.
pub struct SsaTaintTransfer<'a> {
    pub lang: Lang,
    pub namespace: &'a str,
    pub interner: &'a SymbolInterner,
    pub local_summaries: &'a FuncSummaries,
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub interop_edges: &'a [InteropEdge],
    /// SymbolId-keyed taint from top-level scope (JS/TS two-level solve).
    /// Read-only fallback for Param ops representing external variables.
    pub global_seed: Option<&'a HashMap<SymbolId, VarTaint>>,
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
}

/// Per-predecessor state tracking for path-sensitive phi evaluation.
/// Maps (successor_block_idx, predecessor_block_idx) → predecessor's exit state.
type PredStates = HashMap<(usize, usize), SsaTaintState>;

/// Run SSA-based taint analysis, returning events AND converged block states.
pub fn run_ssa_taint_full(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> (Vec<SsaTaintEvent>, Vec<Option<SsaTaintState>>) {
    let num_blocks = ssa.blocks.len();

    // Detect induction variables before analysis
    let back_edges = detect_back_edges(ssa);
    let induction_vars = detect_induction_phis(ssa, &back_edges);

    // Per-block entry states
    let mut block_states: Vec<Option<SsaTaintState>> = vec![None; num_blocks];
    block_states[ssa.entry.0 as usize] = Some(SsaTaintState::initial());

    // Per-predecessor exit states for path-sensitive phi evaluation
    let mut pred_states: PredStates = HashMap::new();

    // Phase 1: fixed-point iteration
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(ssa.entry.0 as usize);

    // Initialize orphan blocks (no predecessors, not entry) with initial state.
    // This handles catch blocks that are disconnected after exception edge stripping.
    for (bid, block) in ssa.blocks.iter().enumerate() {
        if bid != ssa.entry.0 as usize && block.preds.is_empty() {
            block_states[bid] = Some(SsaTaintState::initial());
            worklist.push_back(bid);
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
            block, cfg, ssa, transfer, entry_state,
            &induction_vars, Some(&pred_states),
        );

        // Build per-successor states (branch-aware for Branch terminators)
        let succ_states = compute_succ_states(block, cfg, transfer, &exit_state);

        // Store predecessor-specific states before joining
        for &(succ_id, ref succ_state) in &succ_states {
            let succ_idx = succ_id.0 as usize;
            pred_states.insert((succ_idx, bid), succ_state.clone());
        }

        // Propagate to successors
        for (succ_id, succ_state) in succ_states {
            let succ_idx = succ_id.0 as usize;

            let new_succ_state = match &block_states[succ_idx] {
                Some(existing) => existing.join(&succ_state),
                None => succ_state,
            };

            let changed = block_states[succ_idx]
                .as_ref()
                .is_none_or(|existing| *existing != new_succ_state);

            if changed {
                block_states[succ_idx] = Some(new_succ_state);
                if !worklist.contains(&succ_idx) {
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


            let new_catch_state = match &block_states[catch_idx] {
                Some(existing) => existing.join(&exc_state),
                None => exc_state,
            };

            let changed = block_states[catch_idx]
                .as_ref()
                .is_none_or(|existing| *existing != new_catch_state);

            if changed {
                block_states[catch_idx] = Some(new_catch_state);
                if !worklist.contains(&catch_idx) {
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
            block, cfg, ssa, transfer, entry_state, &mut events,
            &induction_vars, Some(&pred_states),
        );
    }

    (events, block_states)
}

/// Convenience wrapper: returns only events (existing signature).
pub fn run_ssa_taint(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> Vec<SsaTaintEvent> {
    run_ssa_taint_full(ssa, cfg, transfer).0
}

/// Project SsaValue-keyed taint back to SymbolId-keyed taint via var_name lookup.
/// Recomputes exit states from converged entry states, then maps SsaValue → var_name → SymbolId.
pub fn extract_ssa_exit_state(
    block_states: &[Option<SsaTaintState>],
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    interner: &SymbolInterner,
) -> HashMap<SymbolId, VarTaint> {
    // Compute exit states by replaying transfer on converged entry states
    let empty_induction = HashSet::new();
    let mut joined = SsaTaintState::initial();
    for (bid, entry_state) in block_states.iter().enumerate() {
        if let Some(state) = entry_state {
            let exit_state = transfer_block(
                &ssa.blocks[bid], cfg, ssa, transfer, state.clone(),
                &empty_induction, None,
            );
            joined = joined.join(&exit_state);
        }
    }

    // Map SsaValue → var_name → SymbolId
    let mut result: HashMap<SymbolId, VarTaint> = HashMap::new();
    for (val, taint) in &joined.values {
        let var_name = ssa.value_defs.get(val.0 as usize)
            .and_then(|vd| vd.var_name.as_deref());
        if let Some(name) = var_name {
            if let Some(sym) = interner.get(name) {
                result.entry(sym)
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
    }

    result
}

/// Join two SymbolId-keyed seed maps (OR caps, merge origins).
pub fn join_seed_maps(
    a: &HashMap<SymbolId, VarTaint>,
    b: &HashMap<SymbolId, VarTaint>,
) -> HashMap<SymbolId, VarTaint> {
    let mut result = a.clone();
    for (sym, taint) in b {
        result.entry(*sym)
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

/// Filter seed map to only include symbols in the given set.
pub fn filter_seed_to_toplevel(
    seed: &HashMap<SymbolId, VarTaint>,
    toplevel: &std::collections::HashSet<SymbolId>,
) -> HashMap<SymbolId, VarTaint> {
    seed.iter()
        .filter(|(sym, _)| toplevel.contains(sym))
        .map(|(sym, taint)| (*sym, taint.clone()))
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
fn detect_induction_phis(ssa: &SsaBody, back_edges: &HashSet<(BlockId, BlockId)>) -> HashSet<SsaValue> {
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
                            let var_name = ssa.value_defs.get(operand_val.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref());
                            if let Some(name) = var_name {
                                if let Some(sym) = transfer.interner.get(name) {
                                    if !pred_st.validated_may.contains(sym) {
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
                    if let Some(name) = ssa.value_defs.get(phi.value.0 as usize)
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
    transfer: &SsaTaintTransfer,
    exit_state: &SsaTaintState,
) -> SmallVec<[(BlockId, SsaTaintState); 2]> {
    match &block.terminator {
        Terminator::Branch { cond, true_blk, false_blk } => {
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
                let has_semantic_negation =
                    (kind == PredicateKind::AllowlistCheck && cond_lower.contains(" not in "))
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

                // Contradiction pruning
                if true_state.has_contradiction() {
                    true_state = SsaTaintState::bot();
                }
                if false_state.has_contradiction() {
                    false_state = SsaTaintState::bot();
                }

                smallvec::smallvec![
                    (*true_blk, true_state),
                    (*false_blk, false_state),
                ]
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
        Terminator::Return | Terminator::Unreachable => {
            SmallVec::new()
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
    if matches!(kind, PredicateKind::ValidationCall | PredicateKind::AllowlistCheck | PredicateKind::TypeCheck) && polarity {
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
                let mut summary = state.predicates
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

/// Transfer a single SSA instruction.
fn transfer_inst(
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let info = &cfg[inst.cfg_node];

    match &inst.op {
        SsaOp::Source => {
            // Apply source labels from NodeInfo
            let mut source_caps = Cap::empty();
            for lbl in &info.labels {
                if let DataLabel::Source(bits) = lbl {
                    source_caps |= *bits;
                }
            }
            if !source_caps.is_empty() {
                let callee = info.callee.as_deref().unwrap_or("");
                let source_kind = crate::labels::infer_source_kind(source_caps, callee);
                let origin = TaintOrigin {
                    node: inst.cfg_node,
                    source_kind,
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

            for lbl in &info.labels {
                if let DataLabel::Source(bits) = lbl {
                    return_bits |= *bits;
                    let callee_str = info.callee.as_deref().unwrap_or("");
                    let source_kind = crate::labels::infer_source_kind(*bits, callee_str);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                    };
                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                        return_origins.push(origin);
                    }
                }
            }

            // Check for sanitizer labels
            let mut sanitizer_bits = Cap::empty();
            for lbl in &info.labels {
                if let DataLabel::Sanitizer(bits) = lbl {
                    sanitizer_bits |= *bits;
                }
            }

            // Resolve callee summary — always attempt, even when explicit
            // labels are present. Labels take precedence for source caps, but
            // summary propagation and sanitizer behaviour must still apply
            // (matches legacy `apply_call()` semantics).
            let caller_func = info.enclosing_func.as_deref().unwrap_or("");
            let has_source_label = info
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)));

            let mut resolved_callee = false;
            if let Some(resolved) =
                resolve_callee(transfer, callee, caller_func, info.call_ordinal)
            {
                resolved_callee = true;

                // Source caps from summary: only when no explicit Source label
                if !has_source_label && !resolved.source_caps.is_empty() {
                    return_bits |= resolved.source_caps;
                    let source_kind = crate::labels::infer_source_kind(
                        resolved.source_caps,
                        callee,
                    );
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                    };
                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                        return_origins.push(origin);
                    }
                }

                // Propagation: ALWAYS apply
                if resolved.propagates_taint {
                    // Only use positional filtering when original arg_uses is populated
                    let effective_params = if info.arg_uses.is_empty() {
                        &[] as &[usize]
                    } else {
                        &resolved.propagating_params
                    };
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

                // Summary sanitizer: ALWAYS apply
                return_bits &= !resolved.sanitizer_caps;
            }

            // Type-qualified receiver resolution: when normal callee resolution
            // failed and explicit labels are absent, try constructing a type-qualified
            // callee name from the receiver's inferred type (e.g., client.send →
            // HttpClient.send when client is typed as HttpClient).
            if !resolved_callee && info.labels.is_empty() {
                if let Some(rv) = receiver {
                    if let Some(type_facts) = transfer.type_facts {
                        let tq_labels = resolve_type_qualified_labels(
                            callee, *rv, type_facts, transfer.lang, transfer.extra_labels,
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
                let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
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
                // Curl special case: propagate URL taint to handle
                if try_curl_url_propagation(inst, info, args, state) {
                    return;
                }
                // No labels and no summary — default propagation (gen/kill)
                let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
                if return_bits.is_empty() {
                    return_bits = use_caps;
                    return_origins = use_origins;
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
            for lbl in &info.labels {
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

            // Check for source labels
            for lbl in &info.labels {
                if let DataLabel::Source(bits) = lbl {
                    combined_caps |= *bits;
                    let callee_str = info.callee.as_deref().unwrap_or("");
                    let source_kind = crate::labels::infer_source_kind(*bits, callee_str);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                    };
                    if combined_origins.len() < MAX_ORIGINS
                        && !combined_origins.iter().any(|o| o.node == inst.cfg_node)
                    {
                        combined_origins.push(origin);
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
            // Seed from global scope (JS/TS two-level solve)
            if let Some(seed) = &transfer.global_seed {
                if let Some(var_name) = ssa.value_defs.get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if let Some(sym) = transfer.interner.get(var_name) {
                        if let Some(taint) = seed.get(&sym) {
                            state.set(inst.value, taint.clone());
                        }
                    }
                }
            }
        }

        SsaOp::Phi(_) => {
            // Phis processed separately above — shouldn't appear in body
        }
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
                            let var_name = ssa.value_defs.get(operand_val.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref());
                            if let Some(name) = var_name {
                                if let Some(sym) = transfer.interner.get(name) {
                                    if !pred_st.validated_may.contains(sym) {
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
                    if let Some(name) = ssa.value_defs.get(phi.value.0 as usize)
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

    // Process body with sink detection
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);

        // Check for sink
        let info = &cfg[inst.cfg_node];
        if info.all_args_literal {
            continue;
        }

        let mut sink_caps = resolve_sink_caps(info, transfer);

        // Type-qualified sink resolution: when normal sink resolution found nothing,
        // try using the receiver's inferred type to construct a qualified callee name.
        if sink_caps.is_empty() {
            if let SsaOp::Call { callee, receiver: Some(rv), .. } = &inst.op {
                if let Some(type_facts) = transfer.type_facts {
                    let tq_labels = resolve_type_qualified_labels(
                        callee, *rv, type_facts, transfer.lang, transfer.extra_labels,
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
                let caller_func = info.enclosing_func.as_deref().unwrap_or("");
                if let Some(resolved) = resolve_callee(transfer, inner_callee, caller_func, 0) {
                    sink_caps &= !resolved.sanitizer_caps;
                } else {
                    // Fallback: check label classification (built-in + custom rules).
                    // This handles sanitizers that have no function summary (e.g.
                    // external libraries like `escapeHtml`, `DOMPurify.sanitize`).
                    let lang_str = transfer.lang.as_str();
                    let labels = crate::labels::classify_all(
                        lang_str,
                        inner_callee,
                        transfer.extra_labels,
                    );
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

        // Collect tainted SSA values that flow into this sink
        let tainted = collect_tainted_sink_values(inst, info, &state, sink_caps);
        if !tainted.is_empty() {
            // Compute all_validated: check if all tainted vars are validated
            let all_validated = tainted.iter().all(|(val, _, _)| {
                let var_name = ssa.value_defs.get(val.0 as usize)
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
            let any_uses_summary = tainted.iter().any(|(val, _, _)| {
                state.get(*val).is_some_and(|t| t.uses_summary)
            });
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
        // Collect only from propagating param positions
        let offset = if receiver.is_some() { 1 } else { 0 };
        for &param_idx in propagating_params {
            let adj = param_idx + offset;
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
    if info.defines.is_some() {
        return false;
    }
    let callee = match info.callee.as_deref() {
        Some(c) if c.ends_with("curl_easy_setopt") => c,
        _ => return false,
    };
    if !info.uses.iter().any(|u| u == "CURLOPT_URL") {
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
    // Also check info.uses for identifiers that aren't callee, handle, or CURLOPT_URL
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

/// Resolve sink caps from labels or callee summary.
fn resolve_sink_caps(info: &NodeInfo, transfer: &SsaTaintTransfer) -> Cap {
    let label_sink_caps = info.labels.iter().fold(Cap::empty(), |acc, lbl| {
        if let DataLabel::Sink(caps) = lbl {
            acc | *caps
        } else {
            acc
        }
    });
    if !label_sink_caps.is_empty() {
        return label_sink_caps;
    }

    let caller_func = info.enclosing_func.as_deref().unwrap_or("");
    info.callee
        .as_ref()
        .and_then(|c| resolve_callee(transfer, c, caller_func, info.call_ordinal))
        .filter(|r| !r.sink_caps.is_empty())
        .map(|r| r.sink_caps)
        .unwrap_or(Cap::empty())
}

/// Collect tainted SSA values at a sink instruction.
fn collect_tainted_sink_values(
    inst: &SsaInst,
    info: &NodeInfo,
    state: &SsaTaintState,
    sink_caps: Cap,
) -> Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> {
    let mut result = Vec::new();

    // Collect SSA values used by this instruction
    let used_values = inst_use_values(inst);

    // If gated sink, filter to payload arg positions
    if let Some(ref positions) = info.sink_payload_args {
        if let SsaOp::Call { args, receiver, .. } = &inst.op {
            let offset = if receiver.is_some() { 1 } else { 0 };
            for &pos in positions {
                let adj = pos + offset;
                if let Some(arg_vals) = args.get(adj) {
                    for &v in arg_vals {
                        if let Some(taint) = state.get(v) {
                            if (taint.caps & sink_caps) != Cap::empty() {
                                result.push((v, taint.caps, taint.origins.clone()));
                            }
                        }
                    }
                }
            }
            return result;
        }
    }

    // Check all used values
    for v in used_values {
        if let Some(taint) = state.get(v) {
            if (taint.caps & sink_caps) != Cap::empty() {
                result.push((v, taint.caps, taint.origins.clone()));
            }
        }
    }

    result
}

/// Get all SSA values used by an instruction.
fn inst_use_values(inst: &SsaInst) -> Vec<SsaValue> {
    match &inst.op {
        SsaOp::Phi(operands) => operands.iter().map(|(_, v)| *v).collect(),
        SsaOp::Assign(uses) => uses.to_vec(),
        SsaOp::Call {
            args, receiver, ..
        } => {
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
fn resolve_type_qualified_labels(
    callee: &str,
    receiver: SsaValue,
    type_facts: &crate::ssa::type_facts::TypeFactResult,
    lang: Lang,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let receiver_type = match type_facts.get_type(receiver) {
        Some(tk) => tk,
        None => return SmallVec::new(),
    };
    let prefix = match receiver_type.label_prefix() {
        Some(p) => p,
        None => return SmallVec::new(),
    };
    // Extract the method part: last segment after '.'
    let method = callee.rsplit('.').next().unwrap_or(callee);
    let qualified = format!("{}.{}", prefix, method);
    crate::labels::classify_all(lang.as_str(), &qualified, extra_labels)
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

// ── Callee Resolution (mirrors TaintTransfer::resolve_callee) ───────────

struct ResolvedSummary {
    source_caps: Cap,
    sanitizer_caps: Cap,
    sink_caps: Cap,
    propagates_taint: bool,
    propagating_params: Vec<usize>,
}

fn resolve_callee(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
) -> Option<ResolvedSummary> {
    let normalized = normalize_callee_name(callee);

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
            propagates_taint: !ls.propagating_params.is_empty(),
            propagating_params: ls.propagating_params.clone(),
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
                        propagates_taint: fs.propagates_any(),
                        propagating_params: fs.propagating_params.clone(),
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
                propagates_taint: fs.propagates_any(),
                propagating_params: fs.propagating_params.clone(),
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
        propagates_taint: !propagating_params.is_empty(),
        propagating_params,
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
        var_name: cfg.node_weight(sink_node).and_then(|n| n.callee.clone()),
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
                let vals: SmallVec<[SsaValue; 4]> =
                    operands.iter().map(|(_, v)| *v).collect();
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
                    let flow_steps =
                        reconstruct_flow_path(*val, origin, event.sink_node, ssa, cfg);
                    findings.push(crate::taint::Finding {
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
fn extract_sink_arg_positions(
    event: &SsaTaintEvent,
    ssa: &SsaBody,
) -> Vec<usize> {
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
        let tainted_vals: HashSet<SsaValue> = event
            .tainted_values
            .iter()
            .map(|(v, _, _)| *v)
            .collect();

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
    let return_blocks: Vec<usize> = ssa.blocks.iter().enumerate()
        .filter(|(_, b)| matches!(b.terminator, Terminator::Return))
        .map(|(i, _)| i)
        .collect();

    // Collect all param SSA values to exclude from return cap collection.
    // Param values persist with their seeded taint throughout the function —
    // we only want caps on derived values (call results, assigns) at return.
    let all_param_values: std::collections::HashSet<SsaValue> = param_info
        .iter()
        .map(|(_, _, v)| *v)
        .collect();

    // Helper: run a taint probe with a given global_seed and return
    // (surviving_return_caps, sink_events).
    let run_probe = |seed: HashMap<SymbolId, VarTaint>| -> (Cap, Vec<SsaTaintEvent>) {
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
        };

        let (events, block_states) = run_ssa_taint_full(ssa, cfg, &transfer);

        // Collect surviving caps at return blocks.
        // Separate param values from derived values: derived values give
        // more precise transforms (they reflect function-internal sanitization).
        // If only param values reach return → pure passthrough (Identity).
        let mut derived_caps = Cap::empty();
        let mut param_caps = Cap::empty();
        for &bid in &return_blocks {
            if let Some(entry) = &block_states[bid] {
                let empty_induction = HashSet::new();
                let exit = transfer_block(
                    &ssa.blocks[bid], cfg, ssa, &transfer, entry.clone(),
                    &empty_induction, None,
                );
                for (val, taint) in &exit.values {
                    if all_param_values.contains(val) {
                        param_caps |= taint.caps;
                    } else {
                        derived_caps |= taint.caps;
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

        (return_caps, events)
    };

    // Probe with no params tainted → detect source_caps
    let (baseline_return_caps, _baseline_events) = run_probe(HashMap::new());
    let source_caps = baseline_return_caps;

    // Probe each param
    let mut param_to_return = Vec::new();
    let mut param_to_sink = Vec::new();
    let mut param_to_sink_param = Vec::new();

    for &(idx, ref var_name, _ssa_val) in &param_info {
        let sym = match interner.get(var_name) {
            Some(s) => s,
            None => continue,
        };

        let mut seed = HashMap::new();
        let origin = TaintOrigin {
            node: NodeIndex::new(0), // synthetic origin for probing
            source_kind: SourceKind::UserInput,
        };
        seed.insert(sym, VarTaint {
            caps: Cap::all(),
            origins: SmallVec::from_elem(origin, 1),
            uses_summary: false,
        });

        let (return_caps, events) = run_probe(seed);

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

    SsaFuncSummary {
        param_to_return,
        param_to_sink,
        source_caps,
        param_to_sink_param,
    }
}
