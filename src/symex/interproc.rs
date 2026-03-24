//! Interprocedural symbolic execution (Phase 24A).
//!
//! When a callee's `CalleeSsaBody` is available, the symbolic executor walks
//! the callee's SSA blocks as a nested frame instead of treating it as an
//! opaque `mk_call`.  Full symbolic state — return values, heap mutations,
//! taint, and path constraints — is propagated back to the caller.
//!
//! Resolution order in `transfer_inst` Call arm:
//!   container ops → string methods → **interprocedural execution** → summary → opaque mk_call.
//!
//! Transitive descent is supported: callee Call instructions can themselves
//! resolve to bodies, up to `InterprocCtx.max_depth`.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

use crate::callgraph::normalize_callee_name;
use crate::cfg::Cfg;
use crate::labels::{Cap, DataLabel};
use crate::ssa::ir::{BlockId, SsaBody, SsaOp, SsaValue, Terminator};
use crate::symbol::Lang;
use crate::taint::ssa_transfer::CalleeSsaBody;

use super::heap::{HeapKey, SymbolicHeap};
use super::state::{PathConstraint, SymbolicState};
use super::transfer::{self, SymexHeapCtx, SymexSummaryCtx};
use super::value::{mk_phi, SymbolicValue};

// ─────────────────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default max call depth (caller → callee → callee's callee → ...).
const DEFAULT_MAX_DEPTH: usize = 3;

/// Max callee blocks before declining to execute.
const MAX_CALLEE_BLOCKS: usize = 200;

/// Max transfer steps (phis + body instructions) per single callee frame.
const MAX_CALLEE_STEPS: usize = 200;

/// Max total blocks executed across all interprocedural frames for one finding.
const DEFAULT_MAX_BLOCKS: usize = 500;

/// Max frames (callee invocations) across one finding's exploration.
const DEFAULT_MAX_FRAMES: usize = 15;

// ─────────────────────────────────────────────────────────────────────────────
//  Feature gate
// ─────────────────────────────────────────────────────────────────────────────

/// Check if interprocedural symbolic execution is enabled.
///
/// Enabled by default.  Set `NYX_SYMEX_INTERPROC=0` or `=false` to disable.
pub fn interproc_enabled() -> bool {
    std::env::var("NYX_SYMEX_INTERPROC")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Context
// ─────────────────────────────────────────────────────────────────────────────

/// Shared context for interprocedural symbolic execution.
///
/// Created once per `explore_finding()` invocation.  Budget and cache use
/// interior mutability so the context can be shared by immutable reference
/// across recursive `execute_callee()` calls.
pub struct InterprocCtx<'a> {
    /// Pre-lowered intra-file function bodies.
    pub callee_bodies: &'a HashMap<String, CalleeSsaBody>,
    /// Shared CFG (all intra-file functions share one Cfg graph).
    pub cfg: &'a Cfg,
    /// Source language.
    pub lang: Lang,
    /// Maximum call depth.
    pub max_depth: usize,
    /// Shared budget counters.
    pub budget: &'a Cell<InterprocBudget>,
    /// Memoization cache for interprocedural outcomes.
    pub cache: &'a RefCell<InterprocCache>,
}

/// Budget counters shared across all interprocedural frames for one finding.
#[derive(Clone, Copy, Debug)]
pub struct InterprocBudget {
    pub blocks_executed: usize,
    pub max_blocks: usize,
    pub frames_created: usize,
    pub max_frames: usize,
}

impl InterprocBudget {
    /// Create a budget with default limits.
    pub fn new() -> Self {
        InterprocBudget {
            blocks_executed: 0,
            max_blocks: DEFAULT_MAX_BLOCKS,
            frames_created: 0,
            max_frames: DEFAULT_MAX_FRAMES,
        }
    }

    /// Check if any budget limit is exceeded.
    pub fn exhausted(&self) -> bool {
        self.blocks_executed >= self.max_blocks || self.frames_created >= self.max_frames
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Result types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of executing a callee to completion.
#[derive(Clone, Debug)]
pub struct CallOutcome {
    /// One exit state per feasible return path in the callee.
    pub exit_states: Vec<CalleeExitState>,
    /// Callee-internal sink findings with full call-chain evidence.
    pub internal_findings: Vec<InternalSinkFinding>,
}

/// Symbolic state at a single callee return point.
#[derive(Clone, Debug)]
pub struct CalleeExitState {
    /// Symbolic value at the return point (from `Terminator::Return(Some(v))`).
    pub return_value: SymbolicValue,
    /// Whether the return value carries taint.
    pub return_tainted: bool,
    /// Heap fields written by the callee (propagated to caller on resume).
    pub heap_delta: Vec<HeapMutation>,
    /// SSA values newly tainted during callee execution.
    pub taint_delta: HashSet<SsaValue>,
    /// Path constraints accumulated inside the callee.
    pub path_constraints: Vec<PathConstraint>,
}

/// A heap field written by the callee.
#[derive(Clone, Debug)]
pub struct HeapMutation {
    pub key: HeapKey,
    pub value: SymbolicValue,
    pub tainted: bool,
}

/// A sink finding detected inside a callee during interprocedural execution.
#[derive(Clone, Debug)]
pub struct InternalSinkFinding {
    /// CFG node of the sink inside the callee.
    pub sink_node: NodeIndex,
    /// Cap bits of the sink.
    pub sink_cap: Cap,
    /// The tainted symbolic value reaching the sink.
    pub tainted_value: SymbolicValue,
    /// Call chain from the outermost caller to the callee containing the sink.
    pub call_chain: Vec<String>,
    /// Path constraints under which this sink is reached.
    pub constraints: Vec<PathConstraint>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cache
// ─────────────────────────────────────────────────────────────────────────────

/// Cache key abstraction of argument symbolic values.
///
/// Encodes per-argument: (position, tag).  The tag captures:
///   - bits 0: is_tainted
///   - bits 1-4: SymbolicValue discriminant
///   - bits 5-15: hash of concrete value (if Concrete/ConcreteStr)
///
/// Richer than taint-only — captures concrete string/int identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArgAbstraction(SmallVec<[(usize, u16); 4]>);

impl ArgAbstraction {
    /// Build an argument abstraction from the call-site's symbolic values.
    pub fn build(
        arg_values: &[(SsaValue, SymbolicValue, bool)],
    ) -> Self {
        let mut entries: SmallVec<[(usize, u16); 4]> = SmallVec::new();
        for (pos, (_, sym, tainted)) in arg_values.iter().enumerate() {
            let taint_bit: u16 = if *tainted { 1 } else { 0 };
            let discrim: u16 = match sym {
                SymbolicValue::Concrete(_) => 0,
                SymbolicValue::ConcreteStr(_) => 1,
                SymbolicValue::Symbol(_) => 2,
                SymbolicValue::BinOp(..) => 3,
                SymbolicValue::Concat(..) => 4,
                SymbolicValue::Call(..) => 5,
                SymbolicValue::Phi(..) => 6,
                SymbolicValue::Unknown => 7,
                _ => 8, // string ops, etc.
            };
            let concrete_hash: u16 = match sym {
                SymbolicValue::Concrete(n) => (*n as u16).wrapping_mul(31),
                SymbolicValue::ConcreteStr(s) => {
                    let mut h: u16 = 0;
                    for b in s.bytes().take(8) {
                        h = h.wrapping_mul(31).wrapping_add(b as u16);
                    }
                    h
                }
                _ => 0,
            };
            let tag = taint_bit | (discrim << 1) | (concrete_hash << 5);
            entries.push((pos, tag));
        }
        ArgAbstraction(entries)
    }
}

/// Cache type: maps (callee_name, arg_abstraction) → CallOutcome.
pub type InterprocCache = HashMap<(String, ArgAbstraction), CallOutcome>;

// ─────────────────────────────────────────────────────────────────────────────
//  Core execution
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a callee's SSA body interprocedurally.
///
/// Returns `None` if the callee cannot be executed (no body, budget exhausted,
/// depth exceeded, body too large).  Falls through to summary resolution.
///
/// # Arguments
/// * `ctx`          — shared interprocedural context
/// * `callee_name`  — raw callee name from `SsaOp::Call`
/// * `arg_values`   — per-argument (caller SsaValue, SymbolicValue, tainted)
/// * `caller_heap`  — caller's current symbolic heap (for callee reads)
/// * `depth`        — current call depth (0 = top-level caller)
/// * `call_chain`   — function names from outermost caller to current
/// * `summary_ctx`  — summary context for nested calls that can't be inlined
/// * `heap_ctx`     — heap context for nested calls
pub fn execute_callee(
    ctx: &InterprocCtx,
    callee_name: &str,
    arg_values: &[(SsaValue, SymbolicValue, bool)],
    caller_heap: &SymbolicHeap,
    depth: usize,
    call_chain: &[String],
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
) -> Option<CallOutcome> {
    // Gate checks
    if !interproc_enabled() {
        return None;
    }
    if depth >= ctx.max_depth {
        return None;
    }
    {
        let b = ctx.budget.get();
        if b.exhausted() {
            return None;
        }
    }

    // Resolve callee
    let normalized = normalize_callee_name(callee_name);
    let body = ctx.callee_bodies.get(normalized)?;
    if body.ssa.blocks.len() > MAX_CALLEE_BLOCKS {
        return None;
    }

    // Cache check
    let sig = ArgAbstraction::build(arg_values);
    {
        let cache = ctx.cache.borrow();
        if let Some(cached) = cache.get(&(normalized.to_string(), sig.clone())) {
            return Some(cached.clone());
        }
    }

    // Increment frames budget
    {
        let mut b = ctx.budget.get();
        b.frames_created += 1;
        ctx.budget.set(b);
    }

    // Create callee state
    let mut callee_state = SymbolicState::new();
    callee_state.seed_from_const_values(&body.opt.const_values);

    // Seed parameters: walk callee SSA for Param instructions
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = &inst.op {
                if let Some((_, sym, tainted)) = arg_values.get(*index) {
                    callee_state.set(inst.value, sym.clone());
                    if *tainted {
                        callee_state.mark_tainted(inst.value);
                    }
                }
            }
        }
    }

    // Snapshot caller heap: copy fields into callee's heap so callee reads see
    // caller state.  The callee starts with a clone of the caller's heap.
    let initial_heap = caller_heap.clone();
    *callee_state.heap_mut() = initial_heap.clone();

    // Build call chain for this frame
    let mut frame_chain = call_chain.to_vec();
    frame_chain.push(normalized.to_string());

    // Walk callee blocks
    let mut exit_states: Vec<CalleeExitState> = Vec::new();
    let mut internal_findings: Vec<InternalSinkFinding> = Vec::new();
    let mut steps: usize = 0;
    let mut current_block = body.ssa.entry;
    let mut predecessor: Option<BlockId> = None;

    loop {
        // Per-frame step budget
        if steps >= MAX_CALLEE_STEPS {
            break;
        }
        // Global budget
        {
            let b = ctx.budget.get();
            if b.blocks_executed >= b.max_blocks {
                break;
            }
        }

        let block = match body.ssa.blocks.get(current_block.0 as usize) {
            Some(b) => b,
            None => break,
        };

        // Transfer block instructions
        transfer::transfer_block_with_predecessor(
            &mut callee_state,
            block,
            ctx.cfg,
            &body.ssa,
            predecessor,
            summary_ctx,
            heap_ctx,
            // Pass None for interproc_ctx to the recursive call at this level;
            // we handle recursion by calling execute_callee directly below.
            None,
            Some(ctx.lang),
        );

        // Count steps
        let block_steps = block.phis.len() + block.body.len();
        steps += block_steps;
        {
            let mut b = ctx.budget.get();
            b.blocks_executed += 1;
            ctx.budget.set(b);
        }

        // Detect callee-internal sinks
        for inst in block.body.iter() {
            let info = &ctx.cfg[inst.cfg_node];
            for label in &info.labels {
                if let DataLabel::Sink(cap) = label {
                    // Check if any operand is tainted
                    let operands = match &inst.op {
                        SsaOp::Call { args, receiver, .. } => {
                            let mut ops: Vec<SsaValue> = Vec::new();
                            if let Some(r) = receiver {
                                ops.push(*r);
                            }
                            for slot in args {
                                if let Some(&v) = slot.first() {
                                    ops.push(v);
                                }
                            }
                            ops
                        }
                        SsaOp::Assign(uses) => uses.to_vec(),
                        _ => Vec::new(),
                    };
                    if operands.iter().any(|v| callee_state.is_tainted(*v)) {
                        let tainted_val = operands
                            .iter()
                            .find(|v| callee_state.is_tainted(**v))
                            .map(|v| callee_state.get(*v))
                            .unwrap_or(SymbolicValue::Unknown);
                        internal_findings.push(InternalSinkFinding {
                            sink_node: inst.cfg_node,
                            sink_cap: *cap,
                            tainted_value: tainted_val,
                            call_chain: frame_chain.clone(),
                            constraints: callee_state.path_constraints().to_vec(),
                        });
                    }
                }
            }
        }

        // Handle nested calls: check if any Call instruction in the block could
        // be executed interprocedurally.  We do this AFTER transfer (which sets
        // up the state) by checking if the transferred Call result is still
        // opaque (Unknown or Call variant) and a body is available.
        for inst in block.body.iter() {
            if let SsaOp::Call { callee, args, receiver } = &inst.op {
                // Only attempt if the current result is opaque
                let current_val = callee_state.get(inst.value);
                if !matches!(current_val, SymbolicValue::Call(..) | SymbolicValue::Unknown) {
                    continue;
                }
                // Build arg_values for nested call
                let mut nested_args: Vec<(SsaValue, SymbolicValue, bool)> = Vec::new();
                if let Some(r) = receiver {
                    nested_args.push((*r, callee_state.get(*r), callee_state.is_tainted(*r)));
                }
                for slot in args {
                    if let Some(&v) = slot.first() {
                        nested_args.push((v, callee_state.get(v), callee_state.is_tainted(v)));
                    }
                }
                // Recurse
                if let Some(outcome) = execute_callee(
                    ctx,
                    callee,
                    &nested_args,
                    callee_state.heap(),
                    depth + 1,
                    &frame_chain,
                    summary_ctx,
                    heap_ctx,
                ) {
                    // Apply callee outcome to our state
                    let merged = merge_exit_states(&outcome.exit_states);
                    callee_state.set(inst.value, merged.return_value);
                    if merged.return_tainted {
                        callee_state.mark_tainted(inst.value);
                    }
                    for mutation in &merged.heap_delta {
                        callee_state.heap_mut().store(
                            mutation.key.clone(),
                            mutation.value.clone(),
                            mutation.tainted,
                        );
                    }
                    // Collect nested internal findings
                    internal_findings.extend(outcome.internal_findings);
                }
            }
        }

        // Examine terminator
        match &block.terminator {
            Terminator::Return(ret_val) => {
                let (return_value, return_tainted) = if let Some(v) = ret_val {
                    (callee_state.get(*v), callee_state.is_tainted(*v))
                } else {
                    (SymbolicValue::Unknown, false)
                };

                // Compute heap delta: fields changed since initial snapshot
                let heap_delta = compute_heap_delta(&initial_heap, callee_state.heap());

                // Collect taint delta
                let taint_delta = callee_state.tainted_values().clone();

                exit_states.push(CalleeExitState {
                    return_value,
                    return_tainted,
                    heap_delta,
                    taint_delta,
                    path_constraints: callee_state.path_constraints().to_vec(),
                });
                break;
            }
            Terminator::Goto(target) => {
                predecessor = Some(current_block);
                current_block = *target;
            }
            Terminator::Branch { true_blk, false_blk, .. } => {
                // Phase A: deterministic path selection (prefer true branch).
                // Phase B will add proper forking with feasibility checks.
                predecessor = Some(current_block);
                current_block = *true_blk;
                // If true branch is unreachable, try false
                if body.ssa.blocks.get(true_blk.0 as usize).is_none() {
                    current_block = *false_blk;
                }
            }
            Terminator::Unreachable => {
                break;
            }
        }
    }

    let outcome = CallOutcome {
        exit_states,
        internal_findings,
    };

    // Cache the result
    {
        let mut cache = ctx.cache.borrow_mut();
        cache.insert((normalized.to_string(), sig), outcome.clone());
    }

    Some(outcome)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Exit state merging
// ─────────────────────────────────────────────────────────────────────────────

/// Merge multiple callee exit states into a single state for the caller.
///
/// Phase A: conservative merge.
/// - Return value: `mk_phi` if multiple, direct if single.
/// - Taint: union (any return tainted → merged is tainted).
/// - Heap: union all mutations.
/// - Constraints: drop (callee-internal, not meaningful to caller).
///
/// Phase B will add proper per-exit-state forking in the caller.
pub fn merge_exit_states(states: &[CalleeExitState]) -> CalleeExitState {
    match states.len() {
        0 => CalleeExitState {
            return_value: SymbolicValue::Unknown,
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        },
        1 => states[0].clone(),
        _ => {
            // Phi merge for return values
            let phi_ops: Vec<_> = states
                .iter()
                .enumerate()
                .map(|(i, s)| (BlockId(i as u32), s.return_value.clone()))
                .collect();
            let return_value = mk_phi(phi_ops);
            let return_tainted = states.iter().any(|s| s.return_tainted);

            // Union heap mutations
            let mut heap_delta: Vec<HeapMutation> = Vec::new();
            let mut seen_keys: HashSet<HeapKey> = HashSet::new();
            for s in states {
                for m in &s.heap_delta {
                    if seen_keys.insert(m.key.clone()) {
                        heap_delta.push(m.clone());
                    }
                }
            }

            // Union taint
            let mut taint_delta: HashSet<SsaValue> = HashSet::new();
            for s in states {
                taint_delta.extend(&s.taint_delta);
            }

            CalleeExitState {
                return_value,
                return_tainted,
                heap_delta,
                taint_delta,
                path_constraints: Vec::new(), // drop callee constraints
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Heap delta
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the set of heap fields that changed between initial and final state.
fn compute_heap_delta(initial: &SymbolicHeap, final_heap: &SymbolicHeap) -> Vec<HeapMutation> {
    let mut delta = Vec::new();
    for (key, value) in final_heap.entries() {
        let initial_val = initial.load(key);
        // Record if the value changed (new key, or different value)
        let changed = matches!(initial_val, SymbolicValue::Unknown)
            || !sym_value_structurally_eq(&initial_val, value);
        if changed {
            delta.push(HeapMutation {
                key: key.clone(),
                value: value.clone(),
                tainted: final_heap.is_tainted(key),
            });
        }
    }
    delta
}

/// Structural equality check for SymbolicValue (best-effort).
///
/// Full structural equality is expensive for deep trees. This checks the
/// common cases (Concrete, ConcreteStr, Symbol, Unknown) and returns false
/// for complex expressions (conservative — will over-report heap mutations).
fn sym_value_structurally_eq(a: &SymbolicValue, b: &SymbolicValue) -> bool {
    match (a, b) {
        (SymbolicValue::Concrete(x), SymbolicValue::Concrete(y)) => x == y,
        (SymbolicValue::ConcreteStr(x), SymbolicValue::ConcreteStr(y)) => x == y,
        (SymbolicValue::Symbol(x), SymbolicValue::Symbol(y)) => x == y,
        (SymbolicValue::Unknown, SymbolicValue::Unknown) => true,
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_abstraction_different_taint() {
        let v0 = SsaValue(0);
        let a1 = ArgAbstraction::build(&[
            (v0, SymbolicValue::Symbol(v0), false),
        ]);
        let a2 = ArgAbstraction::build(&[
            (v0, SymbolicValue::Symbol(v0), true),
        ]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn arg_abstraction_same_values() {
        let v0 = SsaValue(0);
        let a1 = ArgAbstraction::build(&[
            (v0, SymbolicValue::Concrete(42), false),
        ]);
        let a2 = ArgAbstraction::build(&[
            (v0, SymbolicValue::Concrete(42), false),
        ]);
        assert_eq!(a1, a2);
    }

    #[test]
    fn arg_abstraction_different_concrete() {
        let v0 = SsaValue(0);
        let a1 = ArgAbstraction::build(&[
            (v0, SymbolicValue::Concrete(1), false),
        ]);
        let a2 = ArgAbstraction::build(&[
            (v0, SymbolicValue::Concrete(2), false),
        ]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn merge_exit_states_empty() {
        let merged = merge_exit_states(&[]);
        assert!(matches!(merged.return_value, SymbolicValue::Unknown));
        assert!(!merged.return_tainted);
    }

    #[test]
    fn merge_exit_states_single() {
        let state = CalleeExitState {
            return_value: SymbolicValue::Concrete(42),
            return_tainted: true,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let merged = merge_exit_states(&[state]);
        assert!(matches!(merged.return_value, SymbolicValue::Concrete(42)));
        assert!(merged.return_tainted);
    }

    #[test]
    fn merge_exit_states_multiple_unions_taint() {
        let s1 = CalleeExitState {
            return_value: SymbolicValue::Concrete(1),
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let s2 = CalleeExitState {
            return_value: SymbolicValue::Concrete(2),
            return_tainted: true,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let merged = merge_exit_states(&[s1, s2]);
        // Any tainted → merged is tainted
        assert!(merged.return_tainted);
        // Return value should be a Phi
        assert!(matches!(merged.return_value, SymbolicValue::Phi(_)));
    }

    #[test]
    fn budget_exhaustion() {
        let budget = InterprocBudget {
            blocks_executed: 500,
            max_blocks: 500,
            frames_created: 0,
            max_frames: 15,
        };
        assert!(budget.exhausted());
    }

    #[test]
    fn budget_frames_exhaustion() {
        let budget = InterprocBudget {
            blocks_executed: 0,
            max_blocks: 500,
            frames_created: 15,
            max_frames: 15,
        };
        assert!(budget.exhausted());
    }

    #[test]
    fn budget_not_exhausted() {
        let budget = InterprocBudget::new();
        assert!(!budget.exhausted());
    }

    #[test]
    fn sym_value_eq_concrete() {
        assert!(sym_value_structurally_eq(
            &SymbolicValue::Concrete(5),
            &SymbolicValue::Concrete(5),
        ));
        assert!(!sym_value_structurally_eq(
            &SymbolicValue::Concrete(5),
            &SymbolicValue::Concrete(6),
        ));
    }

    #[test]
    fn sym_value_eq_unknown() {
        assert!(sym_value_structurally_eq(
            &SymbolicValue::Unknown,
            &SymbolicValue::Unknown,
        ));
    }

    #[test]
    fn sym_value_eq_different_kinds() {
        assert!(!sym_value_structurally_eq(
            &SymbolicValue::Concrete(1),
            &SymbolicValue::Unknown,
        ));
    }
}
