use crate::constraint::domain::ConstValue;
use crate::constraint::lower::ConditionExpr;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Unique identifier for an SSA value (one per definition point).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SsaValue(pub u32);

/// Basic block identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockId(pub u32);

/// SSA instruction operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SsaOp {
    /// Phi: merge values from predecessor blocks.
    Phi(SmallVec<[(BlockId, SsaValue); 2]>),
    /// Assignment: result depends on the listed SSA values.
    Assign(SmallVec<[SsaValue; 4]>),
    /// Function/method call.
    Call {
        callee: String,
        /// Per-argument SSA value uses.
        args: Vec<SmallVec<[SsaValue; 2]>>,
        /// Receiver SSA value (for method calls).
        receiver: Option<SsaValue>,
    },
    /// Taint source introduction.
    Source,
    /// Constant / literal value (no taint).
    /// The optional string carries the raw source text when captured during lowering.
    Const(Option<String>),
    /// Function parameter (positional).  Index is the 0-based positional
    /// parameter index, *excluding* any implicit receiver (`self`/`this`).
    /// The receiver, when present, is represented by [`SsaOp::SelfParam`].
    Param { index: usize },
    /// Implicit method receiver (`self` in Rust/Python, `this` in
    /// JS/TS/Java/PHP).  Emitted in block 0 of a function body whenever the
    /// body has a receiver (either an explicit `self` formal parameter or an
    /// implicit `this` reference).  Having a dedicated IR node keeps
    /// receiver taint tracking entirely separate from positional-parameter
    /// taint, eliminating off-by-receiver arithmetic at call sites.
    SelfParam,
    /// Catch-clause exception binding.
    CatchParam,
    /// Non-defining node (e.g. If condition evaluation, Entry, Exit).
    Nop,
    /// Sentinel for "no reaching definition on this control-flow edge".
    ///
    /// Emitted by SSA lowering as a synthesized instruction in the entry
    /// block and referenced from phi operands whose incoming edge does
    /// not carry a definition of the phi's variable — e.g. a try/catch
    /// rejoin where a variable is only defined on the normal path, or
    /// an early-return branch on a later-defined variable.
    ///
    /// Having an explicit value lets phis satisfy the invariant that
    /// `phi.operands.len() == block.preds.len()` (one operand per
    /// predecessor). Downstream analyses treat Undef as a
    /// no-taint / unknown / bottom-of-the-lattice contribution: a phi
    /// operand of Undef carries no caps, no concrete value, and no
    /// abstract fact.
    Undef,
}

/// A single SSA instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsaInst {
    /// The SSA value defined by this instruction.
    pub value: SsaValue,
    /// The operation.
    pub op: SsaOp,
    /// The original CFG node this instruction was derived from.
    pub cfg_node: NodeIndex,
    /// Original variable name (for debugging and label lookups).
    pub var_name: Option<String>,
    /// Source byte span from the original file.
    pub span: (usize, usize),
}

/// Basic block terminator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Terminator {
    Goto(BlockId),
    Branch {
        cond: NodeIndex,
        true_blk: BlockId,
        false_blk: BlockId,
        /// Structured condition lowered from CFG metadata during SSA construction.
        /// `None` when the condition could not be lowered (falls back to text-based
        /// lowering in taint transfer).
        condition: Option<Box<ConditionExpr>>,
    },
    /// Multi-way switch dispatch.
    ///
    /// `targets` lists the per-case successor blocks (order matches the
    /// source-order of cases in the switch); `default` is the fallback
    /// branch taken when no case matches. Block `succs` remain the
    /// authoritative flow set — the terminator is a structured summary.
    ///
    /// Emitted only for switch-like dispatch whose semantics are
    /// guaranteed-exclusive across cases (e.g. Go `switch`, Java
    /// arrow-switch, Rust `match`). Fall-through switches (C, C++, Java
    /// classic switch without `break`) continue to use the cascaded
    /// `Branch` lowering because the precision advantage only holds when
    /// cases are mutually exclusive.
    Switch {
        scrutinee: SsaValue,
        targets: SmallVec<[BlockId; 4]>,
        default: BlockId,
        /// Per-target case literals, aligned 1:1 with `targets`.
        ///
        /// `Some(c)` records the constant value the scrutinee must equal for
        /// the corresponding target to be taken. `None` means the literal is
        /// unknown — emitted for synthetic ≥3-way CFG fanouts or for case
        /// patterns that aren't plain literals (OR-patterns, ranges, guards).
        ///
        /// When omitted/empty (length zero), all targets behave as "unknown
        /// literal" — preserves backward compatibility with consumers that
        /// only inspect `targets`/`default`.
        #[serde(default)]
        case_values: SmallVec<[Option<ConstValue>; 4]>,
    },
    Return(Option<SsaValue>),
    Unreachable,
}

/// A basic block in SSA form.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsaBlock {
    pub id: BlockId,
    /// Phi instructions (always at block start).
    pub phis: Vec<SsaInst>,
    /// Body instructions (after phis).
    pub body: Vec<SsaInst>,
    /// Block terminator.
    pub terminator: Terminator,
    /// Predecessor block IDs.
    pub preds: SmallVec<[BlockId; 2]>,
    /// Successor block IDs.
    pub succs: SmallVec<[BlockId; 2]>,
}

/// Per-value definition metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueDef {
    /// Original variable name (if any).
    pub var_name: Option<String>,
    /// The CFG node where this value was defined.
    pub cfg_node: NodeIndex,
    /// The block containing the definition.
    pub block: BlockId,
}

/// Complete SSA representation for a function/scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsaBody {
    /// All basic blocks, indexed by BlockId.
    pub blocks: Vec<SsaBlock>,
    /// Entry block.
    pub entry: BlockId,
    /// Per-SsaValue definition info, indexed by SsaValue.0.
    pub value_defs: Vec<ValueDef>,
    /// Map from original CFG NodeIndex to the primary SsaValue defined there.
    pub cfg_node_map: std::collections::HashMap<NodeIndex, SsaValue>,
    /// Exception edges: (source block, catch entry block).
    /// Recorded during lowering when exception edges are stripped from the CFG.
    /// Used by taint analysis to seed catch blocks with try-body taint state.
    pub exception_edges: Vec<(BlockId, BlockId)>,
}

impl SsaBody {
    /// Get a block by its ID.
    pub fn block(&self, id: BlockId) -> &SsaBlock {
        &self.blocks[id.0 as usize]
    }

    /// Get a mutable block by its ID.
    pub fn block_mut(&mut self, id: BlockId) -> &mut SsaBlock {
        &mut self.blocks[id.0 as usize]
    }

    /// Total number of SSA values.
    pub fn num_values(&self) -> usize {
        self.value_defs.len()
    }

    /// Look up definition info for an SSA value.
    pub fn def_of(&self, v: SsaValue) -> &ValueDef {
        &self.value_defs[v.0 as usize]
    }
}

/// Errors that can occur during SSA lowering.
#[derive(Debug, Clone)]
pub enum SsaError {
    /// The CFG has no reachable nodes from the entry.
    EmptyCfg,
    /// Entry node not found in the CFG.
    InvalidEntry,
}

impl std::fmt::Display for SsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsaError::EmptyCfg => write!(f, "CFG has no reachable nodes"),
            SsaError::InvalidEntry => write!(f, "entry node not found in CFG"),
        }
    }
}

impl std::error::Error for SsaError {}
