use crate::constraint::domain::ConstValue;
use crate::constraint::lower::ConditionExpr;
use crate::ssa::type_facts::TypeKind;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

/// Unique identifier for an SSA value (one per definition point).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SsaValue(pub u32);

/// Basic block identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockId(pub u32);

/// Interned field-name identifier, scoped to a single [`SsaBody`].
///
/// Different bodies may assign different `FieldId`s to the same field name,
/// so callers MUST resolve through the owning body's [`FieldInterner`]
/// (`SsaBody::field_name`) before using the name in cross-body contexts
/// (e.g. summary serialization).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FieldId(pub u32);

/// Per-body interner for field names referenced by [`SsaOp::FieldProj`].
///
/// Names are deduped within a single SSA body: every distinct field-name
/// string is assigned a stable `FieldId(u32)` for the lifetime of the body.
/// The interner is serialized alongside the body so deserialization restores
/// IDs intact; cross-body summary code is responsible for resolving names
/// before passing them across body boundaries.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FieldInterner {
    /// Names indexed by `FieldId.0`.
    names: Vec<String>,
    /// Reverse lookup: name → existing FieldId.
    #[serde(skip)]
    lookup: HashMap<String, u32>,
}

impl FieldInterner {
    /// Create an empty interner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a field name, returning its [`FieldId`]. Reuses the existing
    /// id if the name has already been interned.
    pub fn intern(&mut self, name: &str) -> FieldId {
        if let Some(&id) = self.lookup.get(name) {
            return FieldId(id);
        }
        let id = self.names.len() as u32;
        self.names.push(name.to_string());
        self.lookup.insert(name.to_string(), id);
        FieldId(id)
    }

    /// Resolve a [`FieldId`] back to its interned name.
    pub fn resolve(&self, id: FieldId) -> &str {
        &self.names[id.0 as usize]
    }

    /// Number of unique interned names.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the interner contains no names.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Rebuild the reverse lookup after deserialization.  Called lazily by
    /// [`Self::ensure_lookup`] so deserialized interners can still be used
    /// for further interning.
    fn rebuild_lookup(&mut self) {
        self.lookup.clear();
        for (i, n) in self.names.iter().enumerate() {
            self.lookup.entry(n.clone()).or_insert(i as u32);
        }
    }

    /// Ensure the reverse lookup is populated (rebuilds after a serde
    /// roundtrip when the lookup table was skipped).
    pub fn ensure_lookup(&mut self) {
        if self.lookup.len() != self.names.len() {
            self.rebuild_lookup();
        }
    }
}

/// SSA instruction operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SsaOp {
    /// Phi: merge values from predecessor blocks.
    Phi(SmallVec<[(BlockId, SsaValue); 2]>),
    /// Assignment: result depends on the listed SSA values.
    Assign(SmallVec<[SsaValue; 4]>),
    /// Function/method call.
    ///
    /// `callee` is the canonical name SSA-time consumers should match on.
    /// When SSA lowering decomposes a chained-receiver method call into a
    /// `FieldProj` chain (e.g. `c.mu.Lock()` → `v_mu = FieldProj(v_c, "mu")`,
    /// `Call("Lock", [v_mu])`), `callee` carries the bare method name
    /// (`"Lock"`) and `callee_text` carries the original full path
    /// (`Some("c.mu.Lock")`).  When no decomposition happens, `callee_text`
    /// is `None` and `callee` already holds the original textual form.
    Call {
        callee: String,
        /// Original textual full path when SSA decomposed a chained receiver.
        /// `None` when the callee was not rewritten — `callee` already holds
        /// the source-level textual form.  Reserved for legacy display /
        /// debug consumers; analysis code should walk the SSA receiver chain
        /// (through `FieldProj` ops) instead.
        #[serde(default)]
        callee_text: Option<String>,
        /// Per-argument SSA value uses.
        args: Vec<SmallVec<[SsaValue; 2]>>,
        /// Receiver SSA value (for method calls).
        receiver: Option<SsaValue>,
    },
    /// Field projection: read field `field` of object `receiver`.
    ///
    /// Models member-access expressions (`obj.field`) as a first-class SSA
    /// op.  Lowering walks the receiver tree so chained accesses like
    /// `c.writer.header` produce a chain of `FieldProj` ops with explicit
    /// per-step receivers — eliminating the textual-prefix parsing that
    /// previously misclassified deep receivers (the gin/context.go FP).
    ///
    /// `field` is interned in the owning [`SsaBody`]'s [`FieldInterner`].
    /// `projected_type` carries the inferred type of the projected field
    /// when known (populated by type-fact analysis), `None` otherwise.
    FieldProj {
        receiver: SsaValue,
        field: FieldId,
        projected_type: Option<TypeKind>,
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
    /// Per-body interner for [`SsaOp::FieldProj`] field names.
    ///
    /// Empty until the lowering phase emits FieldProj ops (Phase 2 of the
    /// field-projections rollout).  Cross-body callers (cross-file
    /// summaries, debug serialization) MUST resolve interned ids through
    /// this interner before transporting field references to other bodies.
    #[serde(default)]
    pub field_interner: FieldInterner,
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

    /// Resolve a [`FieldId`] back to the interned field name within this body.
    pub fn field_name(&self, id: FieldId) -> &str {
        self.field_interner.resolve(id)
    }

    /// Intern a field name in this body's [`FieldInterner`], returning its
    /// stable [`FieldId`].
    pub fn intern_field(&mut self, name: &str) -> FieldId {
        self.field_interner.intern(name)
    }
}

impl SsaInst {
    /// Iterate over the SSA values used (read) by this instruction.
    ///
    /// Yields receiver/operand values for `Call`, `Phi`, `Assign`, and
    /// `FieldProj`; nothing for leaf ops (`Const`, `Param`, `Source`, etc.).
    /// Callers that need the values as a `Vec` should `.collect()`.
    pub fn uses_iter(&self) -> SmallVec<[SsaValue; 4]> {
        match &self.op {
            SsaOp::Phi(operands) => operands.iter().map(|(_, v)| *v).collect(),
            SsaOp::Assign(uses) => uses.iter().copied().collect(),
            SsaOp::Call { args, receiver, .. } => {
                let mut out: SmallVec<[SsaValue; 4]> = SmallVec::new();
                if let Some(rv) = receiver {
                    out.push(*rv);
                }
                for arg in args {
                    out.extend(arg.iter().copied());
                }
                out
            }
            SsaOp::FieldProj { receiver, .. } => {
                let mut out: SmallVec<[SsaValue; 4]> = SmallVec::new();
                out.push(*receiver);
                out
            }
            SsaOp::Source
            | SsaOp::Const(_)
            | SsaOp::Param { .. }
            | SsaOp::SelfParam
            | SsaOp::CatchParam
            | SsaOp::Nop
            | SsaOp::Undef => SmallVec::new(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_interner_dedupes_names() {
        let mut interner = FieldInterner::new();
        let a = interner.intern("mu");
        let b = interner.intern("mu");
        let c = interner.intern("writer");
        assert_eq!(a, b, "interning same name twice yields same id");
        assert_ne!(a, c, "different names get different ids");
        assert_eq!(interner.resolve(a), "mu");
        assert_eq!(interner.resolve(c), "writer");
        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn field_interner_serde_roundtrip_rebuilds_lookup() {
        let mut interner = FieldInterner::new();
        let a = interner.intern("mu");
        let b = interner.intern("writer");
        let json = serde_json::to_string(&interner).expect("serialize");
        let mut restored: FieldInterner = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.resolve(a), "mu");
        assert_eq!(restored.resolve(b), "writer");
        // After ensure_lookup, intern("mu") returns the original id (not a new one).
        restored.ensure_lookup();
        assert_eq!(restored.intern("mu"), a);
        assert_eq!(restored.intern("header"), FieldId(2));
    }

    #[test]
    fn field_proj_use_iter_includes_receiver() {
        let inst = SsaInst {
            value: SsaValue(3),
            op: SsaOp::FieldProj {
                receiver: SsaValue(1),
                field: FieldId(0),
                projected_type: None,
            },
            cfg_node: NodeIndex::new(0),
            var_name: Some("c.mu".into()),
            span: (0, 0),
        };
        let uses: Vec<SsaValue> = inst.uses_iter().into_iter().collect();
        assert_eq!(uses, vec![SsaValue(1)]);
    }

    #[test]
    fn field_proj_serde_roundtrip_with_field_name() {
        // Build a tiny body with one FieldProj op and check that the
        // body's interner survives round-trip and the id resolves back
        // to the original name.
        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("c".into()),
                cfg_node: NodeIndex::new(0),
                block: BlockId(0),
            }],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: FieldInterner::new(),
        };
        let fid = body.intern_field("mu");
        body.blocks[0].body.push(SsaInst {
            value: SsaValue(1),
            op: SsaOp::FieldProj {
                receiver: SsaValue(0),
                field: fid,
                projected_type: None,
            },
            cfg_node: NodeIndex::new(0),
            var_name: Some("c.mu".into()),
            span: (0, 0),
        });

        let json = serde_json::to_string(&body).expect("serialize body");
        let restored: SsaBody = serde_json::from_str(&json).expect("deserialize body");

        let inst = &restored.blocks[0].body[0];
        match &inst.op {
            SsaOp::FieldProj { receiver, field, .. } => {
                assert_eq!(*receiver, SsaValue(0));
                assert_eq!(restored.field_name(*field), "mu");
            }
            other => panic!("expected FieldProj, got {other:?}"),
        }
    }
}
