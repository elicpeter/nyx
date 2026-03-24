use std::collections::{HashMap, HashSet, VecDeque};

use super::ir::*;

/// Lattice value for constant propagation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstLattice {
    /// Not yet analyzed (optimistic top).
    Top,
    /// Known string constant.
    Str(String),
    /// Known integer constant.
    Int(i64),
    /// Known boolean constant.
    Bool(bool),
    /// Null / nil / None.
    Null,
    /// Multiple possible values — not constant.
    Varying,
}

impl ConstLattice {
    /// Meet operation: combine two lattice values.
    fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (ConstLattice::Top, x) | (x, ConstLattice::Top) => x.clone(),
            (ConstLattice::Varying, _) | (_, ConstLattice::Varying) => ConstLattice::Varying,
            (a, b) if a == b => a.clone(),
            _ => ConstLattice::Varying,
        }
    }

    /// Parse a raw constant text into a typed lattice value.
    pub(crate) fn parse(text: &str) -> Self {
        let trimmed = text.trim();

        // Boolean
        if trimmed == "true" || trimmed == "True" || trimmed == "TRUE" {
            return ConstLattice::Bool(true);
        }
        if trimmed == "false" || trimmed == "False" || trimmed == "FALSE" {
            return ConstLattice::Bool(false);
        }

        // Null variants
        if trimmed == "null" || trimmed == "nil" || trimmed == "None"
            || trimmed == "NULL" || trimmed == "nullptr"
        {
            return ConstLattice::Null;
        }

        // Integer (including negative)
        if let Ok(i) = trimmed.parse::<i64>() {
            return ConstLattice::Int(i);
        }

        // String: strip surrounding quotes
        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        {
            let inner = &trimmed[1..trimmed.len() - 1];
            return ConstLattice::Str(inner.to_string());
        }

        // Bare string (no quotes) — treat as string constant
        ConstLattice::Str(trimmed.to_string())
    }

    /// Returns the boolean value if this is a known Bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConstLattice::Bool(b) => Some(*b),
            // Truthiness: null is false, 0 is false, empty string is false
            ConstLattice::Null => Some(false),
            ConstLattice::Int(0) => Some(false),
            ConstLattice::Str(s) if s.is_empty() => Some(false),
            _ => None,
        }
    }
}

/// Result of constant propagation analysis.
pub struct ConstPropResult {
    /// Per-SSA-value constant lattice.
    pub values: HashMap<SsaValue, ConstLattice>,
    /// Blocks that are statically unreachable.
    pub unreachable_blocks: HashSet<BlockId>,
}

/// Run Sparse Conditional Constant Propagation on an SSA body.
pub fn const_propagate(body: &SsaBody) -> ConstPropResult {
    let num_blocks = body.blocks.len();

    // Per-value lattice: starts at Top
    let mut values: HashMap<SsaValue, ConstLattice> = HashMap::new();

    // Executable flags per CFG edge (from_block, to_block)
    let mut executable_edges: HashSet<(BlockId, BlockId)> = HashSet::new();
    // Executable blocks
    let mut executable_blocks: HashSet<BlockId> = HashSet::new();

    // Two worklists
    let mut cfg_worklist: VecDeque<BlockId> = VecDeque::new();
    let mut ssa_worklist: VecDeque<SsaValue> = VecDeque::new();

    // Mark entry executable
    executable_blocks.insert(body.entry);
    cfg_worklist.push_back(body.entry);

    // Build use-map: SsaValue → list of (BlockId, instruction index in block)
    // so we can propagate SSA value changes efficiently.
    let mut use_sites: HashMap<SsaValue, Vec<BlockId>> = HashMap::new();
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            for used_val in inst_uses(inst) {
                use_sites.entry(used_val).or_default().push(block.id);
            }
        }
    }

    // Initialize all values to Top
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            values.insert(inst.value, ConstLattice::Top);
        }
    }

    // Process until both worklists are empty
    loop {
        let mut changed = false;

        // Process CFG worklist
        while let Some(block_id) = cfg_worklist.pop_front() {
            let block = body.block(block_id);

            // Evaluate phis
            for phi in &block.phis {
                if let SsaOp::Phi(operands) = &phi.op {
                    let old = values.get(&phi.value).cloned().unwrap_or(ConstLattice::Top);
                    let new_val = eval_phi(operands, &values, &executable_edges, block_id);
                    if new_val != old {
                        values.insert(phi.value, new_val);
                        ssa_worklist.push_back(phi.value);
                        changed = true;
                    }
                }
            }

            // Evaluate body instructions
            for inst in &block.body {
                let old = values.get(&inst.value).cloned().unwrap_or(ConstLattice::Top);
                let new_val = eval_inst(inst, &values);
                if new_val != old {
                    values.insert(inst.value, new_val);
                    ssa_worklist.push_back(inst.value);
                    changed = true;
                }
            }

            // Process terminator: determine which successors are executable
            process_terminator(
                block,
                body,
                &values,
                &mut executable_edges,
                &mut executable_blocks,
                &mut cfg_worklist,
            );
        }

        // Process SSA worklist
        while let Some(val) = ssa_worklist.pop_front() {
            if let Some(blocks) = use_sites.get(&val) {
                for &block_id in blocks {
                    if !executable_blocks.contains(&block_id) {
                        continue;
                    }
                    let block = body.block(block_id);

                    // Re-evaluate phis using this value
                    for phi in &block.phis {
                        if let SsaOp::Phi(operands) = &phi.op {
                            if operands.iter().any(|(_, v)| *v == val) {
                                let old = values.get(&phi.value).cloned().unwrap_or(ConstLattice::Top);
                                let new_val = eval_phi(operands, &values, &executable_edges, block_id);
                                if new_val != old {
                                    values.insert(phi.value, new_val);
                                    ssa_worklist.push_back(phi.value);
                                    changed = true;
                                }
                            }
                        }
                    }

                    // Re-evaluate body instructions using this value
                    for inst in &block.body {
                        if inst_uses(inst).iter().any(|v| *v == val) {
                            let old = values.get(&inst.value).cloned().unwrap_or(ConstLattice::Top);
                            let new_val = eval_inst(inst, &values);
                            if new_val != old {
                                values.insert(inst.value, new_val);
                                ssa_worklist.push_back(inst.value);
                                changed = true;
                            }
                        }
                    }

                    // Re-evaluate terminator if condition changed
                    process_terminator(
                        block,
                        body,
                        &values,
                        &mut executable_edges,
                        &mut executable_blocks,
                        &mut cfg_worklist,
                    );
                }
            }
        }

        if !changed {
            break;
        }
    }

    // Compute unreachable blocks
    let unreachable_blocks: HashSet<BlockId> = (0..num_blocks)
        .map(|i| BlockId(i as u32))
        .filter(|bid| !executable_blocks.contains(bid))
        .collect();

    ConstPropResult {
        values,
        unreachable_blocks,
    }
}

/// Evaluate a phi: meet of operands from executable predecessors.
fn eval_phi(
    operands: &[(BlockId, SsaValue)],
    values: &HashMap<SsaValue, ConstLattice>,
    executable_edges: &HashSet<(BlockId, BlockId)>,
    this_block: BlockId,
) -> ConstLattice {
    let mut result = ConstLattice::Top;
    for (pred_block, val) in operands {
        if !executable_edges.contains(&(*pred_block, this_block)) {
            continue; // skip non-executable predecessors
        }
        let operand_val = values.get(val).cloned().unwrap_or(ConstLattice::Top);
        result = result.meet(&operand_val);
    }
    result
}

/// Evaluate a single instruction.
fn eval_inst(inst: &SsaInst, values: &HashMap<SsaValue, ConstLattice>) -> ConstLattice {
    match &inst.op {
        SsaOp::Const(Some(text)) => ConstLattice::parse(text),
        SsaOp::Const(None) => ConstLattice::Varying, // unknown constant
        SsaOp::Assign(uses) if uses.len() == 1 => {
            // Copy: propagate the source's value
            values.get(&uses[0]).cloned().unwrap_or(ConstLattice::Top)
        }
        SsaOp::Assign(_) => ConstLattice::Varying, // expression with multiple uses
        SsaOp::Call { .. } | SsaOp::Source | SsaOp::Param { .. } | SsaOp::CatchParam => {
            ConstLattice::Varying
        }
        SsaOp::Phi(_) => ConstLattice::Varying, // phis in body shouldn't happen
        SsaOp::Nop => ConstLattice::Varying,
    }
}

/// Collect SSA values used by an instruction (for use-map building).
fn inst_uses(inst: &SsaInst) -> Vec<SsaValue> {
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

/// Process a block's terminator to determine successor executability.
fn process_terminator(
    block: &SsaBlock,
    body: &SsaBody,
    values: &HashMap<SsaValue, ConstLattice>,
    executable_edges: &mut HashSet<(BlockId, BlockId)>,
    executable_blocks: &mut HashSet<BlockId>,
    cfg_worklist: &mut VecDeque<BlockId>,
) {
    match &block.terminator {
        Terminator::Goto(target) => {
            mark_edge_executable(block.id, *target, executable_edges, executable_blocks, cfg_worklist);
        }
        Terminator::Branch { cond, true_blk, false_blk, condition: _ } => {
            // Try to resolve the condition to a known boolean
            let cond_val = body.cfg_node_map.get(cond)
                .and_then(|v| values.get(v))
                .and_then(|c| c.as_bool());

            match cond_val {
                Some(true) => {
                    mark_edge_executable(block.id, *true_blk, executable_edges, executable_blocks, cfg_worklist);
                }
                Some(false) => {
                    mark_edge_executable(block.id, *false_blk, executable_edges, executable_blocks, cfg_worklist);
                }
                None => {
                    // Unknown: both successors executable
                    mark_edge_executable(block.id, *true_blk, executable_edges, executable_blocks, cfg_worklist);
                    mark_edge_executable(block.id, *false_blk, executable_edges, executable_blocks, cfg_worklist);
                }
            }
        }
        Terminator::Return(_) | Terminator::Unreachable => {}
    }
}

fn mark_edge_executable(
    from: BlockId,
    to: BlockId,
    executable_edges: &mut HashSet<(BlockId, BlockId)>,
    executable_blocks: &mut HashSet<BlockId>,
    cfg_worklist: &mut VecDeque<BlockId>,
) {
    if executable_edges.insert((from, to)) {
        if executable_blocks.insert(to) {
            cfg_worklist.push_back(to);
        } else {
            // Block already executable but new edge — re-evaluate phis
            cfg_worklist.push_back(to);
        }
    }
}

/// Apply constant propagation results: prune branches where condition is known constant.
///
/// Returns the number of branches pruned.
pub fn apply_const_prop(body: &mut SsaBody, result: &ConstPropResult) -> usize {
    // Collect pruning decisions first to avoid borrow conflicts.
    // Each entry: (block_index, taken_block, untaken_block)
    let mut prune_ops: Vec<(usize, BlockId, BlockId)> = Vec::new();

    for (block_idx, block) in body.blocks.iter().enumerate() {
        if let Terminator::Branch { cond, true_blk, false_blk, condition: _ } = &block.terminator {
            let cond_val = body.cfg_node_map.get(cond)
                .and_then(|v| result.values.get(v))
                .and_then(|c| c.as_bool());

            match cond_val {
                Some(true) => {
                    prune_ops.push((block_idx, *true_blk, *false_blk));
                }
                Some(false) => {
                    prune_ops.push((block_idx, *false_blk, *true_blk));
                }
                None => {}
            }
        }
    }

    let pruned = prune_ops.len();

    // Apply pruning
    for (block_idx, taken, untaken) in prune_ops {
        let pred_id = body.blocks[block_idx].id;
        body.blocks[block_idx].terminator = Terminator::Goto(taken);

        // Remove pred from untaken's preds
        let untaken_idx = untaken.0 as usize;
        if untaken_idx < body.blocks.len() {
            body.blocks[untaken_idx].preds.retain(|p| *p != pred_id);
            // Remove phi operands referencing this pred
            for phi in &mut body.blocks[untaken_idx].phis {
                if let SsaOp::Phi(operands) = &mut phi.op {
                    operands.retain(|(bid, _)| *bid != pred_id);
                }
            }
        }

        // Remove untaken from pred's succs
        body.blocks[block_idx].succs.retain(|s| *s != untaken);
    }

    // Mark unreachable blocks
    for &bid in &result.unreachable_blocks {
        body.block_mut(bid).terminator = Terminator::Unreachable;
    }

    pruned
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::SmallVec;
    use petgraph::graph::NodeIndex;

    fn make_body(blocks: Vec<SsaBlock>, value_defs: Vec<ValueDef>) -> SsaBody {
        let cfg_node_map = value_defs
            .iter()
            .enumerate()
            .map(|(i, vd)| (vd.cfg_node, SsaValue(i as u32)))
            .collect();
        SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs,
            cfg_node_map,
            exception_edges: Vec::new(),
        }
    }

    #[test]
    fn const_literal_parsed() {
        assert_eq!(ConstLattice::parse("42"), ConstLattice::Int(42));
        assert_eq!(ConstLattice::parse("-1"), ConstLattice::Int(-1));
        assert_eq!(ConstLattice::parse("true"), ConstLattice::Bool(true));
        assert_eq!(ConstLattice::parse("false"), ConstLattice::Bool(false));
        assert_eq!(ConstLattice::parse("null"), ConstLattice::Null);
        assert_eq!(ConstLattice::parse("nil"), ConstLattice::Null);
        assert_eq!(ConstLattice::parse("\"hello\""), ConstLattice::Str("hello".into()));
        assert_eq!(ConstLattice::parse("'world'"), ConstLattice::Str("world".into()));
    }

    #[test]
    fn meet_lattice() {
        let a = ConstLattice::Int(42);
        let b = ConstLattice::Int(42);
        assert_eq!(a.meet(&b), ConstLattice::Int(42));

        let c = ConstLattice::Int(99);
        assert_eq!(a.meet(&c), ConstLattice::Varying);

        assert_eq!(ConstLattice::Top.meet(&a), ConstLattice::Int(42));
        assert_eq!(a.meet(&ConstLattice::Top), ConstLattice::Int(42));

        assert_eq!(ConstLattice::Varying.meet(&a), ConstLattice::Varying);
    }

    #[test]
    fn single_block_const() {
        // v0 = const("42")
        let n0 = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Const(Some("42".into())),
                cfg_node: n0,
                var_name: Some("x".into()),
                span: (0, 2),
            }],
            terminator: Terminator::Return(None),
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        };
        let body = make_body(
            vec![block],
            vec![ValueDef { var_name: Some("x".into()), cfg_node: n0, block: BlockId(0) }],
        );

        let result = const_propagate(&body);
        assert_eq!(result.values.get(&SsaValue(0)), Some(&ConstLattice::Int(42)));
        assert!(result.unreachable_blocks.is_empty());
    }

    #[test]
    fn copy_propagation_through_assign() {
        // v0 = const("true"), v1 = assign(v0)
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Const(Some("true".into())),
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    span: (0, 4),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                    cfg_node: n1,
                    var_name: Some("y".into()),
                    span: (5, 9),
                },
            ],
            terminator: Terminator::Return(None),
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        };
        let body = make_body(
            vec![block],
            vec![
                ValueDef { var_name: Some("x".into()), cfg_node: n0, block: BlockId(0) },
                ValueDef { var_name: Some("y".into()), cfg_node: n1, block: BlockId(0) },
            ],
        );

        let result = const_propagate(&body);
        assert_eq!(result.values.get(&SsaValue(0)), Some(&ConstLattice::Bool(true)));
        assert_eq!(result.values.get(&SsaValue(1)), Some(&ConstLattice::Bool(true)));
    }
}
