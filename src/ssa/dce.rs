use std::collections::HashMap;

use super::ir::*;
use crate::cfg::Cfg;
use crate::labels::DataLabel;

/// Eliminate dead definitions from an SSA body.
///
/// A definition is dead if its SsaValue has zero uses across the entire body,
/// except for instructions that must be preserved:
/// - `Source` (taint origin, must survive for correctness)
/// - `Call` (may have side effects)
/// - `CatchParam` (exception binding)
/// - Instructions whose CFG node has Sink labels (sink detection relies on them)
///
/// Returns the number of instructions removed.
pub fn eliminate_dead_defs(body: &mut SsaBody, cfg: &Cfg) -> usize {
    let mut total_removed = 0;

    // Iterate until no more removals (removing a def may make its operands dead)
    loop {
        let use_counts = build_use_counts(body);
        let mut removed_this_pass = 0;

        for block in &mut body.blocks {
            // Remove dead body instructions
            let before = block.body.len();
            block.body.retain(|inst| !is_dead(inst, &use_counts, cfg));
            removed_this_pass += before - block.body.len();

            // Remove dead phi instructions
            let before_phis = block.phis.len();
            block.phis.retain(|inst| !is_dead(inst, &use_counts, cfg));
            removed_this_pass += before_phis - block.phis.len();
        }

        total_removed += removed_this_pass;
        if removed_this_pass == 0 {
            break;
        }
    }

    total_removed
}

/// Build a map of SsaValue → number of uses across all instructions.
fn build_use_counts(body: &SsaBody) -> HashMap<SsaValue, usize> {
    let mut counts: HashMap<SsaValue, usize> = HashMap::new();

    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            for v in inst_used_values(inst) {
                *counts.entry(v).or_insert(0) += 1;
            }
        }
    }

    counts
}

/// Check if an instruction is dead and safe to remove.
fn is_dead(inst: &SsaInst, use_counts: &HashMap<SsaValue, usize>, cfg: &Cfg) -> bool {
    let uses = use_counts.get(&inst.value).copied().unwrap_or(0);
    if uses > 0 {
        return false;
    }

    // Never remove side-effectful or semantically required instructions
    match &inst.op {
        SsaOp::Source => return false,
        SsaOp::Call { .. } => return false,
        SsaOp::CatchParam => return false,
        _ => {}
    }

    // Never remove instructions whose CFG node has Sink labels
    if cfg
        .node_weight(inst.cfg_node)
        .is_some_and(|info| info.taint.labels.iter().any(|l| matches!(l, DataLabel::Sink(_))))
    {
        return false;
    }

    true
}

/// Get all SSA values used by an instruction.
fn inst_used_values(inst: &SsaInst) -> Vec<SsaValue> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{NodeInfo, StmtKind};
    use petgraph::Graph;
    use smallvec::SmallVec;

    fn make_cfg_node(kind: StmtKind) -> NodeInfo {
        NodeInfo { kind, ..Default::default() }
    }

    #[test]
    fn dead_const_removed() {
        // v0 = const("42") — unused, should be removed
        // v1 = source() — must survive even if unused
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("42".into())),
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Source,
                        cfg_node: n1,
                        var_name: Some("tainted".into()),
                        span: (3, 10),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("tainted".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(removed, 1);
        assert_eq!(body.blocks[0].body.len(), 1);
        // Source survives
        assert!(matches!(body.blocks[0].body[0].op, SsaOp::Source));
    }

    #[test]
    fn used_def_preserved() {
        // v0 = const("42"), v1 = assign(v0) — v0 is used, both survive
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("42".into())),
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                        cfg_node: n1,
                        var_name: Some("y".into()),
                        span: (3, 5),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
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
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        // v1 is dead (unused), but v0 is used by v1 so on first pass only v1 removed,
        // then v0 becomes dead on second pass
        assert_eq!(removed, 2);
        assert_eq!(body.blocks[0].body.len(), 0);
    }
}
