#![allow(clippy::collapsible_if)]

use std::collections::HashMap;

use super::ir::*;
use crate::cfg::Cfg;

/// Run copy propagation on an SSA body.
///
/// Identifies `Assign([single_use])` instructions where the CFG node has no
/// labels (i.e., no semantic significance like sanitizer/source), then rewrites
/// all uses of the destination value to use the source value directly.
///
/// Returns `(copies_eliminated, resolved_replacement_map)`. The replacement map
/// maps each eliminated destination SsaValue to its transitive root source
/// SsaValue, used downstream by alias analysis to recover base-variable
/// aliasing relationships.
pub fn copy_propagate(body: &mut SsaBody, cfg: &Cfg) -> (usize, HashMap<SsaValue, SsaValue>) {
    // 1. Identify copies: Assign with single operand and no labels on CFG node
    let mut replace_map: HashMap<SsaValue, SsaValue> = HashMap::new();

    for block in &body.blocks {
        for inst in &block.body {
            if let SsaOp::Assign(uses) = &inst.op {
                if uses.len() == 1 {
                    let src = uses[0];
                    let info = &cfg[inst.cfg_node];
                    // Skip if the node has labels — sanitizers, sources, sinks
                    // have semantic meaning that must be preserved.
                    if info.taint.labels.is_empty() {
                        replace_map.insert(inst.value, src);
                    }
                }
            }
        }
    }

    if replace_map.is_empty() {
        return (0, HashMap::new());
    }

    // 2. Build transitive replacement map: chase chains (SSA is acyclic)
    let mut resolved: HashMap<SsaValue, SsaValue> = HashMap::new();
    for &dst in replace_map.keys() {
        let root = resolve_root(dst, &replace_map);
        resolved.insert(dst, root);
    }

    // 3. Rewrite all uses
    let mut count = 0;
    for block in &mut body.blocks {
        // Rewrite phi operands
        for phi in &mut block.phis {
            if let SsaOp::Phi(operands) = &mut phi.op {
                for (_bid, val) in operands.iter_mut() {
                    if let Some(&root) = resolved.get(val) {
                        *val = root;
                    }
                }
            }
        }

        // Rewrite body instructions
        for inst in &mut block.body {
            match &mut inst.op {
                SsaOp::Assign(uses) => {
                    for val in uses.iter_mut() {
                        if let Some(&root) = resolved.get(val) {
                            *val = root;
                        }
                    }
                }
                SsaOp::Call { args, receiver, .. } => {
                    if let Some(rv) = receiver {
                        if let Some(&root) = resolved.get(rv) {
                            *rv = root;
                        }
                    }
                    for arg in args.iter_mut() {
                        for val in arg.iter_mut() {
                            if let Some(&root) = resolved.get(val) {
                                *val = root;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 4. Convert copy instructions to Nop (DCE will clean up)
    for block in &mut body.blocks {
        for inst in &mut block.body {
            if resolved.contains_key(&inst.value) {
                inst.op = SsaOp::Nop;
                count += 1;
            }
        }
    }

    (count, resolved)
}

/// Chase the replacement chain to find the root value.
fn resolve_root(val: SsaValue, map: &HashMap<SsaValue, SsaValue>) -> SsaValue {
    let mut current = val;
    // Safety: SSA is acyclic, but cap iterations to be safe
    for _ in 0..1000 {
        match map.get(&current) {
            Some(&next) if next != current => current = next,
            _ => break,
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{NodeInfo, StmtKind};
    use petgraph::Graph;
    use smallvec::SmallVec;

    fn make_cfg_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn simple_copy_eliminated() {
        // v0 = const("42"), v1 = assign(v0), v2 = assign(v1)
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n2 = cfg.add_node(make_cfg_node(StmtKind::Seq));

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
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(1), 1)),
                        cfg_node: n2,
                        var_name: Some("z".into()),
                        span: (6, 8),
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
                ValueDef {
                    var_name: Some("z".into()),
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
        };

        let (eliminated, copy_map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 2);
        // Both v1 and v2 should map to v0 (the root)
        assert_eq!(copy_map.get(&SsaValue(1)), Some(&SsaValue(0)));
        assert_eq!(copy_map.get(&SsaValue(2)), Some(&SsaValue(0)));

        // v1 and v2 should be Nop now
        assert!(matches!(body.blocks[0].body[1].op, SsaOp::Nop));
        assert!(matches!(body.blocks[0].body[2].op, SsaOp::Nop));
    }
}
