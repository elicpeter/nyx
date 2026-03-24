//! Forward symbolic transfer over SSA instructions.
//!
//! Walks SSA blocks and builds `SymbolicValue` expression trees for each
//! defined SSA value, while eagerly propagating taint through the root-set.

use crate::cfg::Cfg;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::{BlockId, SsaBlock, SsaBody, SsaInst, SsaOp};

use super::state::SymbolicState;
use super::value::{mk_binop, mk_call, mk_phi, Op, SymbolicValue};

/// Transfer a single SSA instruction: set the symbolic value and propagate taint.
pub fn transfer_inst(
    state: &mut SymbolicState,
    inst: &SsaInst,
    cfg: &Cfg,
    _ssa: &SsaBody,
) {
    match &inst.op {
        SsaOp::Const(text) => {
            let sym = match text {
                Some(t) => match ConstLattice::parse(t) {
                    ConstLattice::Int(n) => SymbolicValue::Concrete(n),
                    ConstLattice::Str(s) => SymbolicValue::ConcreteStr(s),
                    _ => SymbolicValue::Unknown, // Bool, Null, Top, Varying
                },
                None => SymbolicValue::Unknown,
            };
            state.set(inst.value, sym);
        }

        SsaOp::Source => {
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
            state.mark_tainted(inst.value);
        }

        SsaOp::Param { .. } => {
            // Params are symbolic inputs but NOT tainted by default.
            // Taint seeding happens via finding.flow_steps in analyse_finding_path.
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
        }

        SsaOp::CatchParam => {
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
        }

        SsaOp::Nop => {
            // Nop does not define a meaningful value — skip.
        }

        SsaOp::Assign(uses) => {
            let uses_slice: &[_] = uses;
            match uses_slice.len() {
                0 => {
                    state.set(inst.value, SymbolicValue::Unknown);
                }
                1 => {
                    // Copy
                    let sym = state.get(uses_slice[0]);
                    state.set(inst.value, sym);
                    state.propagate_taint(inst.value, uses_slice);
                }
                2 => {
                    // Check for binary op metadata on the CFG node
                    let info = &cfg[inst.cfg_node];
                    if let Some(bin_op) = info.bin_op {
                        let lhs = state.get(uses_slice[0]);
                        let rhs = state.get(uses_slice[1]);
                        let sym = mk_binop(Op::from(bin_op), lhs, rhs);
                        state.set(inst.value, sym);
                    } else {
                        // No structural info — conservative Unknown
                        state.set(inst.value, SymbolicValue::Unknown);
                    }
                    state.propagate_taint(inst.value, uses_slice);
                }
                _ => {
                    // 3+ operands — complex expression
                    state.set(inst.value, SymbolicValue::Unknown);
                    state.propagate_taint(inst.value, uses_slice);
                }
            }
        }

        SsaOp::Call { callee, args, receiver } => {
            // Collect symbolic values for arguments
            let mut arg_syms: Vec<SymbolicValue> = Vec::new();
            let mut all_operands: Vec<_> = Vec::new();

            if let Some(recv) = receiver {
                arg_syms.push(state.get(*recv));
                all_operands.push(*recv);
            }

            for arg_slot in args {
                if let Some(&first_val) = arg_slot.first() {
                    arg_syms.push(state.get(first_val));
                    all_operands.push(first_val);
                }
            }

            let sym = mk_call(callee.clone(), arg_syms);
            state.set(inst.value, sym);
            state.propagate_taint(inst.value, &all_operands);
        }

        SsaOp::Phi(operands) => {
            let phi_ops: Vec<_> = operands
                .iter()
                .map(|(bid, v)| (*bid, state.get(*v)))
                .collect();
            let operand_vals: Vec<_> = operands.iter().map(|(_, v)| *v).collect();

            let sym = mk_phi(phi_ops);
            state.set(inst.value, sym);
            state.propagate_taint(inst.value, &operand_vals);
        }
    }
}

/// Transfer a single SSA instruction with optional predecessor context.
///
/// ONLY phi instructions use predecessor-sensitive selection — when
/// `predecessor` is `Some(bid)`, the phi resolves to the operand from
/// that specific predecessor block instead of building a `Phi(...)`
/// expression. All non-phi instructions delegate to [`transfer_inst`].
pub fn transfer_inst_with_predecessor(
    state: &mut SymbolicState,
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    predecessor: Option<BlockId>,
) {
    match (&inst.op, predecessor) {
        (SsaOp::Phi(operands), Some(pred)) => {
            let sym = state.resolve_phi_from_predecessor(operands, pred);
            state.set(inst.value, sym);
            // Taint: propagate only from the matched predecessor operand
            for (bid, v) in operands.iter() {
                if *bid == pred {
                    state.propagate_taint(inst.value, &[*v]);
                    return;
                }
            }
            // Predecessor not found among operands — propagate from all (fallback)
            let operand_vals: Vec<_> = operands.iter().map(|(_, v)| *v).collect();
            state.propagate_taint(inst.value, &operand_vals);
        }
        _ => {
            transfer_inst(state, inst, cfg, ssa);
        }
    }
}

/// Transfer all instructions in a block with predecessor context.
///
/// Phis use predecessor-aware transfer; body instructions use standard
/// [`transfer_inst`]. See [`transfer_inst_with_predecessor`] for details.
pub fn transfer_block_with_predecessor(
    state: &mut SymbolicState,
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    predecessor: Option<BlockId>,
) {
    for inst in &block.phis {
        transfer_inst_with_predecessor(state, inst, cfg, ssa, predecessor);
    }
    for inst in &block.body {
        transfer_inst(state, inst, cfg, ssa);
    }
}

/// Transfer all instructions in a block: phis first, then body.
pub fn transfer_block(
    state: &mut SymbolicState,
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
) {
    for inst in &block.phis {
        transfer_inst(state, inst, cfg, ssa);
    }
    for inst in &block.body {
        transfer_inst(state, inst, cfg, ssa);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BinOp, Cfg, NodeInfo, StmtKind};
    use crate::ssa::ir::{BlockId, SsaInst, SsaValue, Terminator, SsaBlock, ValueDef};
    use petgraph::graph::NodeIndex;
    use smallvec::{smallvec, SmallVec};

    /// Create a minimal Cfg with a single node that has the given bin_op.
    fn cfg_with_node(bin_op: Option<BinOp>) -> (Cfg, NodeIndex) {
        let mut cfg = Cfg::new();
        let info = NodeInfo {
            kind: StmtKind::Seq,
            span: (0, 0),
            labels: SmallVec::new(),
            defines: None,
            extra_defines: Vec::new(),
            uses: Vec::new(),
            callee: None,
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            const_text: None,
            condition_vars: Vec::new(),
            condition_text: None,
            condition_negated: false,
            arg_uses: Vec::new(),
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op,
            managed_resource: false,
        };
        let idx = cfg.add_node(info);
        (cfg, idx)
    }

    fn make_inst(value: u32, op: SsaOp, cfg_node: NodeIndex) -> SsaInst {
        SsaInst {
            value: SsaValue(value),
            op,
            cfg_node,
            var_name: None,
            span: (0, 0),
        }
    }

    fn empty_ssa() -> SsaBody {
        SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
        }
    }

    #[test]
    fn transfer_const_int() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("42".into())), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(42));
        assert!(!state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_const_string() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("\"hello\"".into())), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(
            state.get(SsaValue(0)),
            SymbolicValue::ConcreteStr("hello".into())
        );
    }

    #[test]
    fn transfer_const_bool_fallback() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("true".into())), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Unknown);
    }

    #[test]
    fn transfer_const_none() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(None), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Unknown);
    }

    #[test]
    fn transfer_source_tainted() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Source, node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_param_not_tainted() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Param { index: 0 }, node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(!state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_assign_copy() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Set up source value
        state.set(SsaValue(0), SymbolicValue::Concrete(7));
        state.mark_tainted(SsaValue(0));

        let inst = make_inst(1, SsaOp::Assign(smallvec![SsaValue(0)]), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Concrete(7));
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_assign_binop() {
        let (cfg, node) = cfg_with_node(Some(BinOp::Mul));
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));
        state.set(SsaValue(1), SymbolicValue::Concrete(2));

        let inst = make_inst(
            2,
            SsaOp::Assign(smallvec![SsaValue(0), SsaValue(1)]),
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        let expected = SymbolicValue::BinOp(
            Op::Mul,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
            Box::new(SymbolicValue::Concrete(2)),
        );
        assert_eq!(state.get(SsaValue(2)), expected);
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_assign_no_binop_is_unknown() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.set(SsaValue(1), SymbolicValue::Concrete(2));

        let inst = make_inst(
            2,
            SsaOp::Assign(smallvec![SsaValue(0), SsaValue(1)]),
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Unknown);
    }

    #[test]
    fn transfer_call() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "parseInt".into(),
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        let expected = SymbolicValue::Call(
            "parseInt".into(),
            vec![SymbolicValue::Symbol(SsaValue(0))],
        );
        assert_eq!(state.get(SsaValue(1)), expected);
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_call_with_receiver() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0))); // receiver
        state.set(SsaValue(1), SymbolicValue::Concrete(42)); // arg

        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "send".into(),
                args: vec![smallvec![SsaValue(1)]],
                receiver: Some(SsaValue(0)),
            },
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        let expected = SymbolicValue::Call(
            "send".into(),
            vec![SymbolicValue::Symbol(SsaValue(0)), SymbolicValue::Concrete(42)],
        );
        assert_eq!(state.get(SsaValue(2)), expected);
    }

    #[test]
    fn transfer_phi() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(1));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        let expected = SymbolicValue::Phi(vec![
            (BlockId(0), SymbolicValue::Concrete(1)),
            (BlockId(1), SymbolicValue::Symbol(SsaValue(1))),
        ]);
        assert_eq!(state.get(SsaValue(2)), expected);
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn taint_propagation_chain() {
        // Build a cfg with two nodes: one plain (for source/copy/const), one with Mul
        let mut cfg = Cfg::new();
        let node_plain = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            span: (0, 0),
            labels: SmallVec::new(),
            defines: None,
            extra_defines: Vec::new(),
            uses: Vec::new(),
            callee: None,
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            const_text: None,
            condition_vars: Vec::new(),
            condition_text: None,
            condition_negated: false,
            arg_uses: Vec::new(),
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
            managed_resource: false,
        });
        let node_mul = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            span: (0, 0),
            labels: SmallVec::new(),
            defines: None,
            extra_defines: Vec::new(),
            uses: Vec::new(),
            callee: None,
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            const_text: None,
            condition_vars: Vec::new(),
            condition_text: None,
            condition_negated: false,
            arg_uses: Vec::new(),
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: Some(BinOp::Mul),
            managed_resource: false,
        });
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // v0: source (tainted)
        let i0 = make_inst(0, SsaOp::Source, node_plain);
        transfer_inst(&mut state, &i0, &cfg, &ssa);
        assert!(state.is_tainted(SsaValue(0)));

        // v1: copy of v0
        let i1 = make_inst(1, SsaOp::Assign(smallvec![SsaValue(0)]), node_plain);
        transfer_inst(&mut state, &i1, &cfg, &ssa);
        assert!(state.is_tainted(SsaValue(1)));

        // v2: constant (not tainted)
        let i2 = make_inst(2, SsaOp::Const(Some("3".into())), node_plain);
        transfer_inst(&mut state, &i2, &cfg, &ssa);
        assert!(!state.is_tainted(SsaValue(2)));

        // v3: v1 * v2 (tainted because v1 is tainted)
        let i3 = make_inst(
            3,
            SsaOp::Assign(smallvec![SsaValue(1), SsaValue(2)]),
            node_mul,
        );
        transfer_inst(&mut state, &i3, &cfg, &ssa);
        assert!(state.is_tainted(SsaValue(3)));
        let expected = SymbolicValue::BinOp(
            Op::Mul,
            Box::new(SymbolicValue::Symbol(SsaValue(0))), // v1 was a copy of v0 (Symbol)
            Box::new(SymbolicValue::Concrete(3)),
        );
        assert_eq!(state.get(SsaValue(3)), expected);

        // v4: call using v3 (still tainted)
        let i4 = make_inst(
            4,
            SsaOp::Call {
                callee: "toString".into(),
                args: vec![smallvec![SsaValue(3)]],
                receiver: None,
            },
            node_plain,
        );
        transfer_inst(&mut state, &i4, &cfg, &ssa);
        assert!(state.is_tainted(SsaValue(4)));
    }

    #[test]
    fn transfer_nop_skipped() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(99));
        let inst = make_inst(0, SsaOp::Nop, node);
        transfer_inst(&mut state, &inst, &cfg, &ssa);

        // Nop does not overwrite existing value
        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(99));
    }

    #[test]
    fn transfer_block_processes_phis_then_body() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Set up predecessor values for phi
        state.set(SsaValue(0), SymbolicValue::Concrete(1));
        state.set(SsaValue(1), SymbolicValue::Concrete(1));

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![make_inst(
                2,
                SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
                node,
            )],
            body: vec![make_inst(3, SsaOp::Const(Some("10".into())), node)],
            terminator: Terminator::Return,
            preds: smallvec![],
            succs: smallvec![],
        };

        transfer_block(&mut state, &block, &cfg, &ssa);

        // Phi with all-same should fold to Concrete(1)
        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Concrete(1));
        // Body const should be set
        assert_eq!(state.get(SsaValue(3)), SymbolicValue::Concrete(10));
    }

    #[test]
    fn transfer_phi_with_predecessor_resolves_to_operand() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Set up different values for each predecessor
        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Concrete(20));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
            node,
        );

        // With predecessor B1, should resolve to SsaValue(1) → Concrete(20)
        transfer_inst_with_predecessor(&mut state, &inst, &cfg, &ssa, Some(BlockId(1)));
        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Concrete(20));
    }

    #[test]
    fn transfer_phi_with_predecessor_taint_from_selected_only() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // B0's operand is NOT tainted, B1's operand IS tainted
        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
            node,
        );

        // With predecessor B0 (untainted), result should NOT be tainted
        transfer_inst_with_predecessor(&mut state, &inst, &cfg, &ssa, Some(BlockId(0)));
        assert!(!state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_phi_with_predecessor_taint_from_tainted_pred() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
            node,
        );

        // With predecessor B1 (tainted), result SHOULD be tainted
        transfer_inst_with_predecessor(&mut state, &inst, &cfg, &ssa, Some(BlockId(1)));
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_phi_without_predecessor_builds_phi_expr() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Concrete(20));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
            node,
        );

        // Without predecessor (None), falls back to Phi(...) expression
        transfer_inst_with_predecessor(&mut state, &inst, &cfg, &ssa, None);
        let expected = SymbolicValue::Phi(vec![
            (BlockId(0), SymbolicValue::Concrete(10)),
            (BlockId(1), SymbolicValue::Concrete(20)),
        ]);
        assert_eq!(state.get(SsaValue(2)), expected);
    }

    #[test]
    fn transfer_non_phi_ignores_predecessor() {
        // Non-phi instructions should behave identically regardless of predecessor
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("42".into())), node);
        transfer_inst_with_predecessor(&mut state, &inst, &cfg, &ssa, Some(BlockId(5)));
        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(42));
    }
}
