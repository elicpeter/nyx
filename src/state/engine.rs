use super::lattice::Lattice;
use crate::cfg::{Cfg, EdgeKind, NodeInfo};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, VecDeque};

/// Maximum tracked variables per function (guarded degradation).
pub const MAX_TRACKED_VARS: usize = 64;

/// Default worklist iteration budget.
pub const MAX_WORKLIST_ITERATIONS: usize = 100_000;

/// Generic transfer function trait for forward dataflow analysis.
///
/// Domains implement this to define how abstract state flows through
/// CFG nodes and what events (findings) are emitted.
pub trait Transfer<S: Lattice> {
    /// Side-channel events emitted during transfer (e.g., findings, violations).
    type Event: Clone;

    /// Apply the transfer function to a node, returning the output state
    /// and any events.
    fn apply(
        &self,
        node: NodeIndex,
        info: &NodeInfo,
        edge: Option<EdgeKind>,
        state: S,
    ) -> (S, Vec<Self::Event>);

    /// Per-domain iteration budget. Defaults to [`MAX_WORKLIST_ITERATIONS`].
    fn iteration_budget(&self) -> usize {
        MAX_WORKLIST_ITERATIONS
    }

    /// Called when the budget is exhausted. Returns true if the engine
    /// should continue with the current (non-converged) state, false to bail.
    fn on_budget_exceeded(&self) -> bool {
        false
    }
}

/// Result of running the forward dataflow engine.
pub struct DataflowResult<S, E> {
    /// Converged state at the entry of each node.
    pub states: HashMap<NodeIndex, S>,
    /// Events emitted during Phase 2 transfer over converged states.
    pub events: Vec<E>,
    /// Whether the analysis converged (false if budget was hit).
    #[allow(dead_code)]
    pub converged: bool,
}

/// Run a forward worklist dataflow analysis over the CFG.
///
/// Two-phase design:
/// - Phase 1: fixed-point iteration to converge states (no event collection).
/// - Phase 2: single pass over converged states to collect events.
///
/// Termination is guaranteed by lattice finiteness + iteration budget.
pub fn run_forward<S: Lattice, T: Transfer<S>>(
    cfg: &Cfg,
    entry: NodeIndex,
    transfer: &T,
    initial: S,
) -> DataflowResult<S, T::Event> {
    let mut states: HashMap<NodeIndex, S> = HashMap::new();
    let budget = transfer.iteration_budget();

    // Initialize entry node
    states.insert(entry, initial);

    // ── Phase 1: fixed-point iteration (compute converged states) ─────
    let mut worklist: VecDeque<NodeIndex> = VecDeque::new();
    worklist.push_back(entry);

    let mut iterations: usize = 0;
    let mut converged = true;

    while let Some(node) = worklist.pop_front() {
        iterations += 1;
        if iterations > budget {
            converged = !transfer.on_budget_exceeded();
            if !converged {
                break;
            }
        }

        let node_state = match states.get(&node) {
            Some(s) => s.clone(),
            None => continue,
        };

        let edges: Vec<_> = cfg.edges(node).map(|e| (*e.weight(), e.target())).collect();

        // No outgoing edges — nothing to propagate (exit/dead end).
        if edges.is_empty() {
            continue;
        }

        for &(edge_kind, target) in &edges {
            // Skip redundant Seq edges when a True or False edge reaches the
            // same target. The CFG builder may emit both a Seq edge (from
            // build_sub chaining) and a True/False edge (from explicit If
            // wiring) to the same successor. The Seq edge carries no
            // branch-aware state, so it dilutes the auth elevation that
            // the True edge provides. Dropping it preserves correct semantics.
            if matches!(edge_kind, EdgeKind::Seq)
                && edges.iter().any(|&(k, t)| {
                    t == target && matches!(k, EdgeKind::True | EdgeKind::False)
                })
            {
                continue;
            }

            let info = &cfg[node];
            let (out_state, _events) =
                transfer.apply(node, info, Some(edge_kind), node_state.clone());

            // Join into target's state
            let target_state = states.get(&target);
            let new_target = match target_state {
                Some(existing) => existing.join(&out_state),
                None => out_state,
            };

            let changed = target_state.is_none_or(|existing| *existing != new_target);
            if changed {
                states.insert(target, new_target);
                if !worklist.contains(&target) {
                    worklist.push_back(target);
                }
            }
        }
    }

    // ── Phase 2: single pass over converged states to collect events ──
    let mut events: Vec<T::Event> = Vec::new();
    let mut seen_edges: std::collections::HashSet<(NodeIndex, NodeIndex)> =
        std::collections::HashSet::new();

    for node in states.keys().copied().collect::<Vec<_>>() {
        let node_state = match states.get(&node) {
            Some(s) => s.clone(),
            None => continue,
        };

        let edges: Vec<_> = cfg.edges(node).map(|e| (*e.weight(), e.target())).collect();

        if edges.is_empty() {
            // Exit / dead end — apply transfer for event collection.
            let info = &cfg[node];
            let (_out_state, new_events) = transfer.apply(node, info, None, node_state);
            events.extend(new_events);
            continue;
        }

        for &(edge_kind, target) in &edges {
            // Same redundant-Seq-edge skip as Phase 1.
            if matches!(edge_kind, EdgeKind::Seq)
                && edges.iter().any(|&(k, t)| {
                    t == target && matches!(k, EdgeKind::True | EdgeKind::False)
                })
            {
                continue;
            }
            if !seen_edges.insert((node, target)) {
                continue;
            }
            let info = &cfg[node];
            let (_out_state, new_events) =
                transfer.apply(node, info, Some(edge_kind), node_state.clone());
            events.extend(new_events);
        }
    }

    DataflowResult {
        states,
        events,
        converged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{EdgeKind, NodeInfo, StmtKind};
    use crate::cfg_analysis::rules;
    use crate::state::domain::ResourceLifecycle;
    use crate::state::symbol::SymbolInterner;
    use crate::state::transfer::DefaultTransfer;
    use crate::symbol::Lang;
    use petgraph::Graph;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            span: (0, 0),
            labels: smallvec::SmallVec::new(),
            defines: None,
            extra_defines: vec![],
            uses: vec![],
            callee: None,
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
            arg_uses: vec![],
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            const_text: None,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
            managed_resource: false,
        }
    }

    #[test]
    fn linear_cfg_converges() {
        use crate::state::domain::ProductState;

        // Entry → fopen(f) → fclose(f) → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            defines: Some("f".into()),
            callee: Some("fopen".into()),
            ..make_node(StmtKind::Call)
        });
        let close_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            uses: vec!["f".into()],
            callee: Some("fclose".into()),
            ..make_node(StmtKind::Call)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, close_node, EdgeKind::Seq);
        cfg.add_edge(close_node, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());

        // No events (clean open→close)
        assert!(result.events.is_empty());
        assert!(result.converged);

        // At exit, f should be CLOSED
        let sym_f = interner.get("f").unwrap();
        let exit_state = result.states.get(&exit).unwrap();
        assert_eq!(exit_state.resource.get(sym_f), ResourceLifecycle::CLOSED);
    }

    #[test]
    fn diamond_cfg_joins_states() {
        use crate::state::domain::ProductState;

        //         Entry
        //           |
        //         fopen(f)
        //           |
        //          If
        //         /    \
        //   fclose(f)  (no close)
        //         \    /
        //          Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            defines: Some("f".into()),
            callee: Some("fopen".into()),
            ..make_node(StmtKind::Call)
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let close_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            uses: vec!["f".into()],
            callee: Some("fclose".into()),
            ..make_node(StmtKind::Call)
        });
        let no_close = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, close_node, EdgeKind::True);
        cfg.add_edge(if_node, no_close, EdgeKind::False);
        cfg.add_edge(close_node, exit, EdgeKind::Seq);
        cfg.add_edge(no_close, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());

        // At exit, f should be OPEN | CLOSED (may-leak)
        let sym_f = interner.get("f").unwrap();
        let exit_state = result.states.get(&exit).unwrap();
        assert_eq!(
            exit_state.resource.get(sym_f),
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED
        );
    }
}
