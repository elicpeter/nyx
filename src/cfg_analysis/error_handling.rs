use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence, is_sink};
use crate::cfg::{EdgeKind, StmtKind};
use crate::patterns::Severity;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

pub struct IncompleteErrorHandling;

/// Check if the true branch of an If node terminates (has Return/Break/Continue).
fn branch_terminates(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> bool {
    // Follow the True edge from the If node
    let true_successors: Vec<NodeIndex> = cfg
        .edges(if_node)
        .filter(|e| matches!(e.weight(), EdgeKind::True))
        .map(|e| e.target())
        .collect();

    if true_successors.is_empty() {
        return false;
    }

    // Check if any path through the true branch terminates
    for &start in &true_successors {
        if terminates_on_all_paths(cfg, start, if_node) {
            return true;
        }
    }

    false
}

/// Check if all paths from `node` reach a Return/Break/Continue before exiting scope.
fn terminates_on_all_paths(
    cfg: &crate::cfg::Cfg,
    node: NodeIndex,
    _scope_entry: NodeIndex,
) -> bool {
    use std::collections::HashSet;

    let mut visited = HashSet::new();
    let mut stack = vec![node];

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }

        let info = &cfg[current];
        match info.kind {
            StmtKind::Return | StmtKind::Throw | StmtKind::Break | StmtKind::Continue => {
                // This path terminates
                continue;
            }
            _ => {}
        }

        let successors: Vec<_> = cfg.neighbors(current).collect();
        if successors.is_empty() {
            // Reached a dead end without terminating — path does not terminate
            return false;
        }

        for succ in successors {
            // Don't follow back edges (loops)
            let is_back_edge = cfg
                .edges(current)
                .any(|e| e.target() == succ && matches!(e.weight(), EdgeKind::Back));
            if !is_back_edge {
                stack.push(succ);
            }
        }
    }

    true
}

/// Find successor nodes after an If node merges (nodes reachable from both branches).
fn find_post_if_sinks(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> Vec<NodeIndex> {
    let mut sinks_after = Vec::new();

    // Get all successors of the if node's merge point
    // Walk through successors looking for sinks
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<NodeIndex> = cfg.neighbors(if_node).collect();

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }

        let info = &cfg[current];
        if is_sink(info) || (info.kind == StmtKind::Call && info.call.callee.is_some()) {
            sinks_after.push(current);
        }

        for succ in cfg.neighbors(current) {
            let is_back_edge = cfg
                .edges(current)
                .any(|e| e.target() == succ && matches!(e.weight(), EdgeKind::Back));
            if !is_back_edge {
                stack.push(succ);
            }
        }
    }

    sinks_after
}

impl CfgAnalysis for IncompleteErrorHandling {
    fn name(&self) -> &'static str {
        "incomplete-error-handling"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let mut findings = Vec::new();

        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];

            // Look for If nodes whose condition involves "err" or "error"
            if info.kind != StmtKind::If {
                continue;
            }

            let mentions_err = info.taint.uses.iter().any(|u| {
                let lower = u.to_ascii_lowercase();
                lower == "err" || lower == "error" || lower.contains("err")
            });

            if !mentions_err {
                continue;
            }

            // Check: does the true branch terminate?
            if branch_terminates(ctx.cfg, idx) {
                continue;
            }

            // Check: are there dangerous calls/sinks after this error check?
            let post_sinks = find_post_if_sinks(ctx.cfg, idx);
            let has_dangerous_successor = post_sinks.iter().any(|&s| is_sink(&ctx.cfg[s]));

            if has_dangerous_successor {
                findings.push(CfgFinding {
                    rule_id: "cfg-error-fallthrough".to_string(),
                    title: "Error check without return".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    span: info.ast.span,
                    message: "Error check does not terminate on error; \
                              execution falls through to dangerous operations"
                        .to_string(),
                    evidence: vec![idx],
                    score: None,
                });
            }
        }

        findings
    }
}
