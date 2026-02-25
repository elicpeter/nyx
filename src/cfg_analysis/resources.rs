use super::dominators;
use super::rules;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence};
use crate::cfg::StmtKind;
use crate::patterns::Severity;
use petgraph::graph::NodeIndex;
use std::collections::HashSet;

pub struct ResourceMisuse;

/// Find nodes matching acquire patterns for a given resource pair.
fn find_acquire_nodes(ctx: &AnalysisContext, acquire_patterns: &[&str]) -> Vec<NodeIndex> {
    ctx.cfg
        .node_indices()
        .filter(|&idx| {
            let info = &ctx.cfg[idx];
            if info.kind != StmtKind::Call {
                return false;
            }
            if let Some(callee) = &info.callee {
                let callee_lower = callee.to_ascii_lowercase();
                acquire_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                })
            } else {
                false
            }
        })
        .collect()
}

/// Find nodes matching release patterns for a given resource pair.
fn find_release_nodes(ctx: &AnalysisContext, release_patterns: &[&str]) -> Vec<NodeIndex> {
    ctx.cfg
        .node_indices()
        .filter(|&idx| {
            let info = &ctx.cfg[idx];
            if info.kind != StmtKind::Call {
                return false;
            }
            if let Some(callee) = &info.callee {
                let callee_lower = callee.to_ascii_lowercase();
                release_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                })
            } else {
                false
            }
        })
        .collect()
}

/// Check if a release node is on all paths from acquire to every exit.
fn release_on_all_exit_paths(
    ctx: &AnalysisContext,
    acquire: NodeIndex,
    release_nodes: &[NodeIndex],
    exit: NodeIndex,
) -> bool {
    // Use post-dominators as optimization: if any release post-dominates acquire, it's fine
    if let Some(post_doms) = dominators::compute_post_dominators(ctx.cfg) {
        for &release in release_nodes {
            if dominators::dominates(&post_doms, release, acquire) {
                return true;
            }
        }
    }

    // Fall back to path enumeration via DFS
    // Check if all paths from acquire to exit pass through a release
    let release_set: HashSet<_> = release_nodes.iter().copied().collect();
    all_paths_pass_through(ctx, acquire, exit, &release_set)
}

/// Check if all paths from `from` to `to` pass through at least one node in `through`.
fn all_paths_pass_through(
    ctx: &AnalysisContext,
    from: NodeIndex,
    to: NodeIndex,
    through: &HashSet<NodeIndex>,
) -> bool {
    use std::collections::VecDeque;

    if through.contains(&from) {
        return true;
    }

    // BFS, tracking whether we've passed through a required node
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((from, false));
    visited.insert((from, false));

    while let Some((node, passed)) = queue.pop_front() {
        if node == to {
            if !passed {
                return false; // Found a path to exit without passing through release
            }
            continue;
        }

        for succ in ctx.cfg.neighbors(node) {
            let new_passed = passed || through.contains(&succ);
            let state = (succ, new_passed);
            if visited.insert(state) {
                queue.push_back(state);
            }
        }
    }

    true
}

impl CfgAnalysis for ResourceMisuse {
    fn name(&self) -> &'static str {
        "resource-misuse"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let pairs = rules::resource_pairs(ctx.lang);
        let exit = match dominators::find_exit_node(ctx.cfg) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let mut findings = Vec::new();

        for pair in pairs {
            let acquire_nodes = find_acquire_nodes(ctx, pair.acquire);
            let release_nodes = find_release_nodes(ctx, pair.release);

            for &acquire in &acquire_nodes {
                if !release_on_all_exit_paths(ctx, acquire, &release_nodes, exit) {
                    let info = &ctx.cfg[acquire];
                    let callee_desc = info.callee.as_deref().unwrap_or("(acquire)");

                    findings.push(CfgFinding {
                        rule_id: if pair.resource_name == "mutex" {
                            "cfg-lock-not-released".to_string()
                        } else {
                            "cfg-resource-leak".to_string()
                        },
                        title: format!("{} may leak", pair.resource_name),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        span: info.span,
                        message: format!(
                            "`{callee_desc}` acquires {} but not all exit paths \
                             release it",
                            pair.resource_name
                        ),
                        evidence: vec![acquire],
                        score: None,
                    });
                }
            }
        }

        findings
    }
}
