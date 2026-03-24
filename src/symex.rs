//! Symbolic execution targeting: candidate selection and constraint analysis
//! for taint findings.
//!
//! After SSA taint analysis produces findings, this module selects candidates
//! (non-trivial paths, non-validated) and runs constraint analysis on each
//! path to determine feasibility. Results are stored as `SymbolicVerdict` on
//! the finding, which flows through to Evidence and confidence scoring.

use std::collections::{HashMap, HashSet};

use crate::cfg::Cfg;
use crate::constraint;
use crate::evidence::{SymbolicVerdict, Verdict};
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::{BlockId, SsaBody, SsaValue, Terminator};
use crate::ssa::type_facts::TypeFactResult;
use crate::taint::Finding;

/// Maximum candidates to analyse per file (budget bound).
const MAX_CANDIDATES: usize = 50;

/// Maximum blocks on a path before we skip symex (too expensive).
const MAX_PATH_BLOCKS: usize = 100;

/// Feature gate: check if symbolic execution targeting is enabled.
///
/// Enabled by default. Set `NYX_SYMEX=0` or `NYX_SYMEX=false` to disable.
pub fn is_enabled() -> bool {
    std::env::var("NYX_SYMEX")
        .map(|v| v != "0" && v.to_ascii_lowercase() != "false")
        .unwrap_or(true)
}

/// Run symex analysis on eligible findings, mutating them in place.
///
/// Pre-filters: skips path_validated findings and those with fewer than 2
/// flow steps. Respects the per-file candidate budget.
pub fn annotate_findings(
    findings: &mut [Finding],
    ssa: &SsaBody,
    cfg: &Cfg,
    const_values: &HashMap<SsaValue, ConstLattice>,
    type_facts: &TypeFactResult,
) {
    let mut budget = MAX_CANDIDATES;
    for finding in findings.iter_mut() {
        if budget == 0 {
            break;
        }
        if finding.flow_steps.len() < 2 || finding.path_validated {
            continue;
        }
        finding.symbolic = Some(analyse_finding_path(
            finding, ssa, cfg, const_values, type_facts,
        ));
        budget -= 1;
    }
}

/// Extract the ordered sequence of SSA blocks along a finding's flow path.
///
/// Maps `flow_steps` CFG nodes through `ssa.cfg_node_map` to SSA blocks,
/// deduplicating consecutive blocks.
fn extract_path_blocks(finding: &Finding, ssa: &SsaBody) -> Vec<BlockId> {
    let mut blocks = Vec::new();
    let mut seen = HashSet::new();
    for step in &finding.flow_steps {
        if let Some(&val) = ssa.cfg_node_map.get(&step.cfg_node) {
            if val.0 < ssa.value_defs.len() as u32 {
                let block = ssa.value_defs[val.0 as usize].block;
                if seen.insert(block) {
                    blocks.push(block);
                }
            }
        }
    }
    blocks
}

/// Run constraint analysis on a single finding's taint path.
///
/// Walks the SSA blocks from source to sink, collecting branch conditions
/// and feeding them to the constraint solver. Returns a `SymbolicVerdict`.
fn analyse_finding_path(
    finding: &Finding,
    ssa: &SsaBody,
    cfg: &Cfg,
    const_values: &HashMap<SsaValue, ConstLattice>,
    type_facts: &TypeFactResult,
) -> SymbolicVerdict {
    let path_blocks = extract_path_blocks(finding, ssa);

    if path_blocks.len() < 2 {
        return SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 1,
            witness: None,
        };
    }

    if path_blocks.len() > MAX_PATH_BLOCKS {
        return SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 0,
            witness: Some("path too long for symex budget".into()),
        };
    }

    // Build set of on-path blocks for successor determination
    let on_path: HashSet<BlockId> = path_blocks.iter().copied().collect();

    // Seed PathEnv from optimization results
    let mut env = constraint::PathEnv::empty();
    env.seed_from_optimization(const_values, type_facts);

    let mut constraints_checked: u32 = 0;
    let mut unknown_count: u32 = 0;

    // Walk each block on the path, apply branch conditions
    for &block_id in &path_blocks {
        let block = &ssa.blocks[block_id.0 as usize];
        match &block.terminator {
            Terminator::Branch {
                cond,
                true_blk,
                false_blk,
                condition,
            } => {
                // Determine which successor is on the path
                let true_on_path = on_path.contains(true_blk);
                let false_on_path = on_path.contains(false_blk);

                // If both or neither successor is on path, skip
                // (branch doesn't constrain the path)
                if true_on_path == false_on_path {
                    continue;
                }

                let polarity = true_on_path;

                // Prefer pre-lowered structured condition; fall back to
                // text-based lowering.
                let cond_expr = if let Some(pre_lowered) = condition {
                    (**pre_lowered).clone()
                } else {
                    constraint::lower_condition(
                        &cfg[*cond],
                        ssa,
                        block_id,
                        Some(const_values),
                    )
                };

                if matches!(cond_expr, constraint::ConditionExpr::Unknown) {
                    unknown_count += 1;
                    continue;
                }

                env = constraint::refine_env(&env, &cond_expr, polarity);
                constraints_checked += 1;

                if env.is_unsat() {
                    return SymbolicVerdict {
                        verdict: Verdict::Infeasible,
                        constraints_checked,
                        paths_explored: 1,
                        witness: None,
                    };
                }
            }
            Terminator::Goto(_) | Terminator::Return | Terminator::Unreachable => {}
        }
    }

    // Determine verdict based on what we learned
    let verdict = if constraints_checked == 0 && unknown_count > 0 {
        Verdict::Inconclusive
    } else if constraints_checked == 0 {
        // No branches on path — trivially feasible
        Verdict::Confirmed
    } else {
        Verdict::Confirmed
    };

    SymbolicVerdict {
        verdict,
        constraints_checked,
        paths_explored: 1,
        witness: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::ir::{BlockId, SsaBlock, SsaBody, SsaValue, Terminator, ValueDef};
    use crate::ssa::type_facts::TypeFactResult;
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    fn empty_type_facts() -> TypeFactResult {
        TypeFactResult {
            facts: HashMap::new(),
        }
    }

    fn make_value_def(block: BlockId, cfg_node: NodeIndex) -> ValueDef {
        ValueDef {
            var_name: None,
            cfg_node,
            block,
        }
    }

    #[test]
    fn is_enabled_default() {
        // Remove env var if set, check default
        unsafe { std::env::remove_var("NYX_SYMEX") };
        assert!(is_enabled());
    }

    #[test]
    fn is_enabled_disabled() {
        unsafe { std::env::set_var("NYX_SYMEX", "0") };
        assert!(!is_enabled());
        unsafe { std::env::set_var("NYX_SYMEX", "false") };
        assert!(!is_enabled());
        unsafe { std::env::remove_var("NYX_SYMEX") };
    }

    #[test]
    fn extract_path_blocks_basic() {
        use crate::taint::FlowStepRaw;

        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let b0 = BlockId(0);
        let b1 = BlockId(1);

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return,
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![
                make_value_def(b0, n0),
                make_value_def(b1, n1),
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
        };

        let finding = Finding {
            sink: n1,
            source: n0,
            path: vec![n0, n1],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n1,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
        };

        let blocks = extract_path_blocks(&finding, &ssa);
        assert_eq!(blocks, vec![b0, b1]);
    }

    #[test]
    fn analyse_no_branches_confirmed() {
        use crate::taint::FlowStepRaw;

        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let b0 = BlockId(0);
        let b1 = BlockId(1);

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return,
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![
                make_value_def(b0, n0),
                make_value_def(b1, n1),
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
        };

        let finding = Finding {
            sink: n1,
            source: n0,
            path: vec![n0, n1],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n1,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
        };

        let verdict = analyse_finding_path(
            &finding,
            &ssa,
            &Cfg::new(),
            &HashMap::new(),
            &empty_type_facts(),
        );
        assert_eq!(verdict.verdict, Verdict::Confirmed);
        assert_eq!(verdict.constraints_checked, 0);
        assert_eq!(verdict.paths_explored, 1);
    }

    #[test]
    fn annotate_skips_validated() {
        use crate::taint::FlowStepRaw;

        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);

        let mut finding = Finding {
            sink: n1,
            source: n0,
            path: vec![n0, n1],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: true, // should be skipped
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n1,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
        };

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
        };

        annotate_findings(
            std::slice::from_mut(&mut finding),
            &ssa,
            &Cfg::new(),
            &HashMap::new(),
            &empty_type_facts(),
        );
        // Should remain None — skipped due to path_validated
        assert!(finding.symbolic.is_none());
    }

    #[test]
    fn annotate_skips_short_path() {
        use crate::taint::FlowStepRaw;

        let n0 = NodeIndex::new(0);

        let mut finding = Finding {
            sink: n0,
            source: n0,
            path: vec![n0],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![FlowStepRaw {
                cfg_node: n0,
                var_name: Some("x".into()),
                op_kind: crate::evidence::FlowStepKind::Source,
            }],
            symbolic: None,
        };

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
        };

        annotate_findings(
            std::slice::from_mut(&mut finding),
            &ssa,
            &Cfg::new(),
            &HashMap::new(),
            &empty_type_facts(),
        );
        // Should remain None — only 1 flow step
        assert!(finding.symbolic.is_none());
    }
}
