use super::dominators::{self, dominates};
use super::rules;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence, is_entry_point_func};
use crate::cfg::StmtKind;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule};
use crate::patterns::Severity;
use petgraph::graph::NodeIndex;

pub struct UnguardedSink;

/// Check whether **all** arguments to the sink are constants (no taint-capable
/// variable flows).  Extends the inline callee-part check by tracing one hop
/// through the CFG: if a used variable is defined by a node that itself has
/// empty `uses` and no Source label, the definition is treated as a constant
/// binding (e.g. `let cmd = "git"; Command::new(cmd)`).
fn is_all_args_constant(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.callee.as_deref().unwrap_or("");
    let callee_parts: Vec<&str> = callee_desc.split(['.', ':']).collect();
    let sink_func = sink_info.enclosing_func.as_deref();

    sink_info.uses.iter().all(|u| {
        // Part of the callee name itself → constant
        if callee_parts.contains(&u.as_str()) {
            return true;
        }
        // One-hop trace: find the defining node in the same function
        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];
            if info.enclosing_func.as_deref() != sink_func {
                continue;
            }
            if info.defines.as_deref() == Some(u.as_str()) {
                // If the defining node has no uses (pure constant) and is not
                // a Source, the variable is constant.
                if info.uses.is_empty() && !matches!(info.label, Some(DataLabel::Source(_))) {
                    return true;
                }
            }
        }
        false
    })
}

/// Check if a callee matches any of the runtime label rules that are sanitizers.
fn match_config_sanitizer(callee: &str, extra: &[RuntimeLabelRule]) -> Option<Cap> {
    let callee_lower = callee.to_ascii_lowercase();
    for rule in extra {
        let cap = match rule.label {
            DataLabel::Sanitizer(c) => c,
            _ => continue,
        };
        for m in &rule.matchers {
            let ml = m.to_ascii_lowercase();
            if ml.ends_with('_') {
                if callee_lower.starts_with(&ml) {
                    return Some(cap);
                }
            } else if callee_lower.ends_with(&ml) {
                return Some(cap);
            }
        }
    }
    None
}

/// Find all nodes in the CFG that are calls to guard functions.
fn find_guard_nodes(ctx: &AnalysisContext) -> Vec<(NodeIndex, Cap)> {
    let guard_rules = rules::guard_rules(ctx.lang);
    let config_rules = ctx
        .analysis_rules
        .map(|r| r.extra_labels.as_slice())
        .unwrap_or(&[]);
    let mut result = Vec::new();

    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.kind != StmtKind::Call {
            continue;
        }
        if let Some(callee) = &info.callee {
            // Check config sanitizer rules first
            if let Some(cap) = match_config_sanitizer(callee, config_rules) {
                result.push((idx, cap));
                continue;
            }

            // Then check built-in guard rules
            let callee_lower = callee.to_ascii_lowercase();
            for rule in guard_rules {
                let matched = rule.matchers.iter().any(|m| {
                    let ml = m.to_ascii_lowercase();
                    if ml.ends_with('_') {
                        callee_lower.starts_with(&ml)
                    } else {
                        callee_lower.ends_with(&ml)
                    }
                });
                if matched {
                    result.push((idx, rule.applies_to_sink_caps));
                    break;
                }
            }
        }
    }

    result
}

/// Check whether taint analysis confirmed unsanitized flow to this sink node.
fn taint_confirms_sink(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    ctx.taint_findings.iter().any(|f| f.sink == sink)
}

/// Check whether any variable used by the sink is directly derived from a
/// Source node in the same function (via simple def-use chain).
fn sink_arg_is_source_derived(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.enclosing_func.as_deref();

    // Collect all variables the sink reads
    let sink_uses = &sink_info.uses;
    if sink_uses.is_empty() {
        return false;
    }

    // Walk all nodes in the same function looking for Source nodes that define
    // one of the variables the sink uses.
    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.enclosing_func.as_deref() != sink_func {
            continue;
        }
        if !matches!(info.label, Some(DataLabel::Source(_))) {
            continue;
        }
        // Source node defines a variable that the sink reads → source-derived
        if let Some(def) = &info.defines
            && sink_uses.iter().any(|u| u == def)
        {
            return true;
        }
    }
    false
}

/// Check whether the sink's arguments are *only* function parameters
/// (i.e. this function is a thin wrapper around the sink).
fn sink_arg_is_parameter_only(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.enclosing_func.as_deref();

    let sink_uses = &sink_info.uses;
    if sink_uses.is_empty() {
        // No identifiable arguments — could be a constant call like Command::new("ls")
        return true; // treat as non-dangerous (constant arg)
    }

    // Collect parameter names for the enclosing function from FuncSummaries
    let param_names: Vec<&str> = ctx
        .func_summaries
        .values()
        .filter(|s| {
            // Match by function entry being in the same function
            ctx.cfg[s.entry].enclosing_func.as_deref() == sink_func
        })
        .flat_map(|s| s.param_names.iter().map(|p| p.as_str()))
        .collect();

    if param_names.is_empty() {
        return false; // can't determine params
    }

    // Check if ALL sink uses are parameters
    sink_uses.iter().all(|u| param_names.contains(&u.as_str()))
}

/// Check if the enclosing function qualifies as an entrypoint.
fn sink_in_entrypoint(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    if let Some(func_name) = &sink_info.enclosing_func {
        is_entry_point_func(func_name, ctx.lang)
    } else {
        false
    }
}

impl CfgAnalysis for UnguardedSink {
    fn name(&self) -> &'static str {
        "unguarded-sink"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let doms = dominators::compute_dominators(ctx.cfg, ctx.entry);
        let sink_nodes = dominators::find_sink_nodes(ctx.cfg);
        let guard_nodes = find_guard_nodes(ctx);

        let mut findings = Vec::new();

        for sink in &sink_nodes {
            let sink_info = &ctx.cfg[*sink];
            let sink_caps = match sink_info.label {
                Some(DataLabel::Sink(caps)) => caps,
                _ => continue,
            };

            let sink_func = sink_info.enclosing_func.as_deref();

            // Check: does any applicable guard dominate this sink?
            // Guards must be in the same function to be relevant.
            let is_guarded = guard_nodes.iter().any(|(guard_idx, guard_caps)| {
                let guard_func = ctx.cfg[*guard_idx].enclosing_func.as_deref();
                (*guard_caps & sink_caps) != Cap::empty()
                    && guard_func == sink_func
                    && dominates(&doms, *guard_idx, *sink)
            });

            // Also check if an inline sanitizer dominates this sink (same function).
            let has_sanitizer = ctx.cfg.node_indices().any(|idx| {
                let node_func = ctx.cfg[idx].enclosing_func.as_deref();
                if let Some(DataLabel::Sanitizer(san_caps)) = ctx.cfg[idx].label {
                    (san_caps & sink_caps) != Cap::empty()
                        && node_func == sink_func
                        && dominates(&doms, idx, *sink)
                } else {
                    false
                }
            });

            if is_guarded || has_sanitizer {
                continue;
            }

            let callee_desc = sink_info.callee.as_deref().unwrap_or("(unknown sink)");

            // ── Severity classification ───────────────────────────────
            //
            // HIGH: taint confirms flow OR source directly feeds sink
            // MEDIUM: structural finding without taint confirmation
            // LOW: wrapper function (param-only, non-entrypoint)

            let has_taint = taint_confirms_sink(ctx, *sink);
            let source_derived = sink_arg_is_source_derived(ctx, *sink);

            // If sink args are all constants (including one-hop constant bindings)
            // and taint didn't confirm, this is a false positive — skip it.
            if is_all_args_constant(ctx, *sink) && !has_taint && !source_derived {
                continue;
            }

            let param_only = sink_arg_is_parameter_only(ctx, *sink);
            let in_entrypoint = sink_in_entrypoint(ctx, *sink);

            let (severity, confidence) = if has_taint || source_derived {
                // Taint-confirmed or directly source-derived → HIGH
                (Severity::High, Confidence::High)
            } else if param_only && !in_entrypoint {
                // Wrapper function consuming only parameters → LOW
                (Severity::Low, Confidence::Low)
            } else if !ctx.taint_active && !source_derived {
                // CFG-only mode without taint confirmation → LOW
                (Severity::Low, Confidence::Low)
            } else if in_entrypoint && !param_only {
                // Entrypoint with non-parameter args but no taint confirmation → MEDIUM
                (Severity::Medium, Confidence::Medium)
            } else {
                // Generic structural finding → MEDIUM
                (Severity::Medium, Confidence::Medium)
            };

            findings.push(CfgFinding {
                rule_id: "cfg-unguarded-sink".to_string(),
                title: "Unguarded sink".to_string(),
                severity,
                confidence,
                span: sink_info.span,
                message: format!("Sink `{callee_desc}` has no dominating guard or sanitizer"),
                evidence: vec![*sink],
                score: None,
            });
        }

        findings
    }
}
