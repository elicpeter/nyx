#![allow(clippy::collapsible_if)]

use super::dominators::{self, dominates};
use super::rules;
use super::{
    AnalysisContext, BodyConstFacts, CfgAnalysis, CfgFinding, Confidence, is_entry_point_func,
};
use crate::callgraph::callee_leaf_name;
use crate::cfg::StmtKind;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule};
use crate::patterns::Severity;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::type_facts::TypeFactResult;
use crate::ssa::{SsaOp, SsaValue};
use crate::taint::path_state::{PredicateKind, classify_condition};
use petgraph::graph::NodeIndex;
use std::collections::HashSet;

pub struct UnguardedSink;

/// Check whether **all** arguments to the sink are constants (no taint-capable
/// variable flows).  Extends the inline callee-part check by tracing one hop
/// through the CFG: if a used variable is defined by a node that itself has
/// empty `uses` and no Source label, the definition is treated as a constant
/// binding (e.g. `let cmd = "git"; Command::new(cmd)`).  When SSA
/// [`BodyConstFacts`] are available, falls back to walking the sink's
/// `SsaOp::Call` operands and consulting `OptimizeResult.const_values` for
/// any operand the syntactic trace can't classify (e.g. a chained method-call
/// receiver recorded as a compound identifier rather than a named binding).
fn is_all_args_constant(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    // Fast path: syntactic literal detection from CFG construction.
    // Strictly weaker than the one-hop trace below — serves as an
    // optimization for the common case of inline literal arguments.
    if ctx.cfg[sink].all_args_literal {
        return true;
    }
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    // Split callee description into parts and strip parenthesized arg portions.
    // e.g. `exec.Command("echo", "health-ok").Run` → ["exec", "Command", "Run"]
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    // When the callee was overridden by an inner call (e.g. `db.query` inside
    // `Promise.all([db.query(...)])`), the outer callee's parts (e.g. "Promise",
    // "all") also belong to the callee machinery, not to arguments.
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    sink_info.taint.uses.iter().all(|u| {
        // Part of the callee name itself → not an argument, skip
        // Check both individual parts and the full dotted callee path
        if callee_parts.contains(&u.as_str())
            || u == callee_desc
            || outer_parts.contains(&u.as_str())
        {
            return true;
        }
        // One-hop trace: find the defining node in the same function
        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];
            if info.ast.enclosing_func.as_deref() != sink_func {
                continue;
            }
            if info.taint.defines.as_deref() == Some(u.as_str()) {
                // If the defining node has no uses (pure constant) and is not
                // a Source, the variable is constant.
                if info.taint.uses.is_empty()
                    && !info
                        .taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, DataLabel::Source(_)))
                {
                    return true;
                }
            }
        }
        false
    }) || ssa_all_sink_operands_constant(ctx, sink, callee_desc, &callee_parts, &outer_parts)
}

/// SSA-backed fallback for `is_all_args_constant`.  Looks up the sink CFG
/// node in `cfg_node_map`, expects an `SsaOp::Call`, and checks that every
/// operand (positional args and receiver) either names a callee fragment or
/// resolves to a concrete `ConstLattice` literal.
fn ssa_all_sink_operands_constant(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    callee_desc: &str,
    callee_parts: &[&str],
    outer_parts: &[&str],
) -> bool {
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    let operand_const = |v: SsaValue| -> bool {
        ssa_operand_constant(v, facts, callee_desc, callee_parts, outer_parts)
    };
    let args_ok = args
        .iter()
        .all(|group| group.iter().all(|v| operand_const(*v)));
    let receiver_ok = receiver.is_none_or(operand_const);
    args_ok && receiver_ok
}

/// Return true if this SSA operand is a compile-time-known literal, a callee
/// fragment pseudo-use (not a real runtime value), or transitively composed
/// of such operands.  Returns false for sources, parameters with non-callee
/// names, `Varying` const-prop facts, and any unresolved definition.
fn ssa_operand_constant(
    root: SsaValue,
    facts: &BodyConstFacts,
    callee_desc: &str,
    callee_parts: &[&str],
    outer_parts: &[&str],
) -> bool {
    let mut visited: HashSet<SsaValue> = HashSet::new();
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        if !visited.insert(v) {
            continue;
        }
        match facts.const_values.get(&v) {
            Some(ConstLattice::Str(_))
            | Some(ConstLattice::Int(_))
            | Some(ConstLattice::Bool(_))
            | Some(ConstLattice::Null) => continue,
            Some(ConstLattice::Varying) => {
                // Fall through: a Varying lattice entry may still correspond
                // to a callee-fragment pseudo-name that the SSA models as a
                // Param.  The per-op check below filters those out.
            }
            _ => {}
        }
        let Some(inst) = find_inst(&facts.ssa, v) else {
            return false;
        };
        match &inst.op {
            SsaOp::Const(_) => {}
            SsaOp::Assign(vals) => stack.extend(vals.iter().copied()),
            SsaOp::Phi(ops) => stack.extend(ops.iter().map(|(_, v)| *v)),
            SsaOp::Call { args, receiver, .. } => {
                for group in args {
                    stack.extend(group.iter().copied());
                }
                if let Some(r) = receiver {
                    stack.push(*r);
                }
            }
            SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam | SsaOp::Source => {
                // Only acceptable when the param's `var_name` is a callee
                // fragment — i.e. an identifier that only appears because
                // the CFG recorded name components of the dotted/chained
                // callee as uses.  Real parameters and sources are dynamic.
                let name = inst.var_name.as_deref().unwrap_or("");
                if matches!(inst.op, SsaOp::Source) {
                    return false;
                }
                if !is_callee_fragment(name, callee_desc, callee_parts, outer_parts) {
                    return false;
                }
            }
            SsaOp::Nop => {}
        }
    }
    true
}

fn is_callee_fragment(
    name: &str,
    callee_desc: &str,
    callee_parts: &[&str],
    outer_parts: &[&str],
) -> bool {
    if name.is_empty() {
        return true;
    }
    if callee_parts.contains(&name) || outer_parts.contains(&name) || name == callee_desc {
        return true;
    }
    // Chained-receiver prefix: the name is a strict prefix of `callee_desc`
    // terminating at a `.` or `::` boundary (e.g. name =
    // `Command::new("sh").arg("-c").arg(cmd)` for callee_desc ending in
    // `.status().unwrap`).  These are the outer callee's receiver chain,
    // not user-supplied arguments.
    if callee_desc.len() > name.len() && callee_desc.starts_with(name) {
        let rest = &callee_desc[name.len()..];
        if rest.starts_with('.') || rest.starts_with("::") {
            return true;
        }
    }
    false
}

fn find_inst(ssa: &crate::ssa::SsaBody, v: SsaValue) -> Option<&crate::ssa::SsaInst> {
    let def = ssa.value_defs.get(v.0 as usize)?;
    let block = ssa.blocks.get(def.block.0 as usize)?;
    block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|inst| inst.value == v)
}

/// Check whether every operand SSA value of the sink's Call instruction is
/// proven by type-fact analysis to be non-injectable for `sink_caps`.
///
/// Used to suppress `cfg-unguarded-sink` when all arguments are typed safe
/// (e.g. Rust `port: u16` flowing into `Command::new(…).arg(port.to_string())`).
/// Returns `false` when any required fact is missing so the structural finding
/// is preserved whenever typing is ambiguous.
fn sink_args_typed_safe(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(type_facts) = ctx.type_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    // Chained Rust/JS calls record the whole dotted path as a single Call node.
    // Its SSA operands include pseudo-uses for every identifier segment of the
    // callee (e.g. `Command`, `new`, `arg`, `status`, `unwrap`) plus string
    // literal arguments to intermediate calls.  Filter those out so the
    // is-Int check runs only against real argument values.
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();

    let is_real_arg = |v: SsaValue| -> bool {
        let Some(def) = find_inst(&facts.ssa, v) else {
            return true;
        };
        // Callee-fragment pseudo-uses appear as `Param { .. }` with a
        // var_name that is a segment of the callee text.  SelfParam and
        // CatchParam cover `self`/exception bindings that cannot be the
        // implicit callee chain.
        match &def.op {
            SsaOp::Param { .. } => {
                let name = def.var_name.as_deref().unwrap_or("");
                !is_callee_fragment(name, callee_desc, &callee_parts, &outer_parts)
            }
            // Constant string literals used as inline args (e.g. `"listener"`,
            // `"-c"`) are not user-controlled — treat as non-real for the
            // "all int-typed" test so they don't block suppression.
            SsaOp::Const(_) => false,
            _ => true,
        }
    };

    let mut values: Vec<SsaValue> = Vec::new();
    if let Some(r) = receiver {
        if is_real_arg(*r) {
            values.push(*r);
        }
    }
    for group in args {
        for v in group.iter() {
            if is_real_arg(*v) {
                values.push(*v);
            }
        }
    }
    type_facts_suppress(&values, sink_caps, type_facts)
}

/// Thin wrapper around [`crate::ssa::type_facts::is_type_safe_for_sink`] kept
/// local so the unit tests here can exercise the exact predicate used at the
/// `cfg-unguarded-sink` emission site.
fn type_facts_suppress(
    values: &[SsaValue],
    sink_caps: Cap,
    type_facts: &TypeFactResult,
) -> bool {
    crate::ssa::type_facts::is_type_safe_for_sink(values, sink_caps, type_facts)
}

/// Suppress a `cfg-unguarded-sink` finding when every real argument SSA
/// value resolves to a finite set of metacharacter-free literals, as proved
/// by the static-map analysis.  Runs in lock-step with the SSA taint
/// suppression so both findings paths agree on when a provably-bounded
/// lookup idiom (e.g. `map.get(x).unwrap_or("safe")` over literal inserts)
/// should clear a command-injection sink.
///
/// Only fires for `Cap::SHELL_ESCAPE` — SQL / path suppression from this
/// domain would require stronger reasoning (literal keys can still carry
/// SQL tokens if the inserts themselves contain them).
fn sink_args_static_map_safe(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.intersects(Cap::SHELL_ESCAPE) {
        return false;
    }
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    let sm = crate::ssa::static_map::analyze(
        &facts.ssa,
        ctx.cfg,
        Some(ctx.lang),
        &facts.const_values,
    );
    if sm.is_empty() {
        return false;
    }

    // Skip callee-fragment pseudo-uses the same way `sink_args_typed_safe`
    // does so only real runtime arg values participate in the check.
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();

    let is_real_arg = |v: SsaValue| -> bool {
        let Some(def) = find_inst(&facts.ssa, v) else {
            return true;
        };
        match &def.op {
            SsaOp::Param { .. } => {
                let name = def.var_name.as_deref().unwrap_or("");
                !is_callee_fragment(name, callee_desc, &callee_parts, &outer_parts)
            }
            SsaOp::Const(_) => false,
            _ => true,
        }
    };

    let mut values: Vec<SsaValue> = Vec::new();
    if let Some(r) = receiver {
        if is_real_arg(*r) {
            values.push(*r);
        }
    }
    for group in args {
        for v in group.iter() {
            if is_real_arg(*v) {
                values.push(*v);
            }
        }
    }
    if values.is_empty() {
        return false;
    }
    values.iter().all(|v| match sm.finite_string_values.get(v) {
        Some(set) if !set.is_empty() => set
            .iter()
            .all(|s| crate::abstract_interp::string_domain::is_shell_safe_literal(s)),
        _ => false,
    })
}

/// Check if a callee matches any of the runtime label rules that are sanitizers.
fn match_config_sanitizer(callee: &str, extra: &[RuntimeLabelRule]) -> Option<Cap> {
    // Lazily compute lowercased callee only when a case-insensitive rule is hit.
    let mut callee_lower: Option<String> = None;

    for rule in extra {
        let cap = match rule.label {
            DataLabel::Sanitizer(c) => c,
            _ => continue,
        };
        for m in &rule.matchers {
            if rule.case_sensitive {
                if m.ends_with('_') {
                    if callee.starts_with(m.as_str()) {
                        return Some(cap);
                    }
                } else if callee.ends_with(m.as_str()) {
                    return Some(cap);
                }
            } else {
                let cl = callee_lower.get_or_insert_with(|| callee.to_ascii_lowercase());
                let ml = m.to_ascii_lowercase();
                if ml.ends_with('_') {
                    if cl.starts_with(&ml) {
                        return Some(cap);
                    }
                } else if cl.ends_with(&ml) {
                    return Some(cap);
                }
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

        // If-condition guards: allowlist checks, type checks, validation
        // calls, shell-metachar rejections, and bounded-length checks in
        // branch conditions act as guards for downstream sinks.
        if info.kind == StmtKind::If {
            if let Some(cond_text) = &info.condition_text {
                let kind = classify_condition(cond_text);
                if matches!(
                    kind,
                    PredicateKind::AllowlistCheck
                        | PredicateKind::TypeCheck
                        | PredicateKind::ValidationCall
                ) {
                    result.push((idx, Cap::all()));
                } else if matches!(
                    kind,
                    PredicateKind::ShellMetaValidated | PredicateKind::BoundedLength
                ) {
                    // Shell-metachar rejection and bounded-length checks only
                    // guard shell-family sinks.  Keep scope tight so unrelated
                    // sinks (SQL, XSS) aren't silenced when a shell gate
                    // happens to sit upstream.
                    result.push((idx, Cap::SHELL_ESCAPE | Cap::CODE_EXEC));
                }
            }
        }

        if info.kind != StmtKind::Call {
            continue;
        }
        if let Some(callee) = &info.call.callee {
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
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    // Collect all variables the sink reads
    let sink_uses = &sink_info.taint.uses;
    if sink_uses.is_empty() {
        return false;
    }

    // Walk all nodes in the same function looking for Source nodes that define
    // one of the variables the sink uses.
    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.ast.enclosing_func.as_deref() != sink_func {
            continue;
        }
        if !info
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_)))
        {
            continue;
        }
        // Source node defines a variable that the sink reads → source-derived
        if let Some(def) = &info.taint.defines
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
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    let sink_uses = &sink_info.taint.uses;
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
            ctx.cfg[s.entry].ast.enclosing_func.as_deref() == sink_func
        })
        .flat_map(|s| s.param_names.iter().map(|p| p.as_str()))
        .collect();

    if param_names.is_empty() {
        return false; // can't determine params
    }

    // Check if ALL sink uses are parameters
    sink_uses.iter().all(|u| param_names.contains(&u.as_str()))
}

/// Check if the source bytes at a given span contain a redirect call whose
/// argument starts with a path prefix (`/...`), indicating a server-relative
/// path rather than an attacker-controlled URL.
///
/// Reused by both `cfg-unguarded-sink` suppression and taint finding filtering.
pub(crate) fn has_redirect_path_prefix(source_bytes: &[u8], span: (usize, usize)) -> bool {
    let (start, end) = span;
    if start >= source_bytes.len() || end > source_bytes.len() {
        return false;
    }
    let text = &source_bytes[start..end];
    // Search for the argument portion after the first '('
    if let Some(paren_pos) = text.iter().position(|&b| b == b'(') {
        let after_paren = &text[paren_pos + 1..];
        let trimmed = after_paren
            .iter()
            .skip_while(|&&b| b == b' ' || b == b'\n' || b == b'\t')
            .copied()
            .collect::<Vec<_>>();
        // Template literal: `/ ...
        if trimmed.starts_with(b"`/") {
            return true;
        }
        // String literal: "/ ... or '/ ...
        if trimmed.starts_with(b"\"/") || trimmed.starts_with(b"'/") {
            return true;
        }
    }
    false
}

/// Check if this sink is an internal redirect — a `res.redirect` (SSRF sink)
/// whose argument is a template literal or string starting with `/`, indicating
/// a server-relative path rather than an attacker-controlled URL.
fn is_internal_redirect(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.contains(Cap::SSRF) {
        return false;
    }
    let sink_info = &ctx.cfg[sink];
    let callee = match &sink_info.call.callee {
        Some(c) => c.as_str(),
        None => return false,
    };
    // Only applies to redirect calls
    if !callee.ends_with("redirect") && !callee.ends_with("Redirect") {
        return false;
    }
    has_redirect_path_prefix(ctx.source_bytes, sink_info.ast.span)
}

/// Check if the enclosing function qualifies as an entrypoint.
fn sink_in_entrypoint(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    if let Some(func_name) = &sink_info.ast.enclosing_func {
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
            let sink_caps = sink_info.taint.labels.iter().fold(Cap::empty(), |acc, l| {
                if let DataLabel::Sink(caps) = l {
                    acc | *caps
                } else {
                    acc
                }
            });
            if sink_caps.is_empty() {
                continue;
            }

            let sink_func = sink_info.ast.enclosing_func.as_deref();

            // Check: does any applicable guard dominate this sink?
            // Guards must be in the same function to be relevant.
            let is_guarded = guard_nodes.iter().any(|(guard_idx, guard_caps)| {
                let guard_func = ctx.cfg[*guard_idx].ast.enclosing_func.as_deref();
                (*guard_caps & sink_caps) != Cap::empty()
                    && guard_func == sink_func
                    && dominates(&doms, *guard_idx, *sink)
            });

            // Also check if an inline sanitizer dominates this sink (same function).
            let has_sanitizer = ctx.cfg.node_indices().any(|idx| {
                let node_func = ctx.cfg[idx].ast.enclosing_func.as_deref();
                ctx.cfg[idx].taint.labels.iter().any(|l| {
                    if let DataLabel::Sanitizer(san_caps) = l {
                        (*san_caps & sink_caps) != Cap::empty()
                            && node_func == sink_func
                            && dominates(&doms, idx, *sink)
                    } else {
                        false
                    }
                })
            });

            // Interprocedural sanitizer: check if any arg_callee resolves to a
            // function with sanitizer caps that cover this sink's caps.
            let has_interprocedural_sanitizer = sink_info.arg_callees.iter().any(|mc| {
                if let Some(callee) = mc {
                    let leaf = callee_leaf_name(callee);
                    // Check local function summaries
                    ctx.func_summaries.iter().any(|(k, s)| {
                        k.name == leaf && (s.sanitizer_caps & sink_caps) != Cap::empty()
                    })
                } else {
                    false
                }
            });

            if is_guarded || has_sanitizer || has_interprocedural_sanitizer {
                continue;
            }

            let callee_desc = sink_info.call.callee.as_deref().unwrap_or("(unknown sink)");

            // ── Severity classification ───────────────────────────────
            //
            // HIGH: taint confirms flow OR source directly feeds sink
            // MEDIUM: structural finding without taint confirmation
            // LOW: wrapper function (param-only, non-entrypoint)

            let has_taint = taint_confirms_sink(ctx, *sink);
            let source_derived = sink_arg_is_source_derived(ctx, *sink);

            // If sink args are all constants (including one-hop constant bindings)
            // and taint didn't confirm, this is a false positive — skip it.
            if is_all_args_constant(ctx, *sink) && !has_taint {
                continue;
            }

            // Type-aware suppression: when all SSA operand values of the sink
            // are proven to carry non-injectable types (e.g. integers parsed
            // from a raw source), the arguments cannot form a payload for
            // SHELL/SQL/FILE sinks.  Skip the structural finding — the taint
            // engine already covers the source→sink flow via Phase 10 type
            // suppression.  Unknown-typed or mixed operands fall through.
            if !has_taint && sink_args_typed_safe(ctx, *sink, sink_caps) {
                continue;
            }

            // Static-map suppression: the SSA value flowing into the sink is
            // proved by the static-HashMap-lookup idiom detector to be a
            // finite set of literals free of shell metacharacters.  Mirrors
            // the SSA-taint finite-domain suppression so both paths agree.
            if !has_taint && sink_args_static_map_safe(ctx, *sink, sink_caps) {
                continue;
            }

            // Parameterized SQL queries: arg 0 is a string literal with
            // placeholders ($1, ?, %s, :name) and a params argument exists.
            // These are safe by construction — the driver handles escaping.
            if sink_info.parameterized_query {
                continue;
            }

            // Internal redirects: res.redirect(`/path/...`) with a path-prefix
            // argument are server-relative — not attacker-controlled URLs.
            if is_internal_redirect(ctx, *sink, sink_caps) {
                continue;
            }

            let param_only = sink_arg_is_parameter_only(ctx, *sink);
            let in_entrypoint = sink_in_entrypoint(ctx, *sink);

            let (severity, confidence) = if has_taint || source_derived {
                (Severity::High, Confidence::High)
            } else if param_only && !in_entrypoint {
                // Wrapper function with param-only args — zero signal. Suppress.
                continue;
            } else if !ctx.taint_active {
                // AST-only / cfg-only mode — preserve as LOW (unchanged)
                (Severity::Low, Confidence::Low)
            } else {
                // taint_active=true but found nothing.
                // Keep high-risk sinks (SHELL_ESCAPE, CODE_EXEC, SQL_QUERY, DESERIALIZE)
                // as structural backup. Suppress low-risk sinks (FILE_IO, SSRF, etc.).
                let high_risk =
                    Cap::SHELL_ESCAPE | Cap::CODE_EXEC | Cap::SQL_QUERY | Cap::DESERIALIZE;
                if (sink_caps & high_risk).is_empty() {
                    continue; // FILE_IO, SSRF, FMT_STRING etc. without taint → noise
                }
                // If the function containing the sink has no Source-labeled
                // nodes AND no parameters (through which taint could flow
                // from callers), taint ran and found nothing because there
                // is nothing to find.  Suppress — the structural finding
                // is noise.
                let sink_func = sink_info.ast.enclosing_func.as_deref();
                let has_sources = ctx.cfg.node_indices().any(|n| {
                    let info = &ctx.cfg[n];
                    info.ast.enclosing_func.as_deref() == sink_func
                        && info
                            .taint
                            .labels
                            .iter()
                            .any(|l| matches!(l, DataLabel::Source(_)))
                });
                let has_params = ctx.func_summaries.values().any(|s| {
                    s.entry.index() < ctx.cfg.node_count()
                        && ctx.cfg[s.entry].ast.enclosing_func.as_deref() == sink_func
                        && !s.param_names.is_empty()
                });
                if !has_sources && !has_params {
                    continue; // No sources or params in scope → noise
                }
                (Severity::Medium, Confidence::Medium)
            };

            findings.push(CfgFinding {
                rule_id: "cfg-unguarded-sink".to_string(),
                title: "Unguarded sink".to_string(),
                severity,
                confidence,
                span: sink_info.ast.span,
                message: format!("Sink `{callee_desc}` has no dominating guard or sanitizer"),
                evidence: vec![*sink],
                score: None,
            });
        }

        findings
    }
}
