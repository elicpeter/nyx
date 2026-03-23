pub mod domain;
pub mod path_state;
pub mod ssa_transfer;

use crate::cfg::{Cfg, FuncSummaries};
use crate::interop::InteropEdge;
use crate::labels::SourceKind;
use crate::state::engine::MAX_TRACKED_VARS;
use crate::state::symbol::{SymbolId, SymbolInterner};
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use std::collections::HashSet;

/// A raw flow step at CFG level (before line/col resolution).
#[derive(Debug, Clone)]
pub struct FlowStepRaw {
    pub cfg_node: NodeIndex,
    pub var_name: Option<String>,
    pub op_kind: crate::evidence::FlowStepKind,
}

/// A detected taint finding with both source and sink locations.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The CFG node where tainted data reaches a dangerous operation.
    pub sink: NodeIndex,
    /// The CFG node where taint originated (may be Entry if source is
    /// cross-file and couldn't be pinpointed to a specific node).
    pub source: NodeIndex,
    /// The full path from source to sink through the CFG.
    #[allow(dead_code)] // used for future detailed diagnostics / path display
    pub path: Vec<NodeIndex>,
    /// The kind of source that originated the taint.
    pub source_kind: SourceKind,
    /// Whether all tainted sink variables are guarded by a validation
    /// predicate on this path (metadata only — does not change severity).
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    pub guard_kind: Option<PredicateKind>,
    /// Number of SSA blocks between source and sink (0 = same block).
    pub hop_count: u16,
    /// Capability specificity: number of matching cap bits between source and sink.
    /// Higher = more specific match (e.g. SQL_QUERY→SQL_QUERY vs broad Cap::all()).
    pub cap_specificity: u8,
    /// Whether this finding was resolved via a function summary (cross-function)
    /// rather than direct intra-function flow.
    pub uses_summary: bool,
    /// Reconstructed flow path from source to sink (CFG-level, pre-resolution).
    pub flow_steps: Vec<FlowStepRaw>,
}

/// Run taint analysis on a single file's CFG.
///
/// Uses SSA-based forward dataflow analysis for all 10 languages.
/// For JS/TS: uses a two-level solve to prevent cross-function taint
/// leakage while preserving global-to-function flows.
pub fn analyse_file(
    cfg: &Cfg,
    entry: NodeIndex,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Vec<Finding> {
    let _span = tracing::debug_span!("taint_analyse_file").entered();

    // 1. Build symbol interner from CFG
    let interner = SymbolInterner::from_cfg(cfg);

    if interner.len() > MAX_TRACKED_VARS {
        tracing::warn!(
            symbols = interner.len(),
            max = MAX_TRACKED_VARS,
            "taint analysis: too many variables, some will be ignored"
        );
    }

    // 2a. Lower all functions: produce both SSA summaries and cached bodies
    let (ssa_summaries, callee_bodies) = lower_all_functions(
        cfg, &interner, caller_lang, caller_namespace,
        local_summaries, global_summaries,
    );
    let ssa_sums_ref = if ssa_summaries.is_empty() { None } else { Some(&ssa_summaries) };

    // 2b. Context-sensitive inline analysis setup
    let context_sensitive = std::env::var("NYX_CONTEXT_SENSITIVE")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);
    let inline_cache = std::cell::RefCell::new(std::collections::HashMap::new());
    let callee_bodies_ref = if context_sensitive && !callee_bodies.is_empty() {
        Some(&callee_bodies)
    } else {
        None
    };
    let inline_cache_ref = if context_sensitive { Some(&inline_cache) } else { None };

    // 2c. Run SSA analysis (two-level for JS/TS, single-pass for others)
    let mut findings = if matches!(caller_lang, Lang::JavaScript | Lang::TypeScript) {
        match analyse_ssa_js_two_level(
            cfg, entry, &interner, caller_lang, caller_namespace,
            local_summaries, global_summaries, interop_edges, ssa_sums_ref,
            extra_labels, callee_bodies_ref, inline_cache_ref,
        ) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("SSA JS two-level lowering failed: {e}");
                Vec::new()
            }
        }
    } else {
        match crate::ssa::lower_to_ssa(cfg, entry, None, true) {
            Ok(mut ssa_body) => {
                let opt = crate::ssa::optimize_ssa(&mut ssa_body, cfg, Some(caller_lang));
                tracing::debug!(
                    blocks = ssa_body.blocks.len(),
                    values = ssa_body.num_values(),
                    branches_pruned = opt.branches_pruned,
                    copies_eliminated = opt.copies_eliminated,
                    dead_defs = opt.dead_defs_removed,
                    "SSA lowering + optimization succeeded"
                );
                let ssa_transfer = ssa_transfer::SsaTaintTransfer {
                    lang: caller_lang,
                    namespace: caller_namespace,
                    interner: &interner,
                    local_summaries,
                    global_summaries,
                    interop_edges,
                    global_seed: None,
                    const_values: Some(&opt.const_values),
                    type_facts: Some(&opt.type_facts),
                    ssa_summaries: ssa_sums_ref,
                    extra_labels,
                    base_aliases: Some(&opt.alias_result),
                    callee_bodies: callee_bodies_ref,
                    inline_cache: inline_cache_ref,
                    context_depth: 0,
                    callback_bindings: None,
                    points_to: Some(&opt.points_to),
                };
                let events =
                    ssa_transfer::run_ssa_taint(&ssa_body, cfg, &ssa_transfer);
                ssa_transfer::ssa_events_to_findings(&events, &ssa_body, cfg)
            }
            Err(e) => {
                tracing::warn!("SSA lowering failed: {e}");
                Vec::new()
            }
        }
    };

    // 3. Deduplicate findings by (sink, source), prefer path_validated=true
    findings.sort_by_key(|f| (f.sink.index(), f.source.index(), !f.path_validated));
    findings.dedup_by_key(|f| (f.sink, f.source));

    findings
}

/// Collect SymbolIds of variables defined or used at top-level scope.
/// These are the "global" variables eligible to flow between functions.
fn collect_toplevel_symbols(cfg: &Cfg, interner: &SymbolInterner) -> HashSet<SymbolId> {
    let mut ids = HashSet::new();
    for (_idx, info) in cfg.node_references() {
        if info.enclosing_func.is_none() {
            if let Some(ref d) = info.defines {
                if let Some(sym) = interner.get(d) {
                    ids.insert(sym);
                }
            }
            for u in &info.uses {
                if let Some(sym) = interner.get(u) {
                    ids.insert(sym);
                }
            }
        }
    }
    ids
}

/// Find function entry nodes: (func_name, entry_node) pairs.
///
/// A function entry is the first node with a given `enclosing_func` value.
fn find_function_entries(cfg: &Cfg) -> Vec<(String, NodeIndex)> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for (idx, info) in cfg.node_references() {
        if let Some(ref func_name) = info.enclosing_func
            && seen.insert(func_name.clone())
        {
            entries.push((func_name.clone(), idx));
        }
    }

    entries
}

/// Extract precise SSA function summaries for all functions in a file.
///
/// Lowers each function to SSA individually and runs per-parameter probing
/// to produce an `SsaFuncSummary`. The resulting map is keyed by function name.
pub(crate) fn extract_intra_file_ssa_summaries(
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary> {
    let func_entries = find_function_entries(cfg);
    let mut summaries = std::collections::HashMap::new();

    for (func_name, func_entry) in &func_entries {
        let func_ssa = match crate::ssa::lower_to_ssa(cfg, *func_entry, Some(func_name), false) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };

        // Count params from SSA body
        let param_count = func_ssa.blocks.iter()
            .flat_map(|b| b.phis.iter().chain(b.body.iter()))
            .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
            .count();

        if param_count == 0 {
            continue; // No params → no per-parameter summary needed
        }

        let summary = ssa_transfer::extract_ssa_func_summary(
            &func_ssa, cfg, local_summaries, global_summaries,
            lang, namespace, interner, param_count,
        );

        // Only store if the summary has observable effects
        if !summary.param_to_return.is_empty()
            || !summary.param_to_sink.is_empty()
            || !summary.source_caps.is_empty()
        {
            summaries.insert(func_name.clone(), summary);
        }
    }

    if !summaries.is_empty() {
        tracing::debug!(
            count = summaries.len(),
            "SSA summary extraction: produced intra-file summaries"
        );
    }

    summaries
}

/// Lower all intra-file functions to SSA, producing both summaries and cached
/// SSA bodies for context-sensitive inline analysis.
///
/// Reuses the lowered bodies for both summary extraction and later inline
/// analysis, avoiding redundant lowering.
fn lower_all_functions(
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> (
    std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>,
    std::collections::HashMap<String, ssa_transfer::CalleeSsaBody>,
) {
    let func_entries = find_function_entries(cfg);
    let mut summaries = std::collections::HashMap::new();
    let mut bodies = std::collections::HashMap::new();

    for (func_name, func_entry) in &func_entries {
        let mut func_ssa = match crate::ssa::lower_to_ssa(cfg, *func_entry, Some(func_name), false) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };

        // Count params from SSA body (before optimization, which may remove some)
        let param_count = func_ssa.blocks.iter()
            .flat_map(|b| b.phis.iter().chain(b.body.iter()))
            .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
            .count();

        // Extract summary from unoptimized SSA (matches original behavior)
        if param_count > 0 {
            let summary = ssa_transfer::extract_ssa_func_summary(
                &func_ssa, cfg, local_summaries, global_summaries,
                lang, namespace, interner, param_count,
            );

            if !summary.param_to_return.is_empty()
                || !summary.param_to_sink.is_empty()
                || !summary.source_caps.is_empty()
            {
                summaries.insert(func_name.clone(), summary);
            }
        }

        // Optimize for inline analysis (after summary extraction)
        let opt = crate::ssa::optimize_ssa(&mut func_ssa, cfg, Some(lang));

        // Cache the optimized body for inline analysis
        bodies.insert(func_name.clone(), ssa_transfer::CalleeSsaBody {
            ssa: func_ssa,
            opt,
            param_count,
        });
    }

    if !summaries.is_empty() {
        tracing::debug!(
            count = summaries.len(),
            bodies = bodies.len(),
            "lower_all_functions: produced summaries + cached bodies"
        );
    }

    (summaries, bodies)
}

/// JS/TS two-level SSA solve: top-level scope + per-function, with global seed.
///
/// Level 1: Solve top-level code (scope=None, nop for function bodies).
/// Level 2: For each function, solve seeded with top-level taint. After all
/// functions, join their exit states (filtered to globals) back into the seed.
/// If the seed changed, re-run. Cap at 3 rounds.
fn analyse_ssa_js_two_level(
    cfg: &Cfg,
    entry: NodeIndex,
    interner: &SymbolInterner,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    interop_edges: &[InteropEdge],
    ssa_summaries: Option<&std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>>,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    callee_bodies: Option<&std::collections::HashMap<String, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
) -> Result<Vec<Finding>, crate::ssa::ir::SsaError> {
    const MAX_ITERATIONS: usize = 3;

    // Level 1: top-level SSA (scope=None, nop for function bodies)
    let mut toplevel_ssa = crate::ssa::lower_to_ssa_scoped_nop(cfg, entry, None)?;
    let toplevel_opt = crate::ssa::optimize_ssa(&mut toplevel_ssa, cfg, Some(lang));
    tracing::debug!(
        blocks = toplevel_ssa.blocks.len(),
        values = toplevel_ssa.num_values(),
        branches_pruned = toplevel_opt.branches_pruned,
        "SSA JS two-level: top-level lowering + optimization"
    );
    let toplevel_transfer = ssa_transfer::SsaTaintTransfer {
        lang,
        namespace,
        interner,
        local_summaries,
        global_summaries,
        interop_edges,
        global_seed: None,
        const_values: Some(&toplevel_opt.const_values),
        type_facts: Some(&toplevel_opt.type_facts),
        ssa_summaries,
        extra_labels,
        base_aliases: Some(&toplevel_opt.alias_result),
        callee_bodies,
        inline_cache,
        context_depth: 0,
        callback_bindings: None,
        points_to: Some(&toplevel_opt.points_to),
    };
    let (toplevel_events, toplevel_block_states) =
        ssa_transfer::run_ssa_taint_full(&toplevel_ssa, cfg, &toplevel_transfer);
    let toplevel_seed =
        ssa_transfer::extract_ssa_exit_state(&toplevel_block_states, &toplevel_ssa, cfg, &toplevel_transfer, interner);
    tracing::debug!(
        events = toplevel_events.len(),
        seed_entries = toplevel_seed.len(),
        "SSA JS two-level: top-level result"
    );

    // Collect top-level findings
    let mut all_findings = ssa_transfer::ssa_events_to_findings(&toplevel_events, &toplevel_ssa, cfg);

    let func_entries = find_function_entries(cfg);
    let toplevel_syms = collect_toplevel_symbols(cfg, interner);

    // Iterative Level 2: per-function solve until seed stabilises
    let mut current_seed = toplevel_seed.clone();

    for _round in 0..MAX_ITERATIONS {
        let mut round_findings: Vec<Finding> = Vec::new();
        let mut combined_exit = toplevel_seed.clone();

        for (func_name, func_entry) in &func_entries {
            let mut func_ssa = match crate::ssa::lower_to_ssa(cfg, *func_entry, Some(func_name), false) {
                Ok(ssa) => ssa,
                Err(_) => continue, // empty function → skip
            };
            let func_opt = crate::ssa::optimize_ssa(&mut func_ssa, cfg, Some(lang));
            let func_transfer = ssa_transfer::SsaTaintTransfer {
                lang,
                namespace,
                interner,
                local_summaries,
                global_summaries,
                interop_edges,
                global_seed: Some(&current_seed),
                const_values: Some(&func_opt.const_values),
                type_facts: Some(&func_opt.type_facts),
                ssa_summaries,
                extra_labels,
                base_aliases: Some(&func_opt.alias_result),
                callee_bodies,
                inline_cache,
                context_depth: 0,
                callback_bindings: None,
                points_to: Some(&func_opt.points_to),
            };
            let (func_events, func_block_states) =
                ssa_transfer::run_ssa_taint_full(&func_ssa, cfg, &func_transfer);
            round_findings.extend(
                ssa_transfer::ssa_events_to_findings(&func_events, &func_ssa, cfg),
            );

            // Extract exit state, filter to globals, join into combined
            let func_exit =
                ssa_transfer::extract_ssa_exit_state(&func_block_states, &func_ssa, cfg, &func_transfer, interner);
            let filtered = ssa_transfer::filter_seed_to_toplevel(&func_exit, &toplevel_syms);
            combined_exit = ssa_transfer::join_seed_maps(&combined_exit, &filtered);
        }

        all_findings.extend(round_findings);

        // Converged: seed didn't change
        if combined_exit == current_seed {
            break;
        }
        current_seed = combined_exit;
    }

    // Dedup findings
    all_findings.sort_by_key(|f| (f.sink.index(), f.source.index(), !f.path_validated));
    all_findings.dedup_by_key(|f| (f.sink, f.source));

    Ok(all_findings)
}

#[cfg(test)]
mod tests;
