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
    #[allow(dead_code)] // surfaced in Diag output (task 4)
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    #[allow(dead_code)] // surfaced in Diag output (task 4)
    pub guard_kind: Option<PredicateKind>,
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

    // 2. Run SSA analysis (two-level for JS/TS, single-pass for others)
    let mut findings = if matches!(caller_lang, Lang::JavaScript | Lang::TypeScript) {
        match analyse_ssa_js_two_level(
            cfg, entry, &interner, caller_lang, caller_namespace,
            local_summaries, global_summaries, interop_edges,
        ) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("SSA JS two-level lowering failed: {e}");
                Vec::new()
            }
        }
    } else {
        match crate::ssa::lower_to_ssa(cfg, entry, None, true) {
            Ok(ssa_body) => {
                tracing::debug!(
                    blocks = ssa_body.blocks.len(),
                    values = ssa_body.num_values(),
                    "SSA lowering succeeded"
                );
                let ssa_transfer = ssa_transfer::SsaTaintTransfer {
                    lang: caller_lang,
                    namespace: caller_namespace,
                    interner: &interner,
                    local_summaries,
                    global_summaries,
                    interop_edges,
                    global_seed: None,
                };
                let events =
                    ssa_transfer::run_ssa_taint(&ssa_body, cfg, &ssa_transfer);
                ssa_transfer::ssa_events_to_findings(&events, &ssa_body)
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
) -> Result<Vec<Finding>, crate::ssa::ir::SsaError> {
    const MAX_ITERATIONS: usize = 3;

    // Level 1: top-level SSA (scope=None, nop for function bodies)
    let toplevel_ssa = crate::ssa::lower_to_ssa_scoped_nop(cfg, entry, None)?;
    tracing::debug!(
        blocks = toplevel_ssa.blocks.len(),
        values = toplevel_ssa.num_values(),
        "SSA JS two-level: top-level lowering"
    );
    let toplevel_transfer = ssa_transfer::SsaTaintTransfer {
        lang,
        namespace,
        interner,
        local_summaries,
        global_summaries,
        interop_edges,
        global_seed: None,
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
    let mut all_findings = ssa_transfer::ssa_events_to_findings(&toplevel_events, &toplevel_ssa);

    let func_entries = find_function_entries(cfg);
    let toplevel_syms = collect_toplevel_symbols(cfg, interner);

    // Iterative Level 2: per-function solve until seed stabilises
    let mut current_seed = toplevel_seed.clone();

    for _round in 0..MAX_ITERATIONS {
        let mut round_findings: Vec<Finding> = Vec::new();
        let mut combined_exit = toplevel_seed.clone();

        for (func_name, func_entry) in &func_entries {
            let func_ssa = match crate::ssa::lower_to_ssa(cfg, *func_entry, Some(func_name), false) {
                Ok(ssa) => ssa,
                Err(_) => continue, // empty function → skip
            };
            let func_transfer = ssa_transfer::SsaTaintTransfer {
                lang,
                namespace,
                interner,
                local_summaries,
                global_summaries,
                interop_edges,
                global_seed: Some(&current_seed),
            };
            let (func_events, func_block_states) =
                ssa_transfer::run_ssa_taint_full(&func_ssa, cfg, &func_transfer);
            round_findings.extend(
                ssa_transfer::ssa_events_to_findings(&func_events, &func_ssa),
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
