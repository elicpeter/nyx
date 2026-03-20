pub mod domain;
pub mod path_state;
pub mod transfer;

use crate::cfg::{Cfg, FuncSummaries};
use crate::interop::InteropEdge;
use crate::labels::SourceKind;
use crate::state::engine::{self, MAX_TRACKED_VARS};
use crate::state::lattice::Lattice;
use crate::state::symbol::{SymbolId, SymbolInterner};
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use domain::{SmallBitSet, TaintState};
use path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use std::collections::HashSet;
use transfer::{TaintEvent, TaintTransfer};

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
/// Uses a monotone forward dataflow analysis via `state::engine::run_forward`
/// with the `TaintTransfer` function. Termination is guaranteed by lattice
/// finiteness (bounded `Cap` bits × bounded variable count).
///
/// For JS/TS files: uses a two-level solve to prevent cross-function taint
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

    // 2. Build base transfer function
    let base_transfer = TaintTransfer {
        lang: caller_lang,
        namespace: caller_namespace,
        interner: &interner, // also used for events_to_findings below
        local_summaries,
        global_summaries,
        interop_edges,
        global_seed: None,
        scope_filter: None,
    };

    // 3. Run analysis (two-level for JS/TS, single-pass otherwise)
    let events = if matches!(caller_lang, Lang::JavaScript | Lang::TypeScript) {
        analyse_js_two_level(cfg, entry, &interner, &base_transfer)
    } else {
        let result = engine::run_forward(cfg, entry, &base_transfer, TaintState::initial());
        result.events
    };

    // 4. Convert events to findings
    let mut findings = events_to_findings(&events, &interner);

    // 5. Deduplicate findings by (sink, source), prefer path_validated=true
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

/// Filter a TaintState to only include variables in the top-level symbol set.
/// Prevents function-local variable taint from leaking into the global seed.
fn filter_to_toplevel(state: &TaintState, toplevel_syms: &HashSet<SymbolId>) -> TaintState {
    let mut mask = SmallBitSet::empty();
    for &sym in toplevel_syms {
        mask.insert(sym);
    }

    TaintState {
        vars: state
            .vars
            .iter()
            .filter(|(sym, _)| toplevel_syms.contains(sym))
            .cloned()
            .collect(),
        validated_must: state.validated_must.intersection(mask),
        validated_may: state.validated_may.intersection(mask),
        predicates: state
            .predicates
            .iter()
            .filter(|(sym, _)| toplevel_syms.contains(sym))
            .cloned()
            .collect(),
    }
}

/// JS/TS two-level solve to prevent cross-function taint leakage.
///
/// Level 1: Solve top-level code (nodes where `enclosing_func.is_none()`).
/// Level 2: For each function, solve seeded with top-level taint. After all
/// functions, join their exit states (filtered to globals) back into the seed.
/// If the seed changed, re-run. Cap at 3 rounds.
fn analyse_js_two_level(
    cfg: &Cfg,
    entry: NodeIndex,
    _interner: &SymbolInterner,
    base_transfer: &TaintTransfer,
) -> Vec<TaintEvent> {
    const MAX_ITERATIONS: usize = 3;

    // Level 1: solve top-level only
    let toplevel_transfer = TaintTransfer {
        lang: base_transfer.lang,
        namespace: base_transfer.namespace,
        interner: base_transfer.interner,
        local_summaries: base_transfer.local_summaries,
        global_summaries: base_transfer.global_summaries,
        interop_edges: base_transfer.interop_edges,
        global_seed: None,
        scope_filter: Some(None), // top-level only (enclosing_func == None)
    };

    let toplevel_result =
        engine::run_forward(cfg, entry, &toplevel_transfer, TaintState::initial());
    let toplevel_state = extract_exit_state(&toplevel_result.states);

    // Top-level events emitted once
    let mut all_events = toplevel_result.events;

    let func_entries = find_function_entries(cfg);

    // Compute which variables are top-level (globally visible)
    let toplevel_syms = collect_toplevel_symbols(cfg, base_transfer.interner);

    // Iterative Level 2: re-run functions until seed stabilises
    let mut current_seed = toplevel_state.clone();

    for _round in 0..MAX_ITERATIONS {
        let mut round_events: Vec<TaintEvent> = Vec::new();
        let mut combined_exit = toplevel_state.clone();

        for (func_name, func_entry) in &func_entries {
            let func_transfer = TaintTransfer {
                lang: base_transfer.lang,
                namespace: base_transfer.namespace,
                interner: base_transfer.interner,
                local_summaries: base_transfer.local_summaries,
                global_summaries: base_transfer.global_summaries,
                interop_edges: base_transfer.interop_edges,
                global_seed: Some(&current_seed),
                scope_filter: Some(Some(func_name.as_str())),
            };

            let func_result =
                engine::run_forward(cfg, *func_entry, &func_transfer, TaintState::initial());
            round_events.extend(func_result.events);

            // Filter exit state to global variables only, then join into combined
            let func_exit = extract_exit_state(&func_result.states);
            let filtered = filter_to_toplevel(&func_exit, &toplevel_syms);
            combined_exit = combined_exit.join(&filtered);
        }

        // Accumulate events from every round (state monotonicity does not
        // guarantee event monotonicity — earlier rounds may emit events
        // that later rounds miss due to e.g. contradiction pruning)
        all_events.extend(round_events);

        // Converged: seed didn't change
        if combined_exit == current_seed {
            break;
        }
        current_seed = combined_exit;
    }

    all_events
}

/// Extract the "best" taint state from converged states (join all exit/reachable states).
fn extract_exit_state(states: &std::collections::HashMap<NodeIndex, TaintState>) -> TaintState {
    let mut result = TaintState::initial();
    for state in states.values() {
        result = result.join(state);
    }
    result
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

/// Convert TaintEvents into Findings.
fn events_to_findings(events: &[TaintEvent], _interner: &SymbolInterner) -> Vec<Finding> {
    let mut findings = Vec::new();

    for event in events {
        let TaintEvent::SinkReached {
            sink_node,
            tainted_vars,
            all_validated,
            guard_kind,
            ..
        } = event;

        // Collect unique origins across all tainted vars at this sink
        let mut seen_origins: HashSet<(usize, usize)> = HashSet::new();
        for (_sym, _caps, origins) in tainted_vars {
            for origin in origins {
                if seen_origins.insert((origin.node.index(), sink_node.index())) {
                    findings.push(Finding {
                        sink: *sink_node,
                        source: origin.node,
                        path: vec![origin.node, *sink_node],
                        source_kind: origin.source_kind,
                        path_validated: *all_validated,
                        guard_kind: *guard_kind,
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests;
