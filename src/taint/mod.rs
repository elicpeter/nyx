#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

pub mod domain;
pub mod path_state;
pub mod ssa_transfer;

use crate::cfg::{BodyCfg, BodyId, Cfg, FileCfg, FuncSummaries};
use crate::interop::InteropEdge;
use crate::labels::SourceKind;
use crate::state::engine::MAX_TRACKED_VARS;
use crate::state::symbol::SymbolInterner;
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use std::collections::{HashMap, HashSet, VecDeque};

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
    /// Identifies which body's graph the NodeIndex values reference.
    pub body_id: BodyId,
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
    /// Symbolic constraint analysis verdict, if attempted.
    pub symbolic: Option<crate::evidence::SymbolicVerdict>,
    /// Original source byte span, preserved when origin was remapped across
    /// body boundaries.  `None` for intra-body findings (use `cfg[source].ast.span`).
    pub source_span: Option<usize>,
}

/// Pre-compute module aliases from an unoptimized SSA body for JS/TS.
///
/// Runs const propagation (read-only) to get constant values, then detects
/// `require()` calls to known modules and propagates through phis/copies.
/// Used to make module aliases available during summary extraction.
fn compute_module_aliases_for_summary(
    ssa: &crate::ssa::SsaBody,
    lang: Lang,
) -> std::collections::HashMap<crate::ssa::SsaValue, smallvec::SmallVec<[String; 2]>> {
    if !matches!(lang, Lang::JavaScript | Lang::TypeScript) {
        return std::collections::HashMap::new();
    }
    let cp = crate::ssa::const_prop::const_propagate(ssa);
    crate::ssa::const_prop::collect_module_aliases(ssa, &cp.values)
}

/// Run taint analysis on all bodies in a file.
///
/// Uses a unified multi-body analysis for all languages:
/// 1. Lexical containment propagation: parent body exit state seeds child bodies.
/// 2. JS/TS iterative convergence: functions that modify globals can feed taint
///    back to other functions (up to `MAX_JS_ITERATIONS` rounds).
pub fn analyse_file(
    file_cfg: &FileCfg,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Vec<Finding> {
    let _span = tracing::debug_span!("taint_analyse_file").entered();

    // 1. Lower all function bodies: produce SSA summaries + cached bodies.
    let (ssa_summaries, callee_bodies) = lower_all_functions_from_bodies(
        file_cfg,
        caller_lang,
        caller_namespace,
        local_summaries,
        global_summaries,
    );
    let ssa_sums_ref = if ssa_summaries.is_empty() {
        None
    } else {
        Some(&ssa_summaries)
    };

    // 2. Context-sensitive inline analysis setup
    let context_sensitive = std::env::var("NYX_CONTEXT_SENSITIVE")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);
    let inline_cache = std::cell::RefCell::new(std::collections::HashMap::new());
    let callee_bodies_ref = if context_sensitive && !callee_bodies.is_empty() {
        Some(&callee_bodies)
    } else {
        None
    };
    let inline_cache_ref = if context_sensitive {
        Some(&inline_cache)
    } else {
        None
    };

    // 3. Unified multi-body analysis with lexical containment propagation.
    let max_iterations = if matches!(caller_lang, Lang::JavaScript | Lang::TypeScript) {
        3
    } else {
        1
    };
    let import_bindings_ref = if file_cfg.import_bindings.is_empty() {
        None
    } else {
        Some(&file_cfg.import_bindings)
    };
    let mut all_findings = analyse_multi_body(
        file_cfg,
        caller_lang,
        caller_namespace,
        local_summaries,
        global_summaries,
        interop_edges,
        extra_labels,
        ssa_sums_ref,
        callee_bodies_ref,
        inline_cache_ref,
        max_iterations,
        import_bindings_ref,
    );

    // 4. Deduplicate findings by (body_id, sink, source), prefer path_validated=true
    all_findings.sort_by_key(|f| {
        (
            f.body_id.0,
            f.sink.index(),
            f.source.index(),
            !f.path_validated,
        )
    });
    all_findings.dedup_by_key(|f| (f.body_id, f.sink, f.source));

    all_findings
}

/// Compute containment-topological order: parent bodies before children.
///
/// Uses BFS from roots (bodies with no parent), ensuring a body is always
/// processed after its parent — required for lexical seed propagation.
/// Returns indices into `file_cfg.bodies` in processing order.
fn containment_order(bodies: &[BodyCfg]) -> Vec<usize> {
    let mut children: HashMap<BodyId, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        match body.meta.parent_body_id {
            Some(parent) => children.entry(parent).or_default().push(i),
            None => roots.push(i),
        }
    }
    let mut order = Vec::with_capacity(bodies.len());
    let mut queue: VecDeque<usize> = roots.into();
    while let Some(idx) = queue.pop_front() {
        order.push(idx);
        if let Some(kids) = children.get(&bodies[idx].meta.id) {
            queue.extend(kids);
        }
    }
    order
}

/// Analyse a single body with an optional parent seed.
///
/// Shared logic extracted from `analyse_multi_body` to avoid deep nesting.
fn analyse_body_with_seed(
    body: &BodyCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa_summaries: Option<
        &std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    callee_bodies: Option<&std::collections::HashMap<String, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
    seed: Option<&HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>>,
    import_bindings: Option<&crate::cfg::ImportBindings>,
) -> (
    Vec<Finding>,
    Option<HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>>,
) {
    let cfg = &body.graph;
    let entry = body.entry;
    let body_id = body.meta.id;

    let interner = SymbolInterner::from_cfg(cfg);
    if interner.len() > MAX_TRACKED_VARS {
        tracing::warn!(
            symbols = interner.len(),
            max = MAX_TRACKED_VARS,
            "taint analysis: too many variables, some will be ignored"
        );
    }

    // Per-body graphs contain only the body's own nodes.
    // For non-toplevel bodies, use lower_to_ssa_with_params with scope to
    // create SsaOp::Param ops for external/captured variables and formal
    // parameters — required for global_seed to inject taint from the parent.
    // Top-level bodies use lower_to_ssa with scope_all=true (no Param ops).
    let is_toplevel = body.meta.parent_body_id.is_none();
    // JS/TS function bodies always use scoped lowering to create Param ops
    // for captured variables (globals that flow via seed between bodies).
    // Other languages: scoped lowering only when the parent seed is non-empty,
    // i.e. the parent body actually has taint to propagate.  Without a seed,
    // Param ops would just introduce unused SSA values.
    let has_nonempty_seed = seed.map_or(false, |s| !s.is_empty());
    let use_scoped_lowering =
        !is_toplevel && (matches!(lang, Lang::JavaScript | Lang::TypeScript) || has_nonempty_seed);
    let ssa_result = if use_scoped_lowering {
        let func_name = body
            .meta
            .name
            .clone()
            .unwrap_or_else(|| format!("<anon@{}>", body.meta.span.0));
        crate::ssa::lower_to_ssa_with_params(cfg, entry, Some(&func_name), false, &body.meta.params)
    } else {
        crate::ssa::lower_to_ssa(cfg, entry, None, true)
    };

    match ssa_result {
        Ok(mut ssa_body) => {
            let opt = crate::ssa::optimize_ssa(&mut ssa_body, cfg, Some(lang));
            let dynamic_pts = std::cell::RefCell::new(std::collections::HashMap::new());
            let transfer = ssa_transfer::SsaTaintTransfer {
                lang,
                namespace,
                interner: &interner,
                local_summaries,
                global_summaries,
                interop_edges,
                global_seed: seed,
                const_values: Some(&opt.const_values),
                type_facts: Some(&opt.type_facts),
                ssa_summaries,
                extra_labels,
                base_aliases: Some(&opt.alias_result),
                callee_bodies,
                inline_cache,
                context_depth: 0,
                callback_bindings: None,
                points_to: Some(&opt.points_to),
                dynamic_pts: Some(&dynamic_pts),
                import_bindings,
                module_aliases: if opt.module_aliases.is_empty() {
                    None
                } else {
                    Some(&opt.module_aliases)
                },
            };
            let (events, block_states) =
                ssa_transfer::run_ssa_taint_full(&ssa_body, cfg, &transfer);
            let mut findings = ssa_transfer::ssa_events_to_findings(&events, &ssa_body, cfg);
            for f in &mut findings {
                f.body_id = body_id;
            }
            if crate::symex::is_enabled() {
                let symex_ctx = crate::symex::SymexContext {
                    ssa: &ssa_body,
                    cfg,
                    const_values: &opt.const_values,
                    type_facts: &opt.type_facts,
                    global_summaries,
                    lang,
                    namespace,
                    points_to: Some(&opt.points_to),
                    callee_bodies,
                    scc_membership: None,
                    cross_file_bodies: global_summaries,
                };
                crate::symex::annotate_findings(&mut findings, &symex_ctx);
            }
            // Extract exit state for seeding child bodies.
            let exit_state =
                ssa_transfer::extract_ssa_exit_state(&block_states, &ssa_body, cfg, &transfer);
            (findings, Some(exit_state))
        }
        Err(_) => (Vec::new(), None),
    }
}

/// Unified multi-body taint analysis with lexical containment propagation.
///
/// Pass 1: process all bodies in containment-topological order (parent before
/// child), seeding each child body with its parent's exit state.
///
/// Pass 2 (JS/TS only, `max_iterations > 1`): iterative convergence for
/// functions that modify global state, feeding taint back to other functions.
fn analyse_multi_body(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa_summaries: Option<
        &std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    callee_bodies: Option<&std::collections::HashMap<String, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
    max_iterations: usize,
    import_bindings: Option<&crate::cfg::ImportBindings>,
) -> Vec<Finding> {
    let order = containment_order(&file_cfg.bodies);
    let mut all_findings: Vec<Finding> = Vec::new();

    // Exit states per body, used to seed children.
    let mut body_exit_states: HashMap<
        BodyId,
        HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>,
    > = HashMap::new();

    // ── Pass 1: lexical containment propagation ──────────────────────
    for &idx in &order {
        let body = &file_cfg.bodies[idx];
        // Determine seed from parent body's exit state.
        let parent_seed = body
            .meta
            .parent_body_id
            .and_then(|pid| body_exit_states.get(&pid));

        let (findings, exit_state) = analyse_body_with_seed(
            body,
            lang,
            namespace,
            local_summaries,
            global_summaries,
            interop_edges,
            extra_labels,
            ssa_summaries,
            callee_bodies,
            inline_cache,
            parent_seed,
            import_bindings,
        );
        tracing::debug!(
            body_id = body.meta.id.0,
            body_name = ?body.meta.name,
            findings = findings.len(),
            graph_nodes = body.graph.node_count(),
            has_seed = parent_seed.is_some(),
            "analyse_multi_body: body analysed"
        );
        all_findings.extend(findings);
        if let Some(es) = exit_state {
            body_exit_states.insert(body.meta.id, es);
        }
    }

    // ── Pass 2: JS/TS iterative convergence ──────────────────────────
    // Only for JS/TS: functions that modify global variables can feed taint
    // back to other functions.  Iterate until the top-level seed stabilises.
    if max_iterations > 1 {
        let top = file_cfg.toplevel();
        let top_cfg = &top.graph;

        // Collect top-level binding keys for seed filtering.
        let toplevel_keys: HashSet<ssa_transfer::BindingKey> = {
            let mut keys = HashSet::new();
            for (_idx, info) in top_cfg.node_references() {
                if let Some(ref d) = info.taint.defines {
                    keys.insert(ssa_transfer::BindingKey::new(d.as_str()));
                }
                for u in &info.taint.uses {
                    keys.insert(ssa_transfer::BindingKey::new(u.as_str()));
                }
            }
            keys
        };

        // Initial seed is the top-level exit state.
        let mut current_seed = body_exit_states
            .get(&BodyId(0))
            .cloned()
            .unwrap_or_default();

        for _round in 0..max_iterations.saturating_sub(1) {
            // Combine function body exits filtered to top-level scope.
            let mut combined_exit = current_seed.clone();
            for &idx in &order {
                let body = &file_cfg.bodies[idx];
                if body.meta.parent_body_id.is_none() {
                    continue; // skip top-level itself
                }
                if let Some(es) = body_exit_states.get(&body.meta.id) {
                    let filtered = ssa_transfer::filter_seed_to_toplevel(es, &toplevel_keys);
                    combined_exit = ssa_transfer::join_seed_maps(&combined_exit, &filtered);
                }
            }

            // Converged: seed didn't change.
            if combined_exit == current_seed {
                break;
            }
            current_seed = combined_exit;

            // Re-run non-toplevel bodies with updated seed.
            // Replace non-toplevel findings (the new round has more complete
            // taint context and symex annotations).
            body_exit_states.insert(BodyId(0), current_seed.clone());
            // Remove stale non-toplevel findings from previous rounds.
            all_findings.retain(|f| {
                file_cfg
                    .bodies
                    .get(f.body_id.0 as usize)
                    .map_or(true, |b| b.meta.parent_body_id.is_none())
            });
            for &idx in &order {
                let body = &file_cfg.bodies[idx];
                if body.meta.parent_body_id.is_none() {
                    continue; // don't re-run top-level
                }
                let parent_seed = body
                    .meta
                    .parent_body_id
                    .and_then(|pid| body_exit_states.get(&pid));

                let (findings, exit_state) = analyse_body_with_seed(
                    body,
                    lang,
                    namespace,
                    local_summaries,
                    global_summaries,
                    interop_edges,
                    extra_labels,
                    ssa_summaries,
                    callee_bodies,
                    inline_cache,
                    parent_seed,
                    import_bindings,
                );
                all_findings.extend(findings);
                if let Some(es) = exit_state {
                    body_exit_states.insert(body.meta.id, es);
                }
            }
        }
    }

    all_findings
}

/// Find function entry nodes: (func_name, entry_node) pairs.
///
/// A function entry is the first node with a given `enclosing_func` value.
fn find_function_entries(cfg: &Cfg) -> Vec<(String, NodeIndex)> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for (idx, info) in cfg.node_references() {
        if let Some(ref func_name) = info.ast.enclosing_func
            && seen.insert(func_name.clone())
        {
            entries.push((func_name.clone(), idx));
        }
    }

    entries
}

/// Look up formal parameter names (in declaration order) for a function from
/// the CFG-level local summaries. Returns empty vec if not found.
fn lookup_formal_params(local_summaries: &FuncSummaries, func_name: &str) -> Vec<String> {
    local_summaries
        .iter()
        .find(|(k, _)| k.name == func_name)
        .map(|(_, s)| s.param_names.clone())
        .unwrap_or_default()
}

/// Extract precise SSA function summaries for all functions in a file.
///
/// Lowers each function to SSA individually and runs per-parameter probing
/// to produce an `SsaFuncSummary`. The resulting map is keyed by function name.
#[allow(dead_code)] // Used by tests; production code uses extract_ssa_artifacts
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
        let formal_params = lookup_formal_params(local_summaries, func_name);
        let func_ssa = match crate::ssa::lower_to_ssa_with_params(
            cfg,
            *func_entry,
            Some(func_name),
            false,
            &formal_params,
        ) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };

        // Param count = number of formal params (from CFG), falling back to
        // counting all SsaOp::Param ops when no local summary is available.
        let param_count = if !formal_params.is_empty() {
            formal_params.len()
        } else {
            func_ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count()
        };

        if param_count == 0 {
            continue; // No params → no per-parameter summary needed
        }

        // Pre-compute module aliases for JS/TS (read-only const prop pass)
        let mod_aliases = compute_module_aliases_for_summary(&func_ssa, lang);
        let mod_aliases_ref = if mod_aliases.is_empty() {
            None
        } else {
            Some(&mod_aliases)
        };

        let summary = ssa_transfer::extract_ssa_func_summary(
            &func_ssa,
            cfg,
            local_summaries,
            global_summaries,
            lang,
            namespace,
            interner,
            param_count,
            mod_aliases_ref,
        );

        // Only store if the summary has observable effects
        if !summary.param_to_return.is_empty()
            || !summary.param_to_sink.is_empty()
            || !summary.source_caps.is_empty()
            || !summary.param_container_to_return.is_empty()
            || !summary.param_to_container_store.is_empty()
            || summary.return_abstract.is_some()
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
        let formal_params = lookup_formal_params(local_summaries, func_name);
        let mut func_ssa = match crate::ssa::lower_to_ssa_with_params(
            cfg,
            *func_entry,
            Some(func_name),
            false,
            &formal_params,
        ) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };

        // Param count = number of formal params (from CFG), falling back to
        // counting all SsaOp::Param ops when no local summary is available.
        let param_count = if !formal_params.is_empty() {
            formal_params.len()
        } else {
            func_ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count()
        };

        // Extract summary from unoptimized SSA (matches original behavior)
        if param_count > 0 {
            let mod_aliases = compute_module_aliases_for_summary(&func_ssa, lang);
            let mod_aliases_ref = if mod_aliases.is_empty() {
                None
            } else {
                Some(&mod_aliases)
            };
            let summary = ssa_transfer::extract_ssa_func_summary(
                &func_ssa,
                cfg,
                local_summaries,
                global_summaries,
                lang,
                namespace,
                interner,
                param_count,
                mod_aliases_ref,
            );

            if !summary.param_to_return.is_empty()
                || !summary.param_to_sink.is_empty()
                || !summary.source_caps.is_empty()
                || !summary.param_container_to_return.is_empty()
                || !summary.param_to_container_store.is_empty()
                || summary.return_abstract.is_some()
            {
                summaries.insert(func_name.clone(), summary);
            }
        }

        // Optimize for inline analysis (after summary extraction)
        let opt = crate::ssa::optimize_ssa(&mut func_ssa, cfg, Some(lang));

        // Cache the optimized body for inline analysis
        bodies.insert(
            func_name.clone(),
            ssa_transfer::CalleeSsaBody {
                ssa: func_ssa,
                opt,
                param_count,
                node_meta: std::collections::HashMap::new(),
                body_graph: None,
            },
        );
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

/// Lower all function bodies from `FileCfg` to produce SSA summaries + cached
/// bodies.  Each body's own graph is used directly — no scope filtering needed.
fn lower_all_functions_from_bodies(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> (
    std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>,
    std::collections::HashMap<String, ssa_transfer::CalleeSsaBody>,
) {
    let mut summaries = std::collections::HashMap::new();
    let mut bodies = std::collections::HashMap::new();

    for body in file_cfg.function_bodies() {
        let func_name = body
            .meta
            .name
            .clone()
            .unwrap_or_else(|| format!("<anon@{}>", body.meta.span.0));

        let interner = SymbolInterner::from_cfg(&body.graph);
        let formal_params = &body.meta.params;
        let mut func_ssa = match crate::ssa::lower_to_ssa_with_params(
            &body.graph,
            body.entry,
            Some(&func_name),
            false,
            formal_params,
        ) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };

        let param_count = if !formal_params.is_empty() {
            formal_params.len()
        } else {
            func_ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count()
        };

        if param_count > 0 {
            let mod_aliases = compute_module_aliases_for_summary(&func_ssa, lang);
            let mod_aliases_ref = if mod_aliases.is_empty() {
                None
            } else {
                Some(&mod_aliases)
            };
            let summary = ssa_transfer::extract_ssa_func_summary(
                &func_ssa,
                &body.graph,
                local_summaries,
                global_summaries,
                lang,
                namespace,
                &interner,
                param_count,
                mod_aliases_ref,
            );

            // Always insert the summary, even when all fields are empty/default.
            // An empty summary tells resolve_callee "this function exists and has
            // no taint effects" — preventing fallthrough to the less precise old
            // FuncSummary which may report false source_caps from internal sources.
            summaries.insert(func_name.clone(), summary);
        }

        let opt = crate::ssa::optimize_ssa(&mut func_ssa, &body.graph, Some(lang));

        bodies.insert(
            func_name,
            ssa_transfer::CalleeSsaBody {
                ssa: func_ssa,
                opt,
                param_count,
                node_meta: std::collections::HashMap::new(),
                body_graph: Some(body.graph.clone()),
            },
        );
    }

    if !summaries.is_empty() {
        tracing::debug!(
            count = summaries.len(),
            bodies = bodies.len(),
            "lower_all_functions_from_bodies: produced summaries + cached bodies"
        );
    }

    (summaries, bodies)
}

/// Maximum blocks for a callee body to be eligible for cross-file persistence.
const MAX_CROSS_FILE_BODY_BLOCKS: usize = 100;

/// Extract both SSA summaries and eligible callee bodies from a file in a single
/// lowering pass. Called from `ParsedFile::extract_ssa_summaries()` when
/// cross-file symex is enabled.
///
/// Returns: (ssa_summaries, ssa_bodies) where bodies are size-gated and have
/// `node_meta` populated for cross-file use.
pub(crate) fn extract_ssa_artifacts(
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> (
    std::collections::HashMap<String, crate::summary::ssa_summary::SsaFuncSummary>,
    Vec<(String, usize, ssa_transfer::CalleeSsaBody)>,
) {
    let (summaries, bodies) = lower_all_functions(
        cfg,
        interner,
        lang,
        namespace,
        local_summaries,
        global_summaries,
    );

    let mut eligible_bodies = Vec::new();
    if crate::symex::cross_file_symex_enabled() {
        for (name, mut body) in bodies {
            // Size gate
            if body.ssa.blocks.len() > MAX_CROSS_FILE_BODY_BLOCKS {
                continue;
            }
            // Populate node metadata for cross-file use
            if !ssa_transfer::populate_node_meta(&mut body, cfg) {
                continue; // Failed to resolve all nodes — skip
            }
            let param_count = body.param_count;
            eligible_bodies.push((name, param_count, body));
        }
    }

    (summaries, eligible_bodies)
}

#[cfg(test)]
mod tests;
