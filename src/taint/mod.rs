#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

pub mod backwards;
pub mod domain;
pub mod path_state;
pub mod ssa_transfer;

use crate::cfg::{BodyCfg, BodyId, Cfg, FileCfg, FuncSummaries};
use crate::engine_notes::EngineNote;
use crate::interop::InteropEdge;
use crate::labels::SourceKind;
use crate::state::engine::MAX_TRACKED_VARS;
use crate::state::symbol::SymbolInterner;
use crate::summary::GlobalSummaries;
use crate::symbol::{FuncKey, FuncKind, Lang};
use path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Safety cap on JS/TS in-file pass-2 convergence iterations.
///
/// Pass 2 runs a Jacobi-style round over every non-toplevel body in a
/// JS/TS file, combining each body's exit state (filtered to top-level
/// keys) into the shared seed and re-running non-toplevel bodies until
/// the seed stabilises.  A chain of `k` top-level bindings threaded
/// through `k` helper functions needs up to `k` iterations for taint to
/// walk the chain; the old hardcoded `3` silently truncated any
/// 4-stage chain with no warning.
///
/// This mirrors `scan::SCC_FIXPOINT_SAFETY_CAP` in intent: the lattice
/// is monotone and finite-height, so the real fixed-point is always
/// reachable in a small multiple of the chain depth.  64 is generous
/// enough to cover every realistic JS/TS file we have seen while still
/// bounding worst-case cost.
const JS_TS_PASS2_SAFETY_CAP: usize = 64;

/// Test-only override for [`JS_TS_PASS2_SAFETY_CAP`].  When non-zero,
/// the pass-2 loop uses this value instead of the const cap.  Default
/// `0` leaves production behaviour unchanged.
static JS_TS_PASS2_CAP_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Observability hook: records the number of pass-2 iterations used by
/// the most recent [`analyse_file`] invocation.  Reset at the start of
/// each call so convergence regression tests can read a fresh value.
/// `1` means the initial lexical-containment pass completed; higher
/// values indicate the iterative convergence loop ran that many times
/// without detecting convergence (so the `iters`th iteration was the
/// last round actually executed).  `1` is the common case for
/// non-JS/TS languages and for JS/TS files with no cross-body globals.
static LAST_JS_TS_PASS2_ITERATIONS: AtomicUsize = AtomicUsize::new(0);

/// Set (or clear) the test-only JS/TS pass-2 cap override.  `cap = 0`
/// restores the default.  Intended exclusively for integration tests
/// that need to force cap-hit behaviour on small fixtures.
#[doc(hidden)]
pub fn set_js_ts_pass2_cap_override(cap: usize) {
    JS_TS_PASS2_CAP_OVERRIDE.store(cap, Ordering::Relaxed);
}

/// Returns the pass-2 iteration count observed during the most recent
/// [`analyse_file`] invocation.  Intended for tests and diagnostics.
pub fn last_js_ts_pass2_iterations() -> usize {
    LAST_JS_TS_PASS2_ITERATIONS.load(Ordering::Relaxed)
}

fn js_ts_pass2_cap() -> usize {
    let o = JS_TS_PASS2_CAP_OVERRIDE.load(Ordering::Relaxed);
    if o == 0 { JS_TS_PASS2_SAFETY_CAP } else { o }
}

/// A raw flow step at CFG level (before line/col resolution).
#[derive(Debug, Clone)]
pub struct FlowStepRaw {
    pub cfg_node: NodeIndex,
    pub var_name: Option<String>,
    pub op_kind: crate::evidence::FlowStepKind,
}

/// Resolved source-location of the primary (callee-internal) sink instruction.
///
/// Populated on [`Finding`] when the sink was resolved via a callee summary
/// that recorded a [`crate::summary::SinkSite`].  Data-only primary
/// sink-location attribution: downstream formatters (SARIF, JSON, diag)
/// still report the caller's call-site until they opt in.
#[derive(Debug, Clone, PartialEq)]
pub struct SinkLocation {
    /// Callee file path relative to the workspace root.  Matches the
    /// `FuncKey::namespace` convention used in [`crate::summary::SinkSite`].
    pub file_rel: String,
    /// 1-based line of the sink instruction inside the callee body.
    pub line: u32,
    /// 1-based column of the sink instruction inside the callee body.
    pub col: u32,
    /// Trimmed source line at the sink, copied from the upstream
    /// [`crate::summary::SinkSite`].  Empty when the extractor had no
    /// tree/bytes context.  Used by formatters so the primary-location
    /// display does not need to re-read the callee file.
    pub snippet: String,
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
    /// body boundaries.  `None` for intra-body findings
    /// (use `cfg[source].classification_span()`).
    pub source_span: Option<usize>,
    /// Source-location of the callee-internal dangerous instruction when the
    /// sink was resolved via a function summary carrying a
    /// [`crate::summary::SinkSite`] with concrete coordinates for primary
    /// sink-location attribution.  `None` for:
    /// * intra-procedural / label-based sinks — the caller's `cfg[sink]`
    ///   span already names the dangerous instruction;
    /// * summary-resolved sinks whose `SinkSite` was cap-only (no tree or
    ///   bytes context at extraction time).
    ///
    /// # Invariant
    ///
    /// `primary_location.is_some()` ⇒ the inner [`SinkLocation`] has
    /// `line != 0`.  `file_rel` may be empty for single-file scans where
    /// the scan root is the file itself (every namespace normalizes to
    /// `""`); consumers resolve empty `file_rel` against the file under
    /// analysis.  Enforced at `ssa_events_to_findings` by a
    /// `debug_assert!` — upstream filters drop cap-only sites before
    /// they reach this field.
    ///
    /// Deliberately independent of `uses_summary`: that flag tracks whether
    /// the **taint chain** used a callee summary, not whether the **sink**
    /// was summary-resolved.  A local source can reach a cross-file sink,
    /// yielding `uses_summary == false` alongside a populated
    /// `primary_location`.
    pub primary_location: Option<SinkLocation>,
    /// Engine provenance notes recorded during the analysis that produced
    /// this finding.  Populated when an internal budget/cap was hit — see
    /// [`crate::engine_notes::EngineNote`].  Empty for the typical
    /// under-budget finding.
    pub engine_notes: SmallVec<[EngineNote; 2]>,
    /// Stable hash of the intermediate-variable sequence between `source`
    /// and `sink`.  Used to keep distinct paths through different
    /// variables as separate findings during deduplication — two
    /// `(body_id, sink, source)` siblings with different `path_hash`
    /// values represent flows along different data paths and are
    /// preserved as alternatives rather than collapsed.
    ///
    /// Derived from the `cfg_node` indices in `flow_steps` at the time
    /// the finding is emitted; stable for a given scan but not
    /// necessarily stable across AST/CFG changes.
    pub path_hash: u64,
    /// Stable identifier for this finding, derived from
    /// `(body_id, source.index, sink.index, path_hash, path_validated)`.
    /// Populated after `body_id` is set so the ID is consistent across
    /// the lifetime of the finding and can be used to cross-reference
    /// alternative paths via [`Self::alternative_finding_ids`].  Empty
    /// string before the post-analysis linking pass runs.
    pub finding_id: String,
    /// Stable identifiers of sibling findings that share
    /// `(body_id, sink, source)` but differ in `path_validated` or
    /// `path_hash`.  Populated by the dedup pass in
    /// [`analyse_file`] after all findings are collected.
    ///
    /// The canonical case is a guarded/unguarded pair: if an `exec(x)`
    /// call is reachable from the same source `x` through both a
    /// whitelisted branch and an unguarded branch, both findings
    /// survive dedup and each lists the other here so downstream
    /// formatters can present them as "this flow … and N alternative
    /// path(s)" rather than silently dropping one.
    pub alternative_finding_ids: SmallVec<[String; 2]>,
}

impl Finding {
    /// Append an engine provenance note, deduplicating against notes
    /// already present.  Intended as a builder-style helper for construction
    /// sites that want to tag a new finding inline.
    pub fn with_note(mut self, note: EngineNote) -> Self {
        crate::engine_notes::push_unique(&mut self.engine_notes, note);
        self
    }

    /// Merge a note into `engine_notes`, skipping duplicates.
    pub fn merge_note(&mut self, note: EngineNote) {
        crate::engine_notes::push_unique(&mut self.engine_notes, note);
    }
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
    //    No locator: pass-2 intra-file summaries are transient (not persisted)
    //    and behavior depends on SinkSite.cap only, which is always populated.
    let (ssa_summaries, callee_bodies) = lower_all_functions_from_bodies(
        file_cfg,
        caller_lang,
        caller_namespace,
        local_summaries,
        global_summaries,
        None,
    );
    let ssa_sums_ref = if ssa_summaries.is_empty() {
        None
    } else {
        Some(&ssa_summaries)
    };

    // 2. Context-sensitive inline analysis setup.  Toggle lives at
    //    `analysis.engine.context_sensitive` in `nyx.conf` (or the
    //    `--context-sensitive / --no-context-sensitive` CLI flag).
    let context_sensitive = crate::utils::analysis_options::current().context_sensitive;
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
    //
    // `max_iterations` is the safety cap, not an expected depth — the
    // pass-2 loop breaks on seed equality (monotone lattice, finite
    // height) and only rides the cap when convergence legitimately
    // needs more rounds than the cap allows.  See
    // [`JS_TS_PASS2_SAFETY_CAP`] for the rationale.
    let max_iterations = if matches!(caller_lang, Lang::JavaScript | Lang::TypeScript) {
        js_ts_pass2_cap()
    } else {
        1
    };
    // Reset the observability counter before this scan so tests always
    // read a fresh value.  Non-JS/TS languages leave it at `1` (the
    // lexical-containment pass counts as a single round).
    LAST_JS_TS_PASS2_ITERATIONS.store(0, Ordering::Relaxed);
    let import_bindings_ref = if file_cfg.import_bindings.is_empty() {
        None
    } else {
        Some(&file_cfg.import_bindings)
    };
    // Cross-file bodies come from GlobalSummaries. Threaded through the
    // transfer for context-sensitive resolution; plumbing only when no
    // reader is configured, preserving prior behaviour byte-for-byte.
    let cross_file_bodies_ref = global_summaries.and_then(|gs| gs.bodies_by_key());
    if let Some(map) = cross_file_bodies_ref {
        tracing::debug!(
            cross_file_bodies = map.len(),
            file = %caller_namespace,
            "taint: cross-file bodies available for pass 2"
        );
    }

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
        cross_file_bodies_ref,
    );

    // 4. Deduplicate findings using a richer key that preserves distinct
    //    flows.
    //
    //    The historical dedup at this point was:
    //
    //        sort_by_key(|f| (body_id, sink.index(), source.index(), !path_validated));
    //        dedup_by_key(|f| (body_id, sink, source));
    //
    //    which silently collapsed an *unguarded* flow reaching the same
    //    `(sink, source)` as a guarded flow — the `!path_validated` sort
    //    ordered `path_validated == true` first, so the exploitable
    //    branch was the one that got dropped.  See Phase 7 of
    //    `PRE_RELEASE_PLAN.md`.
    //
    //    New behaviour: the dedup key is
    //        (body_id, sink, source, path_validated, path_hash).
    //    Findings that differ on `path_validated` *or* on `path_hash`
    //    (i.e. traverse different intermediate variables) are kept as
    //    distinct findings.  `link_alternative_paths` then populates
    //    `alternative_finding_ids` on each finding so downstream
    //    formatters can render "… and N alternative path(s)".
    all_findings.sort_by_key(|f| {
        (
            f.body_id.0,
            f.sink.index(),
            f.source.index(),
            !f.path_validated,
            f.path_hash,
        )
    });
    all_findings.dedup_by_key(|f| (f.body_id, f.sink, f.source, f.path_validated, f.path_hash));

    // 5. Assign stable finding IDs now that `body_id` has been set and
    //    the dedup has picked the final set of distinct flows.  The ID
    //    is used to cross-reference siblings via
    //    `Finding.alternative_finding_ids`.
    for f in &mut all_findings {
        f.finding_id = make_finding_id(f);
    }

    // 6. Link alternative paths: for every group of findings that share
    //    `(body_id, sink, source)`, publish each finding's ID into the
    //    other findings' `alternative_finding_ids` list.
    link_alternative_paths(&mut all_findings);

    all_findings
}

/// Build the stable identifier for a [`Finding`].
///
/// Format: `taint-<body_id>-<source_idx>-<sink_idx>-<path_hash_hex>-<v|u>`.
/// The `v`/`u` suffix disambiguates validated (`v`) from unvalidated
/// (`u`) flows that share `(body, sink, source, path_hash)`.  The hex
/// hash disambiguates distinct intermediate paths.  Both components are
/// independent of caller-side formatters so the ID survives
/// serialization to JSON/SARIF unchanged.
fn make_finding_id(f: &Finding) -> String {
    format!(
        "taint-{}-{}-{}-{:016x}-{}",
        f.body_id.0,
        f.source.index(),
        f.sink.index(),
        f.path_hash,
        if f.path_validated { 'v' } else { 'u' },
    )
}

/// Cross-link findings that share `(body_id, sink, source)` but differ
/// on `path_validated` or `path_hash`.  After this call each such
/// finding's `alternative_finding_ids` lists every sibling's
/// [`Finding::finding_id`] — so a guarded flow links to the unguarded
/// sibling and vice versa.  Isolated findings (no sibling) get an
/// empty list.
fn link_alternative_paths(findings: &mut [Finding]) {
    // Group indices by (body_id, sink, source).  A simple O(n log n)
    // sort would clobber the caller-visible order; use a hashmap instead.
    let mut groups: HashMap<(BodyId, NodeIndex, NodeIndex), Vec<usize>> = HashMap::new();
    for (idx, f) in findings.iter().enumerate() {
        groups
            .entry((f.body_id, f.sink, f.source))
            .or_default()
            .push(idx);
    }
    for (_, members) in groups {
        if members.len() < 2 {
            continue;
        }
        // Collect IDs once, then distribute to every member *except self*.
        let ids: Vec<String> = members
            .iter()
            .map(|&i| findings[i].finding_id.clone())
            .collect();
        for &member_idx in &members {
            let own_id = findings[member_idx].finding_id.clone();
            findings[member_idx].alternative_finding_ids.clear();
            findings[member_idx]
                .alternative_finding_ids
                .extend(ids.iter().filter(|id| **id != own_id).cloned());
        }
    }
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
        &std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    callee_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
    seed: Option<&HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>>,
    import_bindings: Option<&crate::cfg::ImportBindings>,
    cross_file_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
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
    let has_nonempty_seed = seed.is_some_and(|s| !s.is_empty());
    // Scoped lowering creates SsaOp::Param ops for formal parameters, required
    // for handler-param auto-seeding to fire. Java lambda bodies need this too
    // so that `cmd -> Runtime.exec(cmd)` picks up `cmd` as a handler param.
    let is_java_lambda =
        lang == Lang::Java && body.meta.kind == crate::cfg::BodyKind::AnonymousFunction;
    let use_scoped_lowering = !is_toplevel
        && (matches!(lang, Lang::JavaScript | Lang::TypeScript)
            || has_nonempty_seed
            || is_java_lambda);
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

    // Clear per-body engine-note collector before the body's analysis;
    // any WorklistCapped / OriginsTruncated notes recorded during
    // transfer land in this bucket and are attached to every finding
    // emitted from the body once analysis is done.
    ssa_transfer::reset_body_engine_notes();

    match ssa_result {
        Ok(mut ssa_body) => {
            let opt = crate::ssa::optimize_ssa(&mut ssa_body, cfg, Some(lang));
            if tracing::enabled!(tracing::Level::TRACE) {
                tracing::trace!(
                    func = body.meta.name.as_deref().unwrap_or("<anon>"),
                    ssa = %ssa_body,
                    "SSA body lowered",
                );
                for block in &ssa_body.blocks {
                    for inst in block.phis.iter().chain(block.body.iter()) {
                        if let Some(t) = opt.type_facts.get_type(inst.value) {
                            tracing::trace!(value = inst.value.0, ty = ?t, "type fact");
                        }
                    }
                }
            }
            let dynamic_pts = std::cell::RefCell::new(std::collections::HashMap::new());
            // Static-map abstract analysis: recognises provably-bounded
            // lookup idioms (e.g. `map.get(x).unwrap_or("safe")`) so the SSA
            // taint engine can clear command-injection findings whose payload
            // is a finite set of literal strings.
            let static_map =
                crate::ssa::static_map::analyze(&ssa_body, cfg, Some(lang), &opt.const_values);
            let static_map_opt = if static_map.is_empty() {
                None
            } else {
                Some(static_map)
            };
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
                promisify_aliases: None,
                module_aliases: if opt.module_aliases.is_empty() {
                    None
                } else {
                    Some(&opt.module_aliases)
                },
                static_map: static_map_opt.as_ref(),
                auto_seed_handler_params: matches!(lang, Lang::JavaScript | Lang::TypeScript)
                    || (lang == Lang::Java
                        && body.meta.kind == crate::cfg::BodyKind::AnonymousFunction),
                cross_file_bodies,
            };
            let (events, block_states) =
                ssa_transfer::run_ssa_taint_full(&ssa_body, cfg, &transfer);
            let mut findings = ssa_transfer::ssa_events_to_findings(&events, &ssa_body, cfg);
            let body_notes = ssa_transfer::take_body_engine_notes();
            for f in &mut findings {
                f.body_id = body_id;
                for note in &body_notes {
                    f.merge_note(note.clone());
                }
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
            // After forward taint + symex have produced a final
            // `Finding.symbolic` shape, run the demand-driven backwards pass
            // and layer its verdict on top.  Placing this *after* symex
            // (which overwrites `symbolic`) preserves any symex witness
            // while still annotating `backwards-confirmed` / `-infeasible`
            // onto the `cutoff_notes` vector.  Gated by
            // `analysis.engine.backwards_analysis` (default off).
            if crate::utils::analysis_options::current().backwards_analysis {
                let bctx = backwards::BackwardsCtx {
                    ssa: &ssa_body,
                    cfg,
                    lang,
                    global_summaries,
                    intra_file_bodies: callee_bodies,
                    depth_budget: backwards::DEFAULT_BACKWARDS_DEPTH,
                };
                for finding in &mut findings {
                    let Some(sink_val) = ssa_body.cfg_node_map.get(&finding.sink).copied() else {
                        continue;
                    };
                    let sink_caps = cfg[finding.sink].taint.labels.iter().fold(
                        crate::labels::Cap::empty(),
                        |acc, l| match l {
                            crate::labels::DataLabel::Sink(c) => acc | *c,
                            _ => acc,
                        },
                    );
                    let caps = if sink_caps.is_empty() {
                        crate::labels::Cap::all()
                    } else {
                        sink_caps
                    };
                    let flows =
                        backwards::analyse_sink_backwards(&bctx, sink_val, finding.sink, caps);
                    let verdict = backwards::aggregate_verdict(&flows);
                    backwards::annotate_finding(finding, verdict);
                }
            }
            // Extract exit state for seeding child bodies.
            let exit_state =
                ssa_transfer::extract_ssa_exit_state(&block_states, &ssa_body, cfg, &transfer);
            (findings, Some(exit_state))
        }
        Err(e) => {
            // SSA lowering produced no analyzable body.  We still surface
            // the event so downstream tooling can tell "we tried and gave
            // up" from "we ran clean" — a TRACE-level log records the
            // reason (no synthetic Finding is manufactured because a
            // diag pointing at no source location would be misleading).
            tracing::trace!(
                body_id = body_id.0,
                body_name = ?body.meta.name,
                error = %e,
                "SSA lowering bailed; emitting engine note",
            );
            ssa_transfer::record_engine_note(crate::engine_notes::EngineNote::SsaLoweringBailed {
                reason: format!("{e}"),
            });
            // Drain the collector so the note does not bleed into the
            // next body (which will call reset on entry, but be explicit).
            let _ = ssa_transfer::take_body_engine_notes();
            (Vec::new(), None)
        }
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
        &std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    callee_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
    max_iterations: usize,
    import_bindings: Option<&crate::cfg::ImportBindings>,
    cross_file_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
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
            cross_file_bodies,
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
    //
    // `iters_used` counts how many rounds of the convergence loop
    // actually ran (not including the initial lexical-containment pass
    // above).  It is used to detect cap-hit after the loop exits: a
    // cap-hit is the case where we exhausted the budget without the
    // `combined_exit == current_seed` break firing.
    let mut converged_early = true;
    let mut iters_used: usize = 0;
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

        let rounds = max_iterations.saturating_sub(1);
        converged_early = rounds == 0;
        for round in 0..rounds {
            iters_used = round + 1;
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
                converged_early = true;
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
                    .is_none_or(|b| b.meta.parent_body_id.is_none())
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
                    cross_file_bodies,
                );
                all_findings.extend(findings);
                if let Some(es) = exit_state {
                    body_exit_states.insert(body.meta.id, es);
                }
            }
        }
    }

    // Record observability counter.  `iters_used == 0` covers the
    // non-JS/TS path (`max_iterations == 1`) and the JS/TS case where
    // the convergence loop did not enter — report `1` so the counter
    // always reflects "at least the lexical-containment pass ran".
    let reported_iters = if iters_used == 0 { 1 } else { iters_used };
    LAST_JS_TS_PASS2_ITERATIONS.store(reported_iters, Ordering::Relaxed);

    // Cap-hit: the loop exhausted `max_iterations` without the
    // `combined_exit == current_seed` break firing.  Tag every finding
    // produced by this file so downstream consumers know the results
    // may be under-reported.  Only meaningful for JS/TS
    // (`max_iterations > 1`); single-iteration languages always
    // converge trivially by definition.
    if max_iterations > 1 && !converged_early {
        tracing::warn!(
            file = %namespace,
            iterations = iters_used,
            cap = max_iterations,
            "JS/TS pass-2 in-file fixpoint did not converge within safety cap — \
             results may be imprecise. This usually indicates a very deep chain \
             of top-level bindings threaded through helper functions; please \
             file a bug with a reproducer."
        );
        let note = EngineNote::InFileFixpointCapped {
            iterations: iters_used as u32,
        };
        for f in &mut all_findings {
            f.merge_note(note.clone());
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

/// Resolve a bare function name + param count to a canonical [`FuncKey`] by
/// consulting the already FuncKey-keyed `local_summaries`.
///
/// When exactly one `(name, arity)`-matching entry exists we use its full
/// identity (container / disambig / kind preserved).  When zero or multiple
/// match we fall back to a free-function key so the caller still has a
/// well-formed key — this can only happen in legacy discovery paths that
/// cannot see through same-name siblings, and those paths were already
/// collision-prone before this refactor.  New intra-file analysis code
/// should prefer [`BodyMeta::func_key`].
fn lookup_canonical_func_key(
    local_summaries: &FuncSummaries,
    lang: Lang,
    namespace: &str,
    func_name: &str,
    param_count: usize,
) -> FuncKey {
    // `local_summaries` is file-local, so every entry's namespace agrees with
    // whatever `build_cfg` wrote (raw file path). We match by lang + name +
    // arity and fall back to name-only — the caller's `namespace` argument is
    // only used when we have to synthesise a key as a last resort.
    let mut matches = local_summaries
        .keys()
        .filter(|k| k.lang == lang && k.name == func_name && k.arity == Some(param_count));
    let first = matches.next().cloned();
    if let Some(first) = first
        && matches.next().is_none()
    {
        return first;
    }
    if let Some(name_only) = local_summaries
        .keys()
        .find(|k| k.lang == lang && k.name == func_name)
    {
        return name_only.clone();
    }
    FuncKey {
        lang,
        namespace: namespace.to_string(),
        container: String::new(),
        name: func_name.to_string(),
        arity: Some(param_count),
        disambig: None,
        kind: FuncKind::Function,
    }
}

/// Extract precise SSA function summaries for all functions in a file.
///
/// Lowers each function to SSA individually and runs per-parameter probing
/// to produce an `SsaFuncSummary`. The resulting map is keyed by canonical
/// [`FuncKey`] so that same-name functions on different containers in the
/// same file produce distinct summary entries.
#[allow(dead_code)] // Used by tests; production code uses extract_ssa_artifacts
pub(crate) fn extract_intra_file_ssa_summaries(
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary> {
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
            None,
            Some(&formal_params),
        );

        // Only store if the summary has observable effects.  With
        // `points_to` support, a void helper whose only observable behaviour
        // is a parameter-to-parameter alias (e.g. `fn set(t, v) { t.x = v; }`)
        // must survive this filter so summary application at cross-file
        // call sites can replay the alias edges.
        if !summary.param_to_return.is_empty()
            || !summary.param_to_sink.is_empty()
            || !summary.source_caps.is_empty()
            || !summary.param_container_to_return.is_empty()
            || !summary.param_to_container_store.is_empty()
            || summary.return_abstract.is_some()
            || !summary.points_to.is_empty()
        {
            let key =
                lookup_canonical_func_key(local_summaries, lang, namespace, func_name, param_count);
            summaries.insert(key, summary);
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

/// Lower all function bodies from `FileCfg` to produce SSA summaries + cached
/// bodies.  Each body's own graph is used directly — no scope filtering needed.
///
/// Both returned maps are keyed by each body's canonical [`FuncKey`] (carried
/// on [`crate::cfg::BodyMeta::func_key`]).  This is the most collision-
/// resistant identity we have: same-name methods on different classes, same-
/// name overloads with different arity, and anonymous bodies at distinct
/// source spans all get distinct keys.
fn lower_all_functions_from_bodies(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
) -> (
    std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>,
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

        // Canonical FuncKey: prefer the identity attached to the body at
        // CFG-construction time; otherwise fall back to matching in
        // `local_summaries`.
        //
        // `body.meta.func_key` carries the raw file-path namespace that
        // `build_cfg` wrote. The caller passes `namespace` already normalized
        // against `scan_root`, which is what FuncSummary keys use on the
        // cross-file side (`FuncSummary::func_key`). Overriding the namespace
        // here keeps both sides of `GlobalSummaries` agreement — otherwise
        // `resolve_callee` resolves to the normalized FuncSummary key and
        // misses the raw-path SSA entry.
        let mut key = body.meta.func_key.clone().unwrap_or_else(|| {
            lookup_canonical_func_key(local_summaries, lang, namespace, &func_name, param_count)
        });
        key.namespace = namespace.to_string();

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
                locator,
                Some(formal_params),
            );

            // Always insert the summary, even when all fields are empty/default.
            // An empty summary tells resolve_callee "this function exists and has
            // no taint effects" — preventing fallthrough to the less precise old
            // FuncSummary which may report false source_caps from internal sources.
            summaries.insert(key.clone(), summary);
        }

        let opt = crate::ssa::optimize_ssa(&mut func_ssa, &body.graph, Some(lang));

        bodies.insert(
            key,
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

type SsaArtifactSummaries =
    std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>;
type EligibleCalleeBodies = Vec<(FuncKey, ssa_transfer::CalleeSsaBody)>;

/// FileCfg-based artifact extraction: iterates per-body (not per function
/// entry) and lowers each body's graph with its recorded entry/params. This
/// path is equivalent to what `analyse_file` uses at taint time, so the SSA
/// summaries produced here line up exactly with what pass 2 will consult.
pub(crate) fn extract_ssa_artifacts_from_file_cfg(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
) -> (SsaArtifactSummaries, EligibleCalleeBodies) {
    let (summaries, bodies) = lower_all_functions_from_bodies(
        file_cfg,
        lang,
        namespace,
        local_summaries,
        global_summaries,
        locator,
    );

    let mut eligible_bodies = Vec::new();
    if crate::symex::cross_file_symex_enabled() {
        for (key, mut body) in bodies {
            if body.ssa.blocks.len() > MAX_CROSS_FILE_BODY_BLOCKS {
                continue;
            }
            // Populate node metadata against the per-body graph whose NodeIndex
            // space the SSA was produced on — otherwise cross-file replay can't
            // find the original CFG nodes.
            //
            // `key.namespace` was already normalised against `scan_root` in
            // `lower_all_functions_from_bodies`; `body.meta.func_key.namespace`
            // still carries the raw `build_cfg` file path.  Compare on
            // structural identity (everything *but* namespace) so the two
            // agree even when the namespace representations differ.
            let Some(body_cfg) = file_cfg.bodies.iter().find(|b| {
                b.meta.func_key.as_ref().is_some_and(|k| {
                    k.lang == key.lang
                        && k.container == key.container
                        && k.name == key.name
                        && k.arity == key.arity
                        && k.disambig == key.disambig
                        && k.kind == key.kind
                })
            }) else {
                continue;
            };
            if !ssa_transfer::populate_node_meta(&mut body, &body_cfg.graph) {
                continue;
            }
            eligible_bodies.push((key, body));
        }
    }

    (summaries, eligible_bodies)
}

#[cfg(test)]
mod tests;
