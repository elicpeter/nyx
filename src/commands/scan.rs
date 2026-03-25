#![allow(clippy::collapsible_if, clippy::type_complexity)]

pub(crate) use crate::ast::{
    analyse_file_fused, extract_all_summaries_from_bytes, run_rules_on_bytes, run_rules_on_file,
};
use crate::callgraph::{CallGraph, FileBatch};
use crate::cli::{IndexMode, OutputFormat};
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::{FindingCategory, Severity, SeverityFilter};
use crate::server::progress::{ScanMetrics, ScanProgress, ScanStage};
use crate::server::scan_log::ScanLogCollector;
use crate::summary::{self, GlobalSummaries};
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use console::style;
use dashmap::DashMap;
use indicatif::{ProgressBar, ProgressStyle};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn make_progress_bar(len: u64, msg: &str, show: bool) -> ProgressBar {
    if !show {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {msg} [{bar:30.cyan/blue}] {pos}/{len} ({eta})",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb.set_message(msg.to_string());
    pb
}

fn record_persist_error(errors: &Arc<Mutex<Vec<String>>>, message: String) {
    errors.lock().expect("persist error mutex").push(message);
}

fn fail_if_persist_errors(stage: &str, errors: Arc<Mutex<Vec<String>>>) -> NyxResult<()> {
    let errors = errors.lock().expect("persist error mutex");
    if errors.is_empty() {
        return Ok(());
    }

    let mut details = errors.iter().take(3).cloned().collect::<Vec<_>>();
    if errors.len() > 3 {
        details.push(format!("... and {} more", errors.len() - 3));
    }

    Err(crate::errors::NyxError::Msg(format!(
        "{stage} failed to persist scan state: {}",
        details.join("; ")
    )))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Diag {
    pub path: String,
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub id: String,
    /// High-level finding category (Security, Reliability, Quality).
    pub category: FindingCategory,
    /// Whether the finding is guarded by a path validation predicate.
    /// Only set for taint findings; `false` for AST/CFG structural findings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_kind: Option<String>,
    /// Optional human-readable message with additional context (e.g. state analysis details).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Structured evidence labels (e.g. Source, Sink) for console display.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,
    /// Confidence level (Low / Medium / High).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<crate::evidence::Confidence>,
    /// Structured evidence (source/sink spans, state transitions, notes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<crate::evidence::Evidence>,
    /// Attack-surface ranking score (higher = more exploitable / important).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank_score: Option<f64>,
    /// Breakdown of how the ranking score was computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank_reason: Option<Vec<(String, String)>>,
    /// Whether this finding was suppressed by an inline `nyx:ignore` directive.
    #[serde(default, skip_serializing_if = "is_false")]
    pub suppressed: bool,
    /// Metadata about the suppression directive, if suppressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression: Option<crate::suppress::SuppressionMeta>,
    /// Rollup data when multiple occurrences are grouped into one finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollup: Option<RollupData>,
}

/// Rollup data for grouped findings (e.g. 38 occurrences of `rs.quality.unwrap`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollupData {
    /// Total number of occurrences.
    pub count: usize,
    /// First N example locations (controlled by `rollup_examples`).
    pub occurrences: Vec<Location>,
}

/// A source location within a file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub line: usize,
    pub col: usize,
}

/// Statistics about findings suppressed by the prioritization pipeline.
pub struct SuppressionStats {
    pub quality_dropped: usize,
    pub low_budget_dropped: usize,
    pub max_results_dropped: usize,
    pub include_quality: bool,
    #[allow(dead_code)]
    pub show_all: bool,
    pub max_low: u32,
    pub max_low_per_file: u32,
    pub max_low_per_rule: u32,
}

impl SuppressionStats {
    pub fn total_suppressed(&self) -> usize {
        self.quality_dropped + self.low_budget_dropped + self.max_results_dropped
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Entry point called by the CLI.
#[allow(clippy::too_many_arguments)]
pub fn handle(
    path: &str,
    index_mode: IndexMode,
    format: OutputFormat,
    severity_filter: Option<SeverityFilter>,
    fail_on: Option<Severity>,
    show_suppressed: bool,
    show_instances: Option<&str>,
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;

    // Detect frameworks from project manifests and enrich the config.
    let config = &{
        let mut cfg = config.clone();
        if cfg.framework_ctx.is_none() {
            let fw = crate::utils::detect_frameworks(&scan_path);
            if !fw.frameworks.is_empty() {
                tracing::info!(frameworks = ?fw.frameworks, "detected frameworks");
            }
            cfg.framework_ctx = Some(fw);
        }
        cfg
    };

    let is_machine = format == OutputFormat::Json || format == OutputFormat::Sarif;
    let suppress_status = config.output.quiet || is_machine;
    if !suppress_status {
        // Status messages go to stderr so stdout stays clean
        eprintln!(
            "{} {}...\n",
            style("Checking").green().bold(),
            &project_name
        );
    }

    let show_progress = !is_machine && !config.output.quiet;

    let mut diags: Vec<Diag> = if index_mode == IndexMode::Off {
        scan_filesystem(&scan_path, config, show_progress)?
    } else {
        if index_mode == IndexMode::Rebuild || !db_path.exists() {
            tracing::debug!("Scanning filesystem index filesystem");
            crate::commands::index::build_index(
                &project_name,
                &scan_path,
                &db_path,
                config,
                show_progress,
            )?;
        }

        let pool = Indexer::init(&db_path)?;
        if config.database.vacuum_on_startup {
            let idx = Indexer::from_pool(&project_name, &pool)?;
            idx.vacuum()?;
        }
        scan_with_index_parallel(&project_name, pool, config, show_progress, &scan_path)?
    };

    tracing::debug!("Found {:?} issues (pre-filter).", diags.len());

    // ── Apply severity filter AFTER all downgrades/dedup ────────────────
    if let Some(ref filter) = severity_filter {
        diags.retain(|d| filter.matches(d.severity));
    }

    // ── Apply minimum-score filter AFTER ranking ─────────────────────
    if let Some(min) = config.output.min_score {
        let threshold = f64::from(min);
        diags.retain(|d| d.rank_score.unwrap_or(0.0) >= threshold);
    }

    // ── Apply minimum-confidence filter AFTER confidence assignment ──
    if let Some(min_conf) = config.output.min_confidence {
        diags.retain(|d| d.confidence.is_none_or(|c| c >= min_conf));
    }

    // ── Apply inline suppressions ───────────────────────────────────
    apply_suppressions(&mut diags);
    if !show_suppressed {
        diags.retain(|d| !d.suppressed);
    }

    // ── Prioritization: category filter, rollup, LOW budgets ─────────
    let stats = prioritize(&mut diags, &config.output, show_instances);

    tracing::debug!("Emitting {:?} issues (post-filter).", diags.len());

    // ── Output ──────────────────────────────────────────────────────────
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string(&diags)
                .map_err(|e| crate::errors::NyxError::Msg(e.to_string()))?;
            println!("{json}");
        }
        OutputFormat::Sarif => {
            let sarif = crate::output::build_sarif(&diags, &scan_path);
            let json = serde_json::to_string_pretty(&sarif)
                .map_err(|e| crate::errors::NyxError::Msg(e.to_string()))?;
            println!("{json}");
        }
        OutputFormat::Console => {
            tracing::debug!("Printing to console");
            print!(
                "{}",
                crate::fmt::render_console(&diags, &project_name, Some(&stats))
            );
        }
    }

    // ── --fail-on: exit non-zero if threshold breached ──────────────────
    // Suppressed findings do not count toward the threshold.
    if let Some(threshold) = fail_on {
        let breached = diags
            .iter()
            .any(|d| !d.suppressed && d.severity <= threshold);
        if breached {
            std::process::exit(1);
        }
    }

    Ok(())
}

// --------------------------------------------------------------------------------------------
// Shared post-processing helpers
// --------------------------------------------------------------------------------------------

/// Assign confidence, rank, and truncate diagnostics.
pub(crate) fn post_process_diags(diags: &mut Vec<Diag>, cfg: &Config) {
    // 1. Compute confidence first (needed by ranking).
    for d in diags.iter_mut() {
        if d.confidence.is_none() {
            d.confidence = Some(crate::evidence::compute_confidence(d));
        }
    }
    // 2. Rank (now has access to confidence).
    if cfg.output.attack_surface_ranking {
        crate::rank::rank_diags(diags);
    }
    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
    }
}

/// Build the call graph from global summaries and run SCC/topo analysis.
fn build_and_analyse_call_graph(
    global_summaries: &GlobalSummaries,
) -> (
    crate::callgraph::CallGraph,
    crate::callgraph::CallGraphAnalysis,
) {
    let _span = tracing::info_span!("build_call_graph").entered();
    let call_graph = crate::callgraph::build_call_graph(global_summaries, &[]);
    let cg_analysis = crate::callgraph::analyse(&call_graph);
    tracing::info!(
        nodes = call_graph.graph.node_count(),
        edges = call_graph.graph.edge_count(),
        unresolved_not_found = call_graph.unresolved_not_found.len(),
        unresolved_ambiguous = call_graph.unresolved_ambiguous.len(),
        sccs = cg_analysis.sccs.len(),
        "call graph built"
    );
    (call_graph, cg_analysis)
}

/// Log individual unresolved/ambiguous callees at debug level, deduplicated by callee name.
fn log_unresolved_callees(call_graph: &CallGraph) {
    use std::collections::HashSet;
    let mut seen_not_found: HashSet<&str> = HashSet::new();
    for u in &call_graph.unresolved_not_found {
        if seen_not_found.insert(&u.callee_name) {
            tracing::debug!(caller=%u.caller.name, callee=%u.callee_name, "unresolved callee: not found");
        }
    }
    let mut seen_ambiguous: HashSet<&str> = HashSet::new();
    for a in &call_graph.unresolved_ambiguous {
        if seen_ambiguous.insert(&a.callee_name) {
            tracing::debug!(caller=%a.caller.name, callee=%a.callee_name, candidates=a.candidates.len(), "unresolved callee: ambiguous");
        }
    }
}

/// Maximum iterations for SCC fixed-point convergence.
const MAX_SCC_FIXPOINT_ITERS: usize = 3;

/// Run pass 2 analysis on a sequence of topo-ordered file batches.
///
/// For batches with mutual recursion, iterates until summaries converge
/// (max [`MAX_SCC_FIXPOINT_ITERS`]).  Updates `global_summaries` between
/// batches so later callers see refined callee context.
fn run_topo_batches(
    batches: &[FileBatch<'_>],
    orphans: &[&PathBuf],
    global_summaries: &mut GlobalSummaries,
    cfg: &Config,
    scan_root: Option<&Path>,
    pb: &ProgressBar,
    progress: Option<&Arc<ScanProgress>>,
    logs: Option<&Arc<ScanLogCollector>>,
) -> Vec<Diag> {
    let root_str = scan_root.map(|r| r.to_string_lossy());
    let root_str_ref = root_str.as_deref();
    let mut result: Vec<Diag> = Vec::new();

    for (batch_idx, batch) in batches.iter().enumerate() {
        if batch.has_mutual_recursion {
            // SCC fixed-point: iterate until summaries converge.
            let mut iteration_diags = Vec::new();
            for iter in 0..MAX_SCC_FIXPOINT_ITERS {
                let snap_before = global_summaries.snapshot_caps();

                // Intermediate iteration diags may be incomplete due to
                // not-yet-converged summaries — only keep final iteration's.
                iteration_diags.clear();

                let ssa_snap_before = global_summaries.snapshot_ssa().clone();

                let batch_results: Vec<(
                    std::path::PathBuf,
                    Vec<Diag>,
                    Vec<crate::summary::FuncSummary>,
                    Vec<(String, usize, crate::summary::ssa_summary::SsaFuncSummary)>,
                )> = batch
                    .files
                    .par_iter()
                    .map(|path| {
                        if let Some(p) = progress {
                            p.set_current_file(&path.to_string_lossy());
                        }
                        let bytes = std::fs::read(path).unwrap_or_default();
                        match analyse_file_fused(
                            &bytes,
                            path,
                            cfg,
                            Some(global_summaries),
                            scan_root,
                        ) {
                            Ok(r) => {
                                pb.inc(0); // don't double-count iterations in progress bar
                                (path.to_path_buf(), r.diags, r.summaries, r.ssa_summaries)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "pass 2 (SCC iter {}): {}: {e}",
                                    iter,
                                    path.display()
                                );
                                if let Some(l) = logs {
                                    l.warn(
                                        format!("Pass 2 (SCC iter {iter}) analysis failed: {e}"),
                                        Some(path.display().to_string()),
                                        None,
                                    );
                                }
                                (path.to_path_buf(), vec![], vec![], vec![])
                            }
                        }
                    })
                    .collect();

                let mut ssa_count: usize = 0;
                for (path, diags, summaries, ssa_summaries) in batch_results {
                    iteration_diags.extend(diags);

                    // Derive lang: prefer FuncSummary slug, fall back to file extension.
                    let lang = summaries
                        .first()
                        .and_then(|s| crate::symbol::Lang::from_slug(&s.lang))
                        .or_else(|| {
                            path.extension()
                                .and_then(|e| e.to_str())
                                .and_then(crate::symbol::Lang::from_extension)
                        });

                    for s in summaries {
                        let key = s.func_key(root_str_ref);
                        global_summaries.insert(key, s);
                    }

                    if let Some(lang) = lang {
                        if !ssa_summaries.is_empty() {
                            let namespace = crate::symbol::normalize_namespace(
                                &path.to_string_lossy(),
                                root_str_ref,
                            );
                            for (name, arity, ssa_sum) in ssa_summaries {
                                let key = crate::symbol::FuncKey {
                                    lang,
                                    namespace: namespace.clone(),
                                    name,
                                    arity: Some(arity),
                                };
                                global_summaries.insert_ssa(key, ssa_sum);
                                ssa_count += 1;
                            }
                        }
                    }
                }

                let snap_after = global_summaries.snapshot_caps();
                let ssa_converged = ssa_snap_before == *global_summaries.snapshot_ssa();
                let converged = snap_before == snap_after && ssa_converged;
                tracing::debug!(
                    batch = batch_idx,
                    files = batch.files.len(),
                    recursive = true,
                    iteration = iter,
                    ssa_summaries_updated = ssa_count,
                    ssa_converged,
                    converged,
                    "SCC batch iteration"
                );
                if converged {
                    break;
                }
            }
            // Count progress for these files once.
            pb.inc(batch.files.len() as u64);
            if let Some(p) = progress {
                p.inc_analyzed(batch.files.len() as u64);
                p.inc_batches_completed(1);
            }
            result.extend(iteration_diags);
        } else {
            // Non-recursive batch: single pass.
            let batch_diags: Vec<Diag> = batch
                .files
                .par_iter()
                .flat_map_iter(|path| {
                    if let Some(p) = progress {
                        p.set_current_file(&path.to_string_lossy());
                    }
                    let d = match run_rules_on_file(path, cfg, Some(global_summaries), scan_root) {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!("pass 2: {}: {e}", path.display());
                            if let Some(l) = logs {
                                l.warn(
                                    format!("Pass 2 analysis failed: {e}"),
                                    Some(path.display().to_string()),
                                    None,
                                );
                            }
                            vec![]
                        }
                    };
                    pb.inc(1);
                    if let Some(p) = progress {
                        p.inc_analyzed(1);
                    }
                    d
                })
                .collect();

            tracing::debug!(
                batch = batch_idx,
                files = batch.files.len(),
                recursive = false,
                "non-recursive batch complete"
            );
            if let Some(p) = progress {
                p.inc_batches_completed(1);
            }
            result.extend(batch_diags);
        }
    }

    // Orphan files (no functions in call graph) — process last, single pass.
    if !orphans.is_empty() {
        let orphan_diags: Vec<Diag> = orphans
            .par_iter()
            .flat_map_iter(|path| {
                if let Some(p) = progress {
                    p.set_current_file(&path.to_string_lossy());
                }
                let d = match run_rules_on_file(path, cfg, Some(global_summaries), scan_root) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("pass 2: {}: {e}", path.display());
                        if let Some(l) = logs {
                            l.warn(
                                format!("Pass 2 analysis failed: {e}"),
                                Some(path.display().to_string()),
                                None,
                            );
                        }
                        vec![]
                    }
                };
                pb.inc(1);
                if let Some(p) = progress {
                    p.inc_analyzed(1);
                }
                d
            })
            .collect();
        if let Some(p) = progress {
            p.inc_batches_completed(1);
        }
        result.extend(orphan_diags);
    }

    result
}

// --------------------------------------------------------------------------------------------
// Two‑pass scanning (no index)
// --------------------------------------------------------------------------------------------

/// Walk the filesystem and perform a two‑pass scan:
///
///  **Pass 1** – Parse every file and extract function summaries.
///  **Pass 2** – Re‑parse every file and run taint analysis with the
///               merged cross‑file summaries.
///
/// AST pattern queries are run during pass 2 (they don't depend on summaries).
pub(crate) fn scan_filesystem(
    root: &Path,
    cfg: &Config,
    show_progress: bool,
) -> NyxResult<Vec<Diag>> {
    scan_filesystem_with_observer(root, cfg, show_progress, None, None, None)
}

/// Walk the filesystem and perform a two-pass scan, optionally reporting
/// progress and metrics through the supplied atomic structs.
pub(crate) fn scan_filesystem_with_observer(
    root: &Path,
    cfg: &Config,
    show_progress: bool,
    progress: Option<&Arc<ScanProgress>>,
    metrics: Option<&Arc<ScanMetrics>>,
    logs: Option<&Arc<ScanLogCollector>>,
) -> NyxResult<Vec<Diag>> {
    // Ensure framework context is available (handle sets it, but direct
    // callers like scan_no_index may not).
    let owned_cfg;
    let cfg = if cfg.framework_ctx.is_some() {
        cfg
    } else {
        owned_cfg = {
            let mut c = cfg.clone();
            c.framework_ctx = Some(crate::utils::detect_frameworks(root));
            c
        };
        &owned_cfg
    };

    if let Some(p) = progress {
        p.set_stage(ScanStage::Discovering);
    }

    // ── Collect file list ────────────────────────────────────────────────
    let walk_start = std::time::Instant::now();
    let all_paths: Vec<PathBuf> = {
        let _span = tracing::info_span!("walk_files").entered();
        let (rx, handle) = spawn_file_walker(root, cfg);
        let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();
        if let Err(err) = handle.join() {
            tracing::error!("walker thread panicked: {:#?}", err);
            if let Some(l) = logs {
                l.error("Walker thread panicked", None, Some(format!("{err:#?}")));
            }
        }
        paths
    };
    tracing::info!(file_count = all_paths.len(), "file walk complete");

    if let Some(p) = progress {
        p.record_walk_ms(walk_start.elapsed().as_millis() as u64);
        p.set_files_discovered(all_paths.len() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "File walk complete: {} files discovered in {}ms",
                all_paths.len(),
                walk_start.elapsed().as_millis()
            ),
            None,
        );
    }

    let needs_taint = cfg.scanner.mode == crate::utils::config::AnalysisMode::Full
        || cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint;

    if !needs_taint {
        // ── AST-only: single fused pass (no cross-file context needed) ──
        if let Some(p) = progress {
            p.set_stage(ScanStage::Indexing);
        }
        if let Some(l) = logs {
            l.info("Starting AST-only analysis (no taint)", None);
        }
        let _span = tracing::info_span!("ast_only_analysis", files = all_paths.len()).entered();
        let pb = make_progress_bar(all_paths.len() as u64, "Running analysis", show_progress);

        let mut diags: Vec<Diag> = all_paths
            .par_iter()
            .flat_map_iter(|path| {
                let result = match analyse_file_fused(
                    &std::fs::read(path).unwrap_or_default(),
                    path,
                    cfg,
                    None,
                    Some(root),
                ) {
                    Ok(r) => r.diags,
                    Err(e) => {
                        tracing::warn!("analysis: {}: {e}", path.display());
                        if let Some(l) = logs {
                            l.warn(
                                format!("Analysis failed: {e}"),
                                Some(path.display().to_string()),
                                None,
                            );
                        }
                        vec![]
                    }
                };
                pb.inc(1);
                if let Some(p) = progress {
                    p.inc_parsed(1);
                    p.inc_analyzed(1);
                    p.set_current_file(&path.to_string_lossy());
                }
                result
            })
            .collect();
        pb.finish_and_clear();

        if let Some(p) = progress {
            p.set_stage(ScanStage::Complete);
        }
        post_process_diags(&mut diags, cfg);
        return Ok(diags);
    }

    // ── Taint mode: two-pass with fused pass 1 ──────────────────────────
    //
    // Pass 1 (fused): parse + CFG (once!) → extract summaries + run
    //   AST queries + local taint + CFG structural analyses.
    //   Summaries are collected for the cross-file merge.
    //
    // Pass 2: re-run full analysis with global summaries injected.
    //   This requires a second parse+CFG, but ONLY for taint-mode files
    //   that need cross-file context.  For repos where most functions
    //   don't have unresolved callees, pass 1 results are already correct.

    // ── Pass 1: fused summary extraction + parallel merge ──────────────
    //
    // Each rayon thread builds a local `GlobalSummaries` from its chunk,
    // then the per-thread maps are merged in a binary reduce tree.
    // This eliminates the serial merge_summaries bottleneck.
    if let Some(p) = progress {
        p.set_stage(ScanStage::Indexing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Starting pass 1: extracting summaries from {} files",
                all_paths.len()
            ),
            None,
        );
    }
    let pass1_start = std::time::Instant::now();
    let global_summaries: GlobalSummaries = {
        let _span = tracing::info_span!("pass1_fused", files = all_paths.len()).entered();
        let pb = make_progress_bar(
            all_paths.len() as u64,
            "Pass 1: Extracting summaries",
            show_progress,
        );
        let root_str = root.to_string_lossy();

        let gs = all_paths
            .par_iter()
            .fold(GlobalSummaries::new, |mut local_gs, path| {
                if let Ok(bytes) = std::fs::read(path) {
                    match analyse_file_fused(&bytes, path, cfg, None, Some(root)) {
                        Ok(r) => {
                            // Extract lang slug before consuming summaries
                            let first_lang = r.summaries.first().map(|s| s.lang.clone());

                            for s in r.summaries {
                                let key = s.func_key(Some(&root_str));
                                local_gs.insert(key, s);
                            }

                            // Insert SSA summaries keyed by FuncKey
                            if !r.ssa_summaries.is_empty() {
                                let lang = first_lang
                                    .as_deref()
                                    .and_then(crate::symbol::Lang::from_slug)
                                    .unwrap_or(crate::symbol::Lang::Rust);
                                let namespace = crate::symbol::normalize_namespace(
                                    &path.to_string_lossy(),
                                    Some(&root_str),
                                );
                                for (name, arity, ssa_sum) in r.ssa_summaries {
                                    let key = crate::symbol::FuncKey {
                                        lang,
                                        namespace: namespace.clone(),
                                        name,
                                        arity: Some(arity),
                                    };
                                    local_gs.insert_ssa(key, ssa_sum);
                                }
                            }

                            // Record language for progress
                            if let Some(p) = progress {
                                if let Some(ref lang) = first_lang {
                                    p.record_language(lang);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("pass 1: {}: {e}", path.display());
                            if let Some(l) = logs {
                                l.warn(
                                    format!("Pass 1 analysis failed: {e}"),
                                    Some(path.display().to_string()),
                                    None,
                                );
                            }
                        }
                    }
                } else {
                    tracing::warn!("pass 1: cannot read {}", path.display());
                    if let Some(l) = logs {
                        l.warn("Cannot read file", Some(path.display().to_string()), None);
                    }
                }
                pb.inc(1);
                if let Some(p) = progress {
                    p.inc_parsed(1);
                    p.set_current_file(&path.to_string_lossy());
                }
                local_gs
            })
            .reduce(GlobalSummaries::new, |mut a, b| {
                a.merge(b);
                a
            });

        pb.finish_and_clear();
        tracing::info!("pass 1 complete");
        gs
    };
    if let Some(p) = progress {
        p.record_pass1_ms(pass1_start.elapsed().as_millis() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!("Pass 1 complete in {}ms", pass1_start.elapsed().as_millis()),
            None,
        );
    }

    // ── Build call graph ────────────────────────────────────────────────
    if let Some(l) = logs {
        l.info("Building call graph", None);
    }
    let cg_start = std::time::Instant::now();
    let (call_graph, cg_analysis) = build_and_analyse_call_graph(&global_summaries);
    log_unresolved_callees(&call_graph);
    if let Some(p) = progress {
        p.record_call_graph_ms(cg_start.elapsed().as_millis() as u64);
    }
    if let Some(m) = metrics {
        m.call_edges.store(
            call_graph.graph.edge_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.functions_analyzed.store(
            call_graph.graph.node_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.unresolved_calls.store(
            (call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len()) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Call graph built in {}ms: {} nodes, {} edges, {} unresolved",
                cg_start.elapsed().as_millis(),
                call_graph.graph.node_count(),
                call_graph.graph.edge_count(),
                call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len(),
            ),
            None,
        );
    }

    // ── Pass 2: re-run with cross-file global summaries ──────────────────
    if let Some(p) = progress {
        p.set_stage(ScanStage::Analyzing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Starting pass 2: taint analysis on {} files",
                all_paths.len()
            ),
            None,
        );
    }
    let pass2_start = std::time::Instant::now();
    let mut diags: Vec<Diag> = {
        let _span = tracing::info_span!("pass2_analysis", files = all_paths.len()).entered();
        let pb = make_progress_bar(
            all_paths.len() as u64,
            "Pass 2: Running analysis",
            show_progress,
        );

        let (batches, orphans) = crate::callgraph::scc_file_batches_with_metadata(
            &call_graph,
            &cg_analysis,
            &all_paths,
            root,
        );
        tracing::info!(
            batches = batches.len(),
            orphan_files = orphans.len(),
            "topo-ordered file batches computed"
        );
        if let Some(l) = logs {
            l.info(
                format!(
                    "Topo-ordered file batches: {} batches, {} orphan files",
                    batches.len(),
                    orphans.len()
                ),
                None,
            );
        }

        let mut gs = global_summaries;
        let total_batches = batches.len() as u64 + u64::from(!orphans.is_empty());
        if let Some(p) = progress {
            p.set_batches_total(total_batches);
        }
        let result = run_topo_batches(
            &batches,
            &orphans,
            &mut gs,
            cfg,
            Some(root),
            &pb,
            progress,
            logs,
        );

        pb.finish_and_clear();
        result
    };
    tracing::info!(diags = diags.len(), "pass 2 complete");
    if let Some(p) = progress {
        p.record_pass2_ms(pass2_start.elapsed().as_millis() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Pass 2 complete in {}ms: {} raw findings",
                pass2_start.elapsed().as_millis(),
                diags.len()
            ),
            None,
        );
    }

    let pp_start = std::time::Instant::now();
    if let Some(p) = progress {
        p.set_stage(ScanStage::PostProcessing);
    }
    post_process_diags(&mut diags, cfg);
    if let Some(p) = progress {
        p.record_post_process_ms(pp_start.elapsed().as_millis() as u64);
        p.set_stage(ScanStage::Complete);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Post-processing complete in {}ms: {} final findings",
                pp_start.elapsed().as_millis(),
                diags.len()
            ),
            None,
        );
    }

    Ok(diags)
}

// --------------------------------------------------------------------------------------------
// Two‑pass scanning (with index)
// --------------------------------------------------------------------------------------------

/// Indexed two‑pass scan:
///
///  **Pass 1** – For every file that needs scanning, extract summaries and
///               persist them to the database.  Unchanged files keep their
///               existing summaries.
///  **Pass 2** – Load *all* summaries from the DB, merge them, and re‑run
///               taint analysis on every file with the full cross‑file view.
///               Files whose *own* code has not changed AND whose
///               dependencies have not changed can serve cached issues
///               instead.  (Today we conservatively re‑analyse every file in
///               pass 2; caching will be refined in approach 2 / 3.)
pub fn scan_with_index_parallel(
    project: &str,
    pool: Arc<Pool<SqliteConnectionManager>>,
    cfg: &Config,
    show_progress: bool,
    scan_root: &Path,
) -> NyxResult<Vec<Diag>> {
    scan_with_index_parallel_observer(
        project,
        pool,
        cfg,
        show_progress,
        scan_root,
        None,
        None,
        None,
    )
}

pub fn scan_with_index_parallel_observer(
    project: &str,
    pool: Arc<Pool<SqliteConnectionManager>>,
    cfg: &Config,
    show_progress: bool,
    scan_root: &Path,
    progress: Option<&Arc<ScanProgress>>,
    metrics: Option<&Arc<ScanMetrics>>,
    logs: Option<&Arc<ScanLogCollector>>,
) -> NyxResult<Vec<Diag>> {
    if let Some(p) = progress {
        p.set_stage(ScanStage::Discovering);
    }
    let walk_start = std::time::Instant::now();
    let indexed_files = {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.get_files(project)?
    };
    let (rx, handle) = spawn_file_walker(scan_root, cfg);
    let files: Vec<PathBuf> = rx.into_iter().flatten().collect();
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
        if let Some(l) = logs {
            l.error(
                "Walker thread panicked during indexed scan",
                None,
                Some(format!("{err:#?}")),
            );
        }
    }
    if let Some(p) = progress {
        p.record_walk_ms(walk_start.elapsed().as_millis() as u64);
        p.set_files_discovered(files.len() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Indexed scan discovered {} files in {}ms",
                files.len(),
                walk_start.elapsed().as_millis()
            ),
            None,
        );
    }

    let current_files: HashSet<PathBuf> = files.iter().cloned().collect();
    let removed_files: Vec<PathBuf> = indexed_files
        .into_iter()
        .filter(|path| !current_files.contains(path))
        .collect();
    if !removed_files.is_empty() {
        let mut idx = Indexer::from_pool(project, &pool)?;
        for path in &removed_files {
            idx.remove_file_and_related(path)?;
        }
        tracing::info!(
            removed = removed_files.len(),
            "pruned deleted files from indexed scan state"
        );
        if let Some(l) = logs {
            l.info(
                format!(
                    "Pruned {} deleted files from indexed state",
                    removed_files.len()
                ),
                None,
            );
        }
    }

    let needs_taint = cfg.scanner.mode == crate::utils::config::AnalysisMode::Full
        || cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint;

    // ── Pass 1: ensure summaries are up‑to‑date ──────────────────────────
    if needs_taint {
        if let Some(p) = progress {
            p.set_stage(ScanStage::Indexing);
        }
        if let Some(l) = logs {
            l.info(
                format!("Refreshing persisted summaries for {} files", files.len()),
                None,
            );
        }
        let _span = tracing::info_span!("pass1_indexed", files = files.len()).entered();
        let pb = make_progress_bar(
            files.len() as u64,
            "Pass 1: Extracting summaries",
            show_progress,
        );
        let pass1_start = std::time::Instant::now();
        let persist_errors = Arc::new(Mutex::new(Vec::new()));
        let skipped_files = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let scan_root_ref = scan_root.to_path_buf();
        let persist_errors_ref = Arc::clone(&persist_errors);
        let skipped_files_ref = Arc::clone(&skipped_files);
        let progress_ref = progress.cloned();
        files.par_iter().for_each_init(
            || Indexer::from_pool(project, &pool).expect("db pool"),
            |idx, path| {
                if let Some(p) = &progress_ref {
                    p.set_current_file(&path.to_string_lossy());
                }
                // Read once, hash once — use the hash for the change check
                // to avoid a second file read inside should_scan.
                if let Ok(bytes) = std::fs::read(path) {
                    let hash = Indexer::digest_bytes(&bytes);
                    let needs_scan = idx.should_scan_with_hash(path, &hash).unwrap_or(true);
                    if needs_scan {
                        match extract_all_summaries_from_bytes(
                            &bytes,
                            path,
                            cfg,
                            Some(&scan_root_ref),
                        ) {
                            Ok((func_sums, ssa_sums)) => {
                                if let Some(p) = &progress_ref {
                                    p.inc_parsed(1);
                                    if let Some(lang) = func_sums.first().map(|s| s.lang.as_str()) {
                                        p.record_language(lang);
                                    }
                                }
                                if let Err(e) =
                                    idx.replace_summaries_for_file(path, &hash, &func_sums)
                                {
                                    record_persist_error(
                                        &persist_errors_ref,
                                        format!("function summaries {}: {e}", path.display()),
                                    );
                                }
                                // Persist SSA summaries with full FuncKey metadata
                                if !ssa_sums.is_empty() {
                                    let lang_slug = func_sums
                                        .first()
                                        .map(|s| s.lang.clone())
                                        .unwrap_or_default();
                                    let namespace = crate::symbol::normalize_namespace(
                                        &path.to_string_lossy(),
                                        Some(&scan_root_ref.to_string_lossy()),
                                    );
                                    let ssa_rows: Vec<_> = ssa_sums
                                        .into_iter()
                                        .map(|(name, arity, sum)| {
                                            (name, arity, lang_slug.clone(), namespace.clone(), sum)
                                        })
                                        .collect();
                                    if let Err(e) =
                                        idx.replace_ssa_summaries_for_file(path, &hash, &ssa_rows)
                                    {
                                        record_persist_error(
                                            &persist_errors_ref,
                                            format!("SSA summaries {}: {e}", path.display()),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("pass 1: {}: {e}", path.display());
                            }
                        }
                    } else {
                        skipped_files_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(p) = &progress_ref {
                            p.inc_skipped(1);
                        }
                    }
                } else {
                    tracing::warn!("pass 1: cannot read {}", path.display());
                }
                pb.inc(1);
            },
        );
        pb.finish_and_clear();
        let skipped = skipped_files.load(std::sync::atomic::Ordering::Relaxed);
        if let Some(p) = progress {
            p.set_files_skipped(skipped);
            p.record_pass1_ms(pass1_start.elapsed().as_millis() as u64);
        }
        if let Some(m) = metrics {
            m.summaries_reused
                .store(skipped, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(l) = logs {
            l.info(
                format!(
                    "Indexed pass 1 complete: {} refreshed, {} reused",
                    files.len().saturating_sub(skipped as usize),
                    skipped
                ),
                None,
            );
        }
        fail_if_persist_errors("Pass 1", persist_errors)?;
    }

    // ── Load global summaries ────────────────────────────────────────────
    let root_str = scan_root.to_string_lossy();
    let global_summaries: Option<GlobalSummaries> = if needs_taint {
        if let Some(p) = progress {
            p.set_stage(ScanStage::LoadingSummaries);
        }
        let _span = tracing::info_span!("load_summaries_db").entered();
        let idx = Indexer::from_pool(project, &pool)?;
        let all = idx.load_all_summaries()?;
        tracing::info!(summaries = all.len(), "loaded cross-file summaries from DB");
        let mut gs = summary::merge_summaries(all, Some(&root_str));

        // Load and insert SSA summaries
        let ssa_rows = idx.load_all_ssa_summaries()?;
        let ssa_count = ssa_rows.len();
        if !ssa_rows.is_empty() {
            tracing::info!(
                ssa_summaries = ssa_rows.len(),
                "loaded SSA summaries from DB"
            );
            for (file_path, name, lang_str, arity, namespace, ssa_sum) in ssa_rows {
                let lang =
                    crate::symbol::Lang::from_slug(&lang_str).unwrap_or(crate::symbol::Lang::Rust);
                // Use persisted namespace; fall back to normalized file_path
                let ns = if namespace.is_empty() {
                    crate::symbol::normalize_namespace(&file_path, Some(&root_str))
                } else {
                    namespace
                };
                let key = crate::symbol::FuncKey {
                    lang,
                    namespace: ns,
                    name,
                    arity: if arity >= 0 {
                        Some(arity as usize)
                    } else {
                        None
                    },
                };
                gs.insert_ssa(key, ssa_sum);
            }
        }
        if let Some(l) = logs {
            l.info(
                format!(
                    "Loaded {} coarse summaries and {} SSA summaries from DB",
                    gs.snapshot_caps().len(),
                    ssa_count
                ),
                None,
            );
        }

        Some(gs)
    } else {
        None
    };

    if !needs_taint {
        // ── AST-only: existing parallel scan with caching ────────────────
        if let Some(p) = progress {
            p.set_stage(ScanStage::Analyzing);
        }
        if let Some(l) = logs {
            l.info("Starting AST-only indexed analysis", None);
        }
        let pass2_start = std::time::Instant::now();
        let _span = tracing::info_span!("pass2_indexed_ast_only").entered();
        let pb2 = make_progress_bar(
            files.len() as u64,
            "Pass 2: Running analysis",
            show_progress,
        );
        let diag_map: DashMap<String, Vec<Diag>> = DashMap::new();
        let persist_errors = Arc::new(Mutex::new(Vec::new()));
        let skipped_files = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let persist_errors_ref = Arc::clone(&persist_errors);
        let skipped_files_ref = Arc::clone(&skipped_files);
        let progress_ref = progress.cloned();
        files.into_par_iter().for_each_init(
            || Indexer::from_pool(project, &pool).expect("db pool"),
            |idx, path| {
                if let Some(p) = &progress_ref {
                    p.set_current_file(&path.to_string_lossy());
                }
                let bytes_opt = std::fs::read(&path).ok();
                let hash = bytes_opt.as_ref().map(|b| Indexer::digest_bytes(b));

                let needs_scan = match (&hash, &bytes_opt) {
                    (Some(h), _) => idx.should_scan_with_hash(&path, h).unwrap_or(true),
                    _ => true,
                };

                let mut diags = if needs_scan {
                    if let Some(p) = &progress_ref {
                        p.inc_parsed(1);
                        p.inc_analyzed(1);
                    }
                    let d = match &bytes_opt {
                        Some(bytes) => run_rules_on_bytes(bytes, &path, cfg, None, Some(scan_root))
                            .unwrap_or_default(),
                        None => {
                            run_rules_on_file(&path, cfg, None, Some(scan_root)).unwrap_or_default()
                        }
                    };

                    let file_id = match &hash {
                        Some(h) => idx.upsert_file_with_hash(&path, h),
                        None => idx.upsert_file(&path),
                    };
                    match file_id {
                        Ok(file_id) => {
                            if let Err(e) = idx.replace_issues(
                                file_id,
                                d.iter().map(|d| IssueRow {
                                    rule_id: &d.id,
                                    severity: d.severity.as_db_str(),
                                    line: d.line as i64,
                                    col: d.col as i64,
                                }),
                            ) {
                                record_persist_error(
                                    &persist_errors_ref,
                                    format!("issues {}: {e}", path.display()),
                                );
                            }
                        }
                        Err(e) => {
                            record_persist_error(
                                &persist_errors_ref,
                                format!("file row {}: {e}", path.display()),
                            );
                        }
                    }
                    d
                } else {
                    skipped_files_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Some(p) = &progress_ref {
                        p.inc_skipped(1);
                    }
                    idx.get_issues_from_file(&path).unwrap_or_default()
                };

                // AST-only: drop taint/cfg findings
                diags.retain(|d| !d.id.starts_with("taint") && !d.id.starts_with("cfg-"));

                if !diags.is_empty() {
                    diag_map
                        .entry(path.to_string_lossy().to_string())
                        .or_default()
                        .append(&mut diags);
                }
                pb2.inc(1);
            },
        );
        pb2.finish_and_clear();
        let skipped = skipped_files.load(std::sync::atomic::Ordering::Relaxed);
        if let Some(p) = progress {
            p.set_files_skipped(skipped);
            p.record_pass2_ms(pass2_start.elapsed().as_millis() as u64);
            p.set_stage(ScanStage::PostProcessing);
        }
        if let Some(m) = metrics {
            m.summaries_reused
                .store(skipped, std::sync::atomic::Ordering::Relaxed);
        }
        fail_if_persist_errors("AST-only pass 2", persist_errors)?;

        let mut diags: Vec<Diag> = diag_map.into_iter().flat_map(|(_, v)| v).collect();
        let post_process_start = std::time::Instant::now();
        post_process_diags(&mut diags, cfg);
        if let Some(p) = progress {
            p.record_post_process_ms(post_process_start.elapsed().as_millis() as u64);
            p.set_stage(ScanStage::Complete);
        }
        if let Some(l) = logs {
            l.info(
                format!(
                    "AST-only indexed scan complete in {}ms: {} findings, {} reused files",
                    pass2_start.elapsed().as_millis(),
                    diags.len(),
                    skipped
                ),
                None,
            );
        }
        return Ok(diags);
    }

    // ── Taint mode: build call graph + topo-ordered pass 2 ────────────
    let mut global_summaries = global_summaries.unwrap();
    if let Some(p) = progress {
        p.set_stage(ScanStage::BuildingCallGraph);
    }
    let cg_start = std::time::Instant::now();
    let (call_graph, cg_analysis) = build_and_analyse_call_graph(&global_summaries);
    log_unresolved_callees(&call_graph);
    if let Some(p) = progress {
        p.record_call_graph_ms(cg_start.elapsed().as_millis() as u64);
    }
    if let Some(m) = metrics {
        m.call_edges.store(
            call_graph.graph.edge_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.functions_analyzed.store(
            call_graph.graph.node_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.unresolved_calls.store(
            (call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len()) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Call graph built in {}ms: {} nodes, {} edges, {} unresolved",
                cg_start.elapsed().as_millis(),
                call_graph.graph.node_count(),
                call_graph.graph.edge_count(),
                call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len(),
            ),
            None,
        );
    }

    let (batches, orphans) = crate::callgraph::scc_file_batches_with_metadata(
        &call_graph,
        &cg_analysis,
        &files,
        scan_root,
    );
    tracing::info!(
        batches = batches.len(),
        orphan_files = orphans.len(),
        "topo-ordered file batches computed (indexed)"
    );
    if let Some(l) = logs {
        l.info(
            format!(
                "Topo-ordered indexed analysis plan: {} batches, {} orphan files",
                batches.len(),
                orphans.len()
            ),
            None,
        );
    }

    let _span = tracing::info_span!("pass2_indexed").entered();
    if let Some(p) = progress {
        p.set_stage(ScanStage::Analyzing);
        p.set_batches_total(batches.len() as u64 + u64::from(!orphans.is_empty()));
    }
    let pass2_start = std::time::Instant::now();
    let pb2 = make_progress_bar(
        files.len() as u64,
        "Pass 2: Running analysis",
        show_progress,
    );

    let topo_diags = run_topo_batches(
        &batches,
        &orphans,
        &mut global_summaries,
        cfg,
        Some(scan_root),
        &pb2,
        progress,
        logs,
    );
    pb2.finish_and_clear();
    if let Some(p) = progress {
        p.record_pass2_ms(pass2_start.elapsed().as_millis() as u64);
        p.set_stage(ScanStage::PostProcessing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Indexed pass 2 complete in {}ms: {} raw findings",
                pass2_start.elapsed().as_millis(),
                topo_diags.len()
            ),
            None,
        );
    }

    // Persist issues to DB after topo analysis, grouped by file.
    {
        let mut by_file: HashMap<&str, Vec<&Diag>> = HashMap::new();
        for d in &topo_diags {
            by_file.entry(&d.path).or_default().push(d);
        }
        let mut idx = Indexer::from_pool(project, &pool)?;
        for path in &files {
            if !path.exists() {
                idx.remove_file_and_related(path)?;
                continue;
            }

            let file_id = idx.upsert_file(path)?;
            let empty: [&Diag; 0] = [];
            let file_diags = by_file
                .get(path.to_string_lossy().as_ref())
                .map(Vec::as_slice)
                .unwrap_or(&empty);

            idx.replace_issues(
                file_id,
                file_diags.iter().map(|d| IssueRow {
                    rule_id: &d.id,
                    severity: d.severity.as_db_str(),
                    line: d.line as i64,
                    col: d.col as i64,
                }),
            )?;
        }
    }
    if let Some(l) = logs {
        l.info(
            format!("Persisted findings for {} files", files.len()),
            None,
        );
    }

    let mut diags = topo_diags;

    // Apply mode filter for taint-only mode.
    if cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint {
        diags.retain(|d| d.id.starts_with("taint") || d.id.starts_with("cfg-"));
    }

    let post_process_start = std::time::Instant::now();
    post_process_diags(&mut diags, cfg);
    if let Some(p) = progress {
        p.record_post_process_ms(post_process_start.elapsed().as_millis() as u64);
        p.set_stage(ScanStage::Complete);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Indexed scan complete in {}ms: {} final findings",
                pass2_start.elapsed().as_millis(),
                diags.len()
            ),
            None,
        );
    }

    Ok(diags)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Low-noise prioritization pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Rules eligible for rollup grouping (high-frequency, low-signal patterns).
const ROLLUP_RULES: &[&str] = &[
    "rs.quality.unwrap",
    "rs.quality.expect",
    "rs.quality.panic_macro",
];

/// Apply category filtering, rollup grouping, and LOW budgets to reduce noise.
///
/// Modifies `diags` in place and returns suppression statistics for the footer.
pub(crate) fn prioritize(
    diags: &mut Vec<Diag>,
    config: &crate::utils::config::OutputConfig,
    show_instances: Option<&str>,
) -> SuppressionStats {
    let mut stats = SuppressionStats {
        quality_dropped: 0,
        low_budget_dropped: 0,
        max_results_dropped: 0,
        include_quality: config.include_quality,
        show_all: config.show_all,
        max_low: config.max_low,
        max_low_per_file: config.max_low_per_file,
        max_low_per_rule: config.max_low_per_rule,
    };

    if config.show_all {
        return stats;
    }

    // ── 1. Category filter: drop Quality unless include_quality ────────
    if !config.include_quality {
        let before = diags.len();
        diags.retain(|d| d.category != FindingCategory::Quality);
        stats.quality_dropped = before - diags.len();
    }

    // ── 2. Rollup: group high-frequency LOW Quality findings ──────────
    rollup_findings(diags, config, show_instances);

    // ── 3. LOW budgets ────────────────────────────────────────────────
    apply_low_budgets(diags, config, &mut stats);

    // ── 4. Global max_results with severity stability ─────────────────
    if let Some(max) = config.max_results {
        let max = max as usize;
        if diags.len() > max {
            // Partition by severity priority: High first, then Medium, then Low
            let high_count = diags
                .iter()
                .filter(|d| d.severity == Severity::High)
                .count();
            let med_count = diags
                .iter()
                .filter(|d| d.severity == Severity::Medium)
                .count();

            let take = if high_count >= max {
                // Only High fits
                diags.retain(|d| d.severity == Severity::High);
                diags.truncate(max);
                max
            } else if high_count + med_count >= max {
                // High + some Medium
                let med_slots = max - high_count;
                let mut med_seen = 0usize;
                diags.retain(|d| {
                    if d.severity == Severity::High {
                        true
                    } else if d.severity == Severity::Medium && med_seen < med_slots {
                        med_seen += 1;
                        true
                    } else {
                        false
                    }
                });
                max
            } else {
                // High + Medium + some Low
                let low_slots = max - high_count - med_count;
                let mut low_seen = 0usize;
                diags.retain(|d| {
                    if d.severity == Severity::High || d.severity == Severity::Medium {
                        true
                    } else if low_seen < low_slots {
                        low_seen += 1;
                        true
                    } else {
                        false
                    }
                });
                max
            };
            let original_total = high_count + med_count + diags.len(); // approximate
            stats.max_results_dropped = original_total.saturating_sub(take);
        }
    }

    stats
}

/// Group eligible LOW Quality findings into rollup Diags.
fn rollup_findings(
    diags: &mut Vec<Diag>,
    config: &crate::utils::config::OutputConfig,
    show_instances: Option<&str>,
) {
    use std::collections::HashMap;

    // Identify which diags are eligible for rollup
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (i, d) in diags.iter().enumerate() {
        if d.severity != Severity::Low {
            continue;
        }
        if d.category != FindingCategory::Quality {
            continue;
        }
        if !ROLLUP_RULES.contains(&d.id.as_str()) {
            continue;
        }
        if show_instances == Some(d.id.as_str()) {
            continue;
        }
        groups
            .entry((d.path.clone(), d.id.clone()))
            .or_default()
            .push(i);
    }

    // Only rollup groups with more than 1 occurrence
    let mut to_remove: Vec<usize> = Vec::new();
    let mut rollups: Vec<Diag> = Vec::new();

    for ((_path, _rule_id), mut indices) in groups {
        if indices.len() <= 1 {
            continue;
        }

        // Sort by (line, col) for deterministic canonical location
        indices.sort_by_key(|&i| (diags[i].line, diags[i].col));

        let canonical_idx = indices[0];
        let total = indices.len();

        // Collect example locations (first N)
        let examples: Vec<Location> = indices
            .iter()
            .take(config.rollup_examples as usize)
            .map(|&i| Location {
                line: diags[i].line,
                col: diags[i].col,
            })
            .collect();

        // Build rollup Diag from canonical
        let canonical = &diags[canonical_idx];
        let rollup_diag = Diag {
            path: canonical.path.clone(),
            line: canonical.line,
            col: canonical.col,
            severity: canonical.severity,
            id: canonical.id.clone(),
            category: canonical.category,
            path_validated: false,
            guard_kind: None,
            message: canonical.message.clone(),
            labels: vec![],
            confidence: canonical.confidence,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: Some(RollupData {
                count: total,
                occurrences: examples,
            }),
        };

        rollups.push(rollup_diag);
        to_remove.extend(indices);
    }

    if to_remove.is_empty() {
        return;
    }

    // Remove originals (in reverse order to preserve indices)
    to_remove.sort_unstable();
    to_remove.dedup();
    for &i in to_remove.iter().rev() {
        diags.remove(i);
    }

    // Sort rollups for deterministic output: by (path, id, line)
    rollups.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.id.cmp(&b.id))
            .then(a.line.cmp(&b.line))
    });

    // Add rollup diags
    diags.extend(rollups);
}

/// Enforce per-file, per-rule, and total LOW budgets.
fn apply_low_budgets(
    diags: &mut Vec<Diag>,
    config: &crate::utils::config::OutputConfig,
    stats: &mut SuppressionStats,
) {
    use std::collections::HashMap;

    let mut per_file: HashMap<String, u32> = HashMap::new();
    let mut per_rule: HashMap<String, u32> = HashMap::new();
    let mut total_low: u32 = 0;

    let before = diags.len();
    diags.retain(|d| {
        // High/Medium always kept
        if d.severity != Severity::Low {
            return true;
        }

        // Check per-file budget
        let file_count = per_file.entry(d.path.clone()).or_insert(0);
        if *file_count >= config.max_low_per_file {
            return false;
        }

        // Check per-rule budget
        let rule_count = per_rule.entry(d.id.clone()).or_insert(0);
        if *rule_count >= config.max_low_per_rule {
            return false;
        }

        // Check total budget
        if total_low >= config.max_low {
            return false;
        }

        *file_count += 1;
        *rule_count += 1;
        total_low += 1;
        true
    });
    stats.low_budget_dropped = before - diags.len();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Inline suppression application
// ─────────────────────────────────────────────────────────────────────────────

/// Apply inline `nyx:ignore` / `nyx:ignore-next-line` suppressions to `diags`.
///
/// For each unique file path in the diagnostics, the source file is read once,
/// suppression directives are parsed, and matching findings are marked as
/// suppressed.
fn apply_suppressions(diags: &mut [Diag]) {
    use std::collections::HashMap;

    // Group diag indices by path (clone path strings to avoid borrowing diags).
    let mut by_path: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, d) in diags.iter().enumerate() {
        by_path.entry(d.path.clone()).or_default().push(i);
    }

    for (path, indices) in &by_path {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        let file_path = Path::new(path.as_str());
        let index = crate::suppress::parse_inline_suppressions(file_path, &source);
        if index.is_empty() {
            continue;
        }
        for &i in indices {
            if let Some(meta) = index.check(diags[i].line, &diags[i].id) {
                diags[i].suppressed = true;
                diags[i].suppression = Some(meta);
            }
        }
    }
}

#[test]
fn scan_with_index_parallel_uses_existing_index_without_rescanning() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    std::fs::create_dir(&project_dir).unwrap();
    std::fs::write(project_dir.join("foo.txt"), "abc").unwrap();

    let (project_name, db_path) = get_project_info(&project_dir, td.path()).unwrap();
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg, false)
        .unwrap();

    let pool = Indexer::init(&db_path).unwrap();

    assert_eq!(
        Indexer::from_pool(&project_name, &pool)
            .unwrap()
            .get_files(&project_name)
            .unwrap()
            .len(),
        1
    );

    let diags =
        scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false, &project_dir)
            .expect("scan should succeed");

    assert!(diags.is_empty());
}

#[test]
fn scan_with_index_parallel_discovers_new_files_after_index_build() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    std::fs::create_dir(&project_dir).unwrap();
    std::fs::write(project_dir.join("foo.txt"), "abc").unwrap();

    let (project_name, db_path) = get_project_info(&project_dir, td.path()).unwrap();
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg, false)
        .unwrap();

    std::fs::write(project_dir.join("bar.txt"), "xyz").unwrap();

    let pool = Indexer::init(&db_path).unwrap();
    scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false, &project_dir)
        .expect("scan should succeed");

    let files = Indexer::from_pool(&project_name, &pool)
        .unwrap()
        .get_files(&project_name)
        .unwrap();
    assert_eq!(
        files.len(),
        2,
        "new files should be discovered without rebuild"
    );
}

#[test]
fn scan_with_index_parallel_clears_stale_issues_when_file_becomes_clean() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    std::fs::create_dir(&project_dir).unwrap();
    let app = project_dir.join("app.js");
    std::fs::write(
        &app,
        r#"
function run() {
  const cmd = process.env.CMD;
  eval(cmd);
}
"#,
    )
    .unwrap();

    let (project_name, db_path) = get_project_info(&project_dir, td.path()).unwrap();
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg, false)
        .unwrap();

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool(&project_name, &pool).unwrap();
    assert!(
        !idx.get_issues_from_file(&app).unwrap().is_empty(),
        "the initial indexed build should persist at least one issue"
    );

    std::fs::write(
        &app,
        r#"
function run() {
  const cmd = "safe";
  console.log(cmd);
}
"#,
    )
    .unwrap();

    let diags =
        scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false, &project_dir)
            .expect("scan should succeed");
    assert!(
        diags.is_empty(),
        "the cleaned file should no longer report findings"
    );

    let idx = Indexer::from_pool(&project_name, &pool).unwrap();
    assert!(
        idx.get_issues_from_file(&app).unwrap().is_empty(),
        "DB issues should be cleared when a file becomes clean"
    );
}

#[test]
fn severity_filter_applied_at_output_stage() {
    // Simulate: findings start as High, get downgraded to Medium by nonprod logic,
    // then --severity HIGH should filter them out.
    let diags = vec![
        Diag {
            path: "tests/test.py".into(),
            line: 1,
            col: 1,
            severity: Severity::Medium, // was High, downgraded
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
        },
        Diag {
            path: "src/main.rs".into(),
            line: 10,
            col: 5,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
        },
    ];

    let filter = SeverityFilter::parse("HIGH").unwrap();
    let filtered: Vec<_> = diags
        .into_iter()
        .filter(|d| filter.matches(d.severity))
        .collect();

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].severity, Severity::High);
    assert_eq!(filtered[0].path, "src/main.rs");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Prioritization pipeline tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod prioritize_tests {
    use super::*;
    use crate::utils::config::OutputConfig;

    fn make_diag(
        path: &str,
        line: usize,
        severity: Severity,
        id: &str,
        cat: FindingCategory,
    ) -> Diag {
        Diag {
            path: path.into(),
            line,
            col: 1,
            severity,
            id: id.into(),
            category: cat,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
        }
    }

    fn default_config() -> OutputConfig {
        OutputConfig::default()
    }

    #[test]
    fn quality_dropped_by_default() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::High,
                "taint-flow",
                FindingCategory::Security,
            ),
        ];
        let stats = prioritize(&mut diags, &default_config(), None);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].id, "taint-flow");
        assert_eq!(stats.quality_dropped, 1);
    }

    #[test]
    fn quality_kept_with_include_quality() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::High,
                "taint-flow",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 2);
        assert_eq!(stats.quality_dropped, 0);
    }

    #[test]
    fn show_all_disables_everything() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                3,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.show_all = true;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 3); // no filtering, no rollup
        assert_eq!(stats.quality_dropped, 0);
        assert_eq!(stats.low_budget_dropped, 0);
        assert!(diags.iter().all(|d| d.rollup.is_none()));
    }

    #[test]
    fn rollup_groups_by_file_and_rule() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                10,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                20,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                30,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "b.rs",
                5,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "b.rs",
                15,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        let _stats = prioritize(&mut diags, &cfg, None);

        // Should have 2 rollup diags (one per file)
        let rollups: Vec<_> = diags.iter().filter(|d| d.rollup.is_some()).collect();
        assert_eq!(rollups.len(), 2);

        let a_rollup = rollups.iter().find(|d| d.path == "a.rs").unwrap();
        assert_eq!(a_rollup.rollup.as_ref().unwrap().count, 3);

        let b_rollup = rollups.iter().find(|d| d.path == "b.rs").unwrap();
        assert_eq!(b_rollup.rollup.as_ref().unwrap().count, 2);
    }

    #[test]
    fn rollup_examples_limited() {
        let mut diags: Vec<Diag> = (1..=20)
            .map(|i| {
                make_diag(
                    "a.rs",
                    i,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                )
            })
            .collect();
        let mut cfg = default_config();
        cfg.include_quality = true;
        cfg.rollup_examples = 3;
        let _stats = prioritize(&mut diags, &cfg, None);

        let rollup = diags.iter().find(|d| d.rollup.is_some()).unwrap();
        assert_eq!(rollup.rollup.as_ref().unwrap().count, 20);
        assert_eq!(rollup.rollup.as_ref().unwrap().occurrences.len(), 3);
    }

    #[test]
    fn rollup_canonical_is_first_sorted() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                50,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                10,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                30,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        let _stats = prioritize(&mut diags, &cfg, None);

        let rollup = diags.iter().find(|d| d.rollup.is_some()).unwrap();
        assert_eq!(rollup.line, 10); // canonical = first sorted
    }

    #[test]
    fn low_budget_per_file() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "some-rule",
                FindingCategory::Security,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Low,
                "some-rule-2",
                FindingCategory::Security,
            ),
            make_diag(
                "b.rs",
                1,
                Severity::Low,
                "some-rule",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.max_low_per_file = 1;
        cfg.max_low = 100;
        cfg.max_low_per_rule = 100;
        let stats = prioritize(&mut diags, &cfg, None);
        // a.rs: only 1 LOW kept, b.rs: 1 LOW kept
        assert_eq!(diags.len(), 2);
        assert_eq!(stats.low_budget_dropped, 1);
    }

    #[test]
    fn low_budget_per_rule() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rule-x",
                FindingCategory::Security,
            ),
            make_diag(
                "b.rs",
                1,
                Severity::Low,
                "rule-x",
                FindingCategory::Security,
            ),
            make_diag(
                "c.rs",
                1,
                Severity::Low,
                "rule-x",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.max_low_per_file = 100;
        cfg.max_low = 100;
        cfg.max_low_per_rule = 2;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 2);
        assert_eq!(stats.low_budget_dropped, 1);
    }

    #[test]
    fn low_budget_total() {
        let mut diags: Vec<Diag> = (1..=5)
            .map(|i| {
                make_diag(
                    &format!("f{i}.rs"),
                    1,
                    Severity::Low,
                    &format!("rule-{i}"),
                    FindingCategory::Security,
                )
            })
            .collect();
        let mut cfg = default_config();
        cfg.max_low_per_file = 100;
        cfg.max_low_per_rule = 100;
        cfg.max_low = 3;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 3);
        assert_eq!(stats.low_budget_dropped, 2);
    }

    #[test]
    fn high_medium_never_dropped_by_low_budget() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::High,
                "vuln-1",
                FindingCategory::Security,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Medium,
                "vuln-2",
                FindingCategory::Security,
            ),
            make_diag(
                "a.rs",
                3,
                Severity::Low,
                "vuln-3",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.max_low = 0;
        cfg.max_low_per_file = 0;
        cfg.max_low_per_rule = 0;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 2); // High + Medium kept
        assert!(diags.iter().all(|d| d.severity != Severity::Low));
        assert_eq!(stats.low_budget_dropped, 1);
    }

    #[test]
    fn rollup_counts_as_one_for_budget() {
        // 10 unwrap findings in same file → 1 rollup → counts as 1 LOW
        let mut diags: Vec<Diag> = (1..=10)
            .map(|i| {
                make_diag(
                    "a.rs",
                    i,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                )
            })
            .collect();
        // Add another LOW finding from a different rule
        diags.push(make_diag(
            "a.rs",
            100,
            Severity::Low,
            "other-rule",
            FindingCategory::Security,
        ));

        let mut cfg = default_config();
        cfg.include_quality = true;
        cfg.max_low_per_file = 2; // allow 2 per file
        cfg.max_low = 100;
        cfg.max_low_per_rule = 100;
        let _stats = prioritize(&mut diags, &cfg, None);

        // Should have rollup (1) + other-rule (1) = 2
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn show_instances_bypasses_rollup_for_rule() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                3,
                Severity::Low,
                "rs.quality.expect",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                4,
                Severity::Low,
                "rs.quality.expect",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        cfg.max_low = 100;
        cfg.max_low_per_file = 100;
        cfg.max_low_per_rule = 100;
        let _stats = prioritize(&mut diags, &cfg, Some("rs.quality.unwrap"));

        // unwrap not rolled up (2 individual), expect rolled up (1 rollup)
        let unwrap_count = diags.iter().filter(|d| d.id == "rs.quality.unwrap").count();
        let expect_rollup = diags
            .iter()
            .find(|d| d.id == "rs.quality.expect" && d.rollup.is_some());
        assert_eq!(unwrap_count, 2);
        assert!(expect_rollup.is_some());
    }

    #[test]
    fn json_includes_rollup_data() {
        let d = Diag {
            path: "a.rs".into(),
            line: 10,
            col: 1,
            severity: Severity::Low,
            id: "rs.quality.unwrap".into(),
            category: FindingCategory::Quality,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: Some(RollupData {
                count: 38,
                occurrences: vec![Location { line: 10, col: 1 }, Location { line: 20, col: 5 }],
            }),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"rollup\""));
        assert!(json.contains("\"count\":38"));
        assert!(json.contains("\"occurrences\""));
    }

    #[test]
    fn deterministic_output() {
        let make_diags = || {
            vec![
                make_diag(
                    "b.rs",
                    5,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
                make_diag(
                    "a.rs",
                    10,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
                make_diag(
                    "a.rs",
                    3,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
                make_diag(
                    "b.rs",
                    1,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
            ]
        };
        let mut cfg = default_config();
        cfg.include_quality = true;

        let mut d1 = make_diags();
        let mut d2 = make_diags();
        let _s1 = prioritize(&mut d1, &cfg, None);
        let _s2 = prioritize(&mut d2, &cfg, None);

        let j1 = serde_json::to_string(&d1).unwrap();
        let j2 = serde_json::to_string(&d2).unwrap();
        assert_eq!(j1, j2, "same input should produce same output");
    }
}
