pub(crate) use crate::ast::{
    analyse_file_fused, extract_summaries_from_bytes, run_rules_on_bytes, run_rules_on_file,
};
use crate::cli::{IndexMode, OutputFormat};
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::{Severity, SeverityFilter};
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
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

#[derive(Debug, Clone, serde::Serialize)]
pub struct Diag {
    pub path: String,
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub id: String,
    /// Whether the finding is guarded by a path validation predicate.
    /// Only set for taint findings; `false` for AST/CFG structural findings.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_kind: Option<String>,
    /// Optional human-readable message with additional context (e.g. state analysis details).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Structured evidence labels (e.g. Source, Sink) for console display.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,
    /// Confidence level (Low / Medium / High).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<crate::evidence::Confidence>,
    /// Structured evidence (source/sink spans, state transitions, notes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<crate::evidence::Evidence>,
    /// Attack-surface ranking score (higher = more exploitable / important).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank_score: Option<f64>,
    /// Breakdown of how the ranking score was computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank_reason: Option<Vec<(String, String)>>,
    /// Whether this finding was suppressed by an inline `nyx:ignore` directive.
    #[serde(skip_serializing_if = "is_false")]
    pub suppressed: bool,
    /// Metadata about the suppression directive, if suppressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<crate::suppress::SuppressionMeta>,
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
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;

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
        scan_with_index_parallel(&project_name, pool, config, show_progress)?
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
            print!("{}", crate::fmt::render_console(&diags, &project_name));
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
    // ── Collect file list ────────────────────────────────────────────────
    let all_paths: Vec<PathBuf> = {
        let _span = tracing::info_span!("walk_files").entered();
        let (rx, handle) = spawn_file_walker(root, cfg);
        // Drain the channel BEFORE joining the walker thread.
        // The channel is bounded, so joining first would deadlock once
        // the walker fills it and blocks on send.
        let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();
        if let Err(err) = handle.join() {
            tracing::error!("walker thread panicked: {:#?}", err);
        }
        paths
    };
    tracing::info!(file_count = all_paths.len(), "file walk complete");

    let needs_taint = cfg.scanner.mode == crate::utils::config::AnalysisMode::Full
        || cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint;

    if !needs_taint {
        // ── AST-only: single fused pass (no cross-file context needed) ──
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
                        vec![]
                    }
                };
                pb.inc(1);
                result
            })
            .collect();
        pb.finish_and_clear();

        if cfg.output.attack_surface_ranking {
            crate::rank::rank_diags(&mut diags);
        }
        for d in &mut diags {
            if d.confidence.is_none() {
                d.confidence = Some(crate::evidence::compute_confidence(d));
            }
        }
        if let Some(max) = cfg.output.max_results {
            diags.truncate(max as usize);
        }
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
                            for s in r.summaries {
                                let key = s.func_key(Some(&root_str));
                                local_gs.insert(key, s);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("pass 1: {}: {e}", path.display());
                        }
                    }
                } else {
                    tracing::warn!("pass 1: cannot read {}", path.display());
                }
                pb.inc(1);
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

    // ── Build call graph ────────────────────────────────────────────────
    {
        let _span = tracing::info_span!("build_call_graph").entered();
        // TODO: wire interop_edges from config/index when InteropEdge sources are implemented
        let call_graph = crate::callgraph::build_call_graph(&global_summaries, &[]);
        let cg_analysis = crate::callgraph::analyse(&call_graph);
        tracing::info!(
            nodes = call_graph.graph.node_count(),
            edges = call_graph.graph.edge_count(),
            unresolved_not_found = call_graph.unresolved_not_found.len(),
            unresolved_ambiguous = call_graph.unresolved_ambiguous.len(),
            sccs = cg_analysis.sccs.len(),
            "call graph built"
        );
    }

    // ── Pass 2: re-run with cross-file global summaries ──────────────────
    let mut diags: Vec<Diag> = {
        let _span = tracing::info_span!("pass2_analysis", files = all_paths.len()).entered();
        let pb = make_progress_bar(
            all_paths.len() as u64,
            "Pass 2: Running analysis",
            show_progress,
        );

        let result: Vec<Diag> = all_paths
            .par_iter()
            .flat_map_iter(|path| {
                let result = match run_rules_on_file(path, cfg, Some(&global_summaries), Some(root))
                {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("pass 2: {}: {e}", path.display());
                        vec![]
                    }
                };
                pb.inc(1);
                result
            })
            .collect();
        pb.finish_and_clear();
        result
    };
    tracing::info!(diags = diags.len(), "pass 2 complete");

    if cfg.output.attack_surface_ranking {
        crate::rank::rank_diags(&mut diags);
    }
    for d in &mut diags {
        if d.confidence.is_none() {
            d.confidence = Some(crate::evidence::compute_confidence(d));
        }
    }
    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
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
) -> NyxResult<Vec<Diag>> {
    let files = {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.get_files(project)?
    };

    let needs_taint = cfg.scanner.mode == crate::utils::config::AnalysisMode::Full
        || cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint;

    // ── Pass 1: ensure summaries are up‑to‑date ──────────────────────────
    if needs_taint {
        let _span = tracing::info_span!("pass1_indexed", files = files.len()).entered();
        let pb = make_progress_bar(
            files.len() as u64,
            "Pass 1: Extracting summaries",
            show_progress,
        );

        files.par_iter().for_each_init(
            || Indexer::from_pool(project, &pool).expect("db pool"),
            |idx, path| {
                // Read once, hash once — use the hash for the change check
                // to avoid a second file read inside should_scan.
                if let Ok(bytes) = std::fs::read(path) {
                    let hash = Indexer::digest_bytes(&bytes);
                    let needs_scan = idx.should_scan_with_hash(path, &hash).unwrap_or(true);
                    if needs_scan {
                        match extract_summaries_from_bytes(&bytes, path, cfg) {
                            Ok(sums) => {
                                idx.replace_summaries_for_file(path, &hash, &sums).ok();
                            }
                            Err(e) => {
                                tracing::warn!("pass 1: {}: {e}", path.display());
                            }
                        }
                    }
                } else {
                    tracing::warn!("pass 1: cannot read {}", path.display());
                }
                pb.inc(1);
            },
        );
        pb.finish_and_clear();
    }

    // ── Load global summaries ────────────────────────────────────────────
    let global_summaries: Option<GlobalSummaries> = if needs_taint {
        let _span = tracing::info_span!("load_summaries_db").entered();
        let idx = Indexer::from_pool(project, &pool)?;
        let all = idx.load_all_summaries()?;
        tracing::info!(summaries = all.len(), "loaded cross-file summaries from DB");
        Some(summary::merge_summaries(all, None))
    } else {
        None
    };

    // ── Build call graph ────────────────────────────────────────────────
    if let Some(ref gs) = global_summaries {
        let _span = tracing::info_span!("build_call_graph").entered();
        // TODO: wire interop_edges from config/index when InteropEdge sources are implemented
        let call_graph = crate::callgraph::build_call_graph(gs, &[]);
        let cg_analysis = crate::callgraph::analyse(&call_graph);
        tracing::info!(
            nodes = call_graph.graph.node_count(),
            edges = call_graph.graph.edge_count(),
            unresolved_not_found = call_graph.unresolved_not_found.len(),
            unresolved_ambiguous = call_graph.unresolved_ambiguous.len(),
            sccs = cg_analysis.sccs.len(),
            "call graph built"
        );
    }

    // ── Pass 2: full analysis ────────────────────────────────────────────
    let _span = tracing::info_span!("pass2_indexed").entered();
    let pb2 = make_progress_bar(
        files.len() as u64,
        "Pass 2: Running analysis",
        show_progress,
    );
    let diag_map: DashMap<String, Vec<Diag>> = DashMap::new();

    files.into_par_iter().for_each_init(
        || Indexer::from_pool(project, &pool).expect("db pool"),
        |idx, path| {
            // Read file once for both change-detection and analysis.
            let bytes_opt = std::fs::read(&path).ok();
            let hash = bytes_opt.as_ref().map(|b| Indexer::digest_bytes(b));

            // In pass 2 we always re-analyse when taint is enabled because
            // global summaries may have changed even if this file didn't.
            // For AST-only mode, we can still use the cached issues.
            let needs_scan = if needs_taint {
                true // conservative: always re-analyse in taint mode
            } else {
                match (&hash, &bytes_opt) {
                    (Some(h), _) => idx.should_scan_with_hash(&path, h).unwrap_or(true),
                    _ => true,
                }
            };

            let mut diags = if needs_scan {
                let d = match &bytes_opt {
                    Some(bytes) => {
                        run_rules_on_bytes(bytes, &path, cfg, global_summaries.as_ref(), None)
                            .unwrap_or_default()
                    }
                    None => run_rules_on_file(&path, cfg, global_summaries.as_ref(), None)
                        .unwrap_or_default(),
                };

                // Persist issues + update file record (use pre-computed hash)
                let file_id = match &hash {
                    Some(h) => idx.upsert_file_with_hash(&path, h).unwrap_or_default(),
                    None => idx.upsert_file(&path).unwrap_or_default(),
                };
                idx.replace_issues(
                    file_id,
                    d.iter().map(|d| IssueRow {
                        rule_id: &d.id,
                        severity: d.severity.as_db_str(),
                        line: d.line as i64,
                        col: d.col as i64,
                    }),
                )
                .ok();
                d
            } else {
                idx.get_issues_from_file(&path).unwrap_or_default()
            };

            match cfg.scanner.mode {
                crate::utils::config::AnalysisMode::Ast => {
                    diags.retain(|d| !d.id.starts_with("taint") && !d.id.starts_with("cfg-"));
                }
                crate::utils::config::AnalysisMode::Taint => {
                    diags.retain(|d| d.id.starts_with("taint") || d.id.starts_with("cfg-"));
                }
                crate::utils::config::AnalysisMode::Full => {}
            }

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

    let mut diags: Vec<Diag> = diag_map.into_iter().flat_map(|(_, v)| v).collect();

    if cfg.output.attack_surface_ranking {
        crate::rank::rank_diags(&mut diags);
    }
    for d in &mut diags {
        if d.confidence.is_none() {
            d.confidence = Some(crate::evidence::compute_confidence(d));
        }
    }
    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
    }

    Ok(diags)
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

    let diags = scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false)
        .expect("scan should succeed");

    assert!(diags.is_empty());
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
        },
        Diag {
            path: "src/main.rs".into(),
            line: 10,
            col: 5,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
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
