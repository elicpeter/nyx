pub(crate) use crate::ast::{extract_summaries_from_file, run_rules_on_file};
use crate::database::index::{Indexer, IssueRow};
use crate::errors::{NyxError, NyxResult};
use crate::patterns::Severity;
use crate::summary::{self, FuncSummary, GlobalSummaries};
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use console::style;
use dashmap::DashMap;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Diag {
    pub(crate) path: String,
    pub(crate) line: usize,
    pub(crate) col: usize,
    pub(crate) severity: Severity,
    pub(crate) id: String,
}

/// Entry point called by the CLI.
pub fn handle(
    path: &str,
    no_index: bool,
    rebuild_index: bool,
    format: String,
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;

    println!(
        "{} {}...\n",
        style("Checking").green().bold(),
        &project_name
    );

    let diags: Vec<Diag> = if no_index {
        scan_filesystem(&scan_path, config)?
    } else {
        if rebuild_index || !db_path.exists() {
            tracing::debug!("Scanning filesystem index filesystem");
            crate::commands::index::build_index(&project_name, &scan_path, &db_path, config)?;
        }

        let pool = Indexer::init(&db_path)?;
        scan_with_index_parallel(&project_name, pool, config)?
    };

    tracing::debug!("Found {:?} issues.", diags.len());

    if format == "console" || (format.is_empty() && config.output.default_format == "console") {
        tracing::debug!("Printing to console");
        let mut grouped: BTreeMap<&str, Vec<&Diag>> = BTreeMap::new();
        for d in &diags {
            grouped.entry(&d.path).or_default().push(d);
        }

        for (path, issues) in &grouped {
            println!("{}", style(path).blue().underlined());
            for d in issues {
                println!(
                    "  {:>4}:{:<4}  [{:}]  {:}",
                    d.line,
                    d.col,
                    d.severity,
                    style(&d.id).bold()
                );
            }
            println!();
        }

        println!(
            "{} '{}' generated {} issues.",
            style("warning").yellow().bold(),
            style(project_name).white().bold(),
            style(diags.len()).bold()
        );
        println!("\t");
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
fn scan_filesystem(root: &Path, cfg: &Config) -> NyxResult<Vec<Diag>> {
    // ── Collect file list ────────────────────────────────────────────────
    let (rx, handle) = spawn_file_walker(root, cfg);
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
    }
    let all_paths: Vec<PathBuf> = rx.into_iter().flatten().collect();

    // ── Pass 1: extract summaries ────────────────────────────────────────
    let needs_taint =
        cfg.scanner.mode == crate::utils::config::AnalysisMode::Full
            || cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint;

    let global_summaries: Option<GlobalSummaries> = if needs_taint {
        tracing::debug!("Pass 1: extracting function summaries from {} files", all_paths.len());
        let per_file: Mutex<Vec<FuncSummary>> = Mutex::new(Vec::new());

        all_paths.par_iter().for_each(|path| {
            match extract_summaries_from_file(path, cfg) {
                Ok(sums) if !sums.is_empty() => {
                    per_file.lock().unwrap().extend(sums);
                }
                Err(e) => {
                    tracing::warn!("pass 1: failed to summarise {}: {e}", path.display());
                }
                _ => {}
            }
        });

        let collected = per_file.into_inner().unwrap();
        tracing::debug!("Pass 1 complete: {} summaries collected", collected.len());
        Some(summary::merge_summaries(collected))
    } else {
        None
    };

    // ── Pass 2: full analysis with cross‑file context ────────────────────
    tracing::debug!("Pass 2: running full analysis on {} files", all_paths.len());
    let acc = Mutex::new(Vec::new());

    all_paths
        .par_iter()
        .try_for_each(|path| {
            let mut local = run_rules_on_file(path, cfg, global_summaries.as_ref())?;
            acc.lock().unwrap().append(&mut local);
            Ok::<(), NyxError>(())
        })?;

    let mut diags = acc.into_inner()?;
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
) -> NyxResult<Vec<Diag>> {
    let files = {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.get_files(project)?
    };

    let needs_taint =
        cfg.scanner.mode == crate::utils::config::AnalysisMode::Full
            || cfg.scanner.mode == crate::utils::config::AnalysisMode::Taint;

    // ── Pass 1: ensure summaries are up‑to‑date ──────────────────────────
    if needs_taint {
        tracing::debug!("Pass 1 (indexed): updating summaries for {} files", files.len());

        files.par_iter().for_each_init(
            || Indexer::from_pool(project, &pool).expect("db pool"),
            |idx, path| {
                let needs_scan = idx.should_scan(path).unwrap_or(true);
                if !needs_scan {
                    return; // summaries in DB are still valid
                }

                match extract_summaries_from_file(path, cfg) {
                    Ok(sums) => {
                        let hash = match std::fs::read(path) {
                            Ok(bytes) => {
                                let mut h = blake3::Hasher::new();
                                h.update(&bytes);
                                h.finalize().as_bytes().to_vec()
                            }
                            Err(_) => vec![],
                        };
                        idx.replace_summaries_for_file(path, &hash, &sums).ok();
                    }
                    Err(e) => {
                        tracing::warn!("pass 1: {}: {e}", path.display());
                    }
                }
            },
        );
    }

    // ── Load global summaries ────────────────────────────────────────────
    let global_summaries: Option<GlobalSummaries> = if needs_taint {
        let idx = Indexer::from_pool(project, &pool)?;
        let all = idx.load_all_summaries()?;
        tracing::debug!("Loaded {} cross-file summaries from DB", all.len());
        Some(summary::merge_summaries(all))
    } else {
        None
    };

    // ── Pass 2: full analysis ────────────────────────────────────────────
    let diag_map: DashMap<String, Vec<Diag>> = DashMap::new();

    files.into_par_iter().for_each_init(
        || Indexer::from_pool(project, &pool).expect("db pool"),
        |idx, path| {
            // In pass 2 we always re-analyse when taint is enabled because
            // global summaries may have changed even if this file didn't.
            // For AST-only mode, we can still use the cached issues.
            let needs_scan = if needs_taint {
                true // conservative: always re-analyse in taint mode
            } else {
                idx.should_scan(&path).unwrap_or(true)
            };

            let mut diags = if needs_scan {
                let d = run_rules_on_file(&path, cfg, global_summaries.as_ref())
                    .unwrap_or_default();

                // Persist issues + update file record
                let file_id = idx.upsert_file(&path).unwrap_or_default();
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
                    diags.retain(|d| !d.id.starts_with("taint"));
                }
                crate::utils::config::AnalysisMode::Taint => {
                    diags.retain(|d| d.id.starts_with("taint"));
                }
                crate::utils::config::AnalysisMode::Full => {}
            }

            if !diags.is_empty() {
                diag_map
                    .entry(path.to_string_lossy().to_string())
                    .or_default()
                    .append(&mut diags);
            }
        },
    );

    let mut diags: Vec<Diag> = diag_map.into_iter().flat_map(|(_, v)| v).collect();

    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
    }

    Ok(diags)
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
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg).unwrap();

    let pool = Indexer::init(&db_path).unwrap();

    assert_eq!(
        Indexer::from_pool(&project_name, &pool)
            .unwrap()
            .get_files(&project_name)
            .unwrap()
            .len(),
        1
    );

    let diags = scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg)
        .expect("scan should succeed");

    assert!(diags.is_empty());
}
