use crate::cli::IndexAction;
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::Severity;
use crate::server::progress::{ScanMetrics, ScanProgress, ScanStage};
use crate::server::scan_log::ScanLogCollector;
use crate::utils::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

pub fn handle(
    action: IndexAction,
    database_dir: &std::path::Path,
    config: &Config,
) -> NyxResult<()> {
    match action {
        IndexAction::Build { path, force } => {
            let build_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&build_path, database_dir)?;

            if force || !db_path.exists() {
                build_index(
                    &project_name,
                    &build_path,
                    &db_path,
                    config,
                    !config.output.quiet,
                )?;
                println!(
                    "✔ {} {}",
                    style("Index built:").green(),
                    style(db_path.display()).white().bold()
                );
                exit(0);
            } else {
                println!(
                    "{} {}",
                    style("↩ Index already exists").yellow(),
                    style("(use --force to rebuild)").dim()
                );
                exit(0);
            }
        }
        IndexAction::Status { path } => {
            let status_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&status_path, database_dir)?;

            println!("{}", style("Project status").blue().bold().underlined());
            println!(
                "  {:14} {}",
                style("Project"),
                style(&project_name).white().bold()
            );
            println!(
                "  {:14} {}",
                style("Index path"),
                style(db_path.display()).underlined()
            );
            println!(
                "  {:14} {}",
                style("Exists"),
                style(db_path.exists()).bold()
            );

            if db_path.exists() {
                let meta = fs::metadata(&db_path)?;
                let size = ByteSize::b(meta.len());
                let mtime: DateTime<Local> = meta.modified()?.into();
                println!("  {:14} {}", style("Size"), size);
                println!(
                    "  {:14} {}",
                    style("Modified"),
                    mtime.format("%Y-%m-%d %H:%M:%S")
                );
            }

            exit(0);
        }
    }
}

pub fn build_index(
    project_name: &str,
    project_path: &std::path::Path,
    db_path: &std::path::Path,
    config: &Config,
    show_progress: bool,
) -> NyxResult<()> {
    build_index_with_observer(
        project_name,
        project_path,
        db_path,
        config,
        show_progress,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_index_with_observer(
    project_name: &str,
    project_path: &std::path::Path,
    db_path: &std::path::Path,
    config: &Config,
    show_progress: bool,
    progress: Option<&Arc<ScanProgress>>,
    metrics: Option<&Arc<ScanMetrics>>,
    logs: Option<&Arc<ScanLogCollector>>,
) -> NyxResult<()> {
    // Pass 1 of the indexed scan reads persisted summaries produced here, so
    // framework context must be populated at index-build time — otherwise
    // framework-conditional label rules never contribute to the summaries
    // and indexed scans diverge from non-indexed ones.  Matches the
    // auto-fill in scan_filesystem_with_observer /
    // scan_with_index_parallel_observer.
    let owned_cfg = crate::commands::scan::ensure_framework_ctx(project_path, config);
    let config = owned_cfg.as_ref().unwrap_or(config);

    tracing::debug!("Building index for: {}", project_name);
    let pool = Indexer::init(db_path)?;
    {
        let idx = Indexer::from_pool(project_name, &pool)?;
        idx.clear()?;
    }

    tracing::debug!("Cleaned index for: {}", project_name);

    if let Some(p) = progress {
        p.set_stage(ScanStage::Discovering);
    }
    if let Some(l) = logs {
        l.info(
            format!("Rebuilding index for {}", project_path.display()),
            None,
        );
    }

    let walk_start = std::time::Instant::now();
    let (rx, handle) = spawn_file_walker(project_path, config);
    // Drain the channel BEFORE joining — the bounded channel will deadlock
    // if we join first and the walker blocks on send.
    let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
        if let Some(l) = logs {
            l.error(
                "Walker thread panicked during index rebuild",
                None,
                Some(format!("{err:#?}")),
            );
        }
    }
    if let Some(p) = progress {
        p.record_walk_ms(walk_start.elapsed().as_millis() as u64);
        p.set_files_discovered(paths.len() as u64);
        p.set_stage(ScanStage::Indexing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Index rebuild discovered {} files in {}ms",
                paths.len(),
                walk_start.elapsed().as_millis()
            ),
            None,
        );
    }

    let pb = if show_progress {
        let pb = ProgressBar::new(paths.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{bar:30.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        pb.set_message("Indexing files");
        pb
    } else {
        ProgressBar::hidden()
    };

    let progress = progress.cloned();
    let metrics = metrics.cloned();
    let logs = logs.cloned();
    let pass1_start = std::time::Instant::now();
    paths
        .into_par_iter()
        .try_for_each(|path| -> NyxResult<()> {
            let mut idx = Indexer::from_pool(project_name, &pool)?;

            // Read once, hash once — pass bytes to both rule execution and
            // summary extraction.  Use pre-computed hash for upsert to avoid
            // a redundant file read inside upsert_file.
            let bytes = std::fs::read(&path)?;
            let hash = Indexer::digest_bytes(&bytes);

            // Parse once and persist every artifact we can reuse later:
            // findings, coarse summaries, and precise SSA summaries.
            let fused = crate::commands::scan::analyse_file_fused(
                &bytes,
                &path,
                config,
                None,
                Some(project_path),
            )?;
            if let Some(ref p) = progress {
                p.inc_parsed(1);
                p.set_current_file(&path.to_string_lossy());
                if let Some(lang) = fused.summaries.first().map(|s| s.lang.as_str()) {
                    p.record_language(lang);
                }
            }
            if let Some(ref m) = metrics {
                m.cfg_nodes.fetch_add(fused.cfg_nodes as u64, Relaxed);
            }
            let file_id = idx.upsert_file_with_hash(&path, &hash)?;

            let rows: Vec<IssueRow> = fused
                .diags
                .iter()
                .map(|d| IssueRow {
                    rule_id: d.id.as_ref(),
                    severity: match d.severity {
                        Severity::High => "HIGH",
                        Severity::Medium => "MEDIUM",
                        Severity::Low => "LOW",
                    },
                    line: d.line as i64,
                    col: d.col as i64,
                })
                .collect();

            idx.replace_issues(file_id, rows)?;

            if !fused.summaries.is_empty() {
                idx.replace_summaries_for_file(&path, &hash, &fused.summaries)?;
            }

            if !fused.ssa_summaries.is_empty() {
                let ssa_rows: Vec<_> = fused
                    .ssa_summaries
                    .into_iter()
                    .map(|(key, sum)| {
                        (
                            key.name,
                            key.arity.unwrap_or(0),
                            key.lang.as_str().to_string(),
                            key.namespace,
                            key.container,
                            key.disambig,
                            key.kind,
                            sum,
                        )
                    })
                    .collect();
                idx.replace_ssa_summaries_for_file(&path, &hash, &ssa_rows)?;
            }

            // Persist SSA callee bodies at index-build time so CLI-initiated
            // rebuilds (`--index rebuild`) populate the same
            // `ssa_function_bodies` rows that `scan_with_index_parallel`
            // would have written via its pass-1 branch.  Without this,
            // indexed scans load zero cross-file bodies and cross-file
            // inline silently falls back to summary resolution.
            if !fused.ssa_bodies.is_empty() {
                let body_rows: Vec<_> = fused
                    .ssa_bodies
                    .into_iter()
                    .map(|(key, body)| {
                        (
                            key.name,
                            key.arity.unwrap_or(0),
                            key.lang.as_str().to_string(),
                            key.namespace,
                            key.container,
                            key.disambig,
                            key.kind,
                            body,
                        )
                    })
                    .collect();
                idx.replace_ssa_bodies_for_file(&path, &hash, &body_rows)?;
            }

            pb.inc(1);
            Ok(())
        })?;
    pb.finish_and_clear();
    if let Some(p) = &progress {
        p.record_pass1_ms(pass1_start.elapsed().as_millis() as u64);
    }
    if let Some(l) = &logs {
        l.info(
            format!(
                "Index rebuild complete in {}ms",
                pass1_start.elapsed().as_millis()
            ),
            None,
        );
    }

    {
        let idx = Indexer::from_pool(project_name, &pool)?;
        idx.vacuum()?;
    }

    Ok(())
}

#[test]
fn build_index_creates_db_and_registers_files() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    fs::create_dir(&project_dir).unwrap();
    let f_txt = project_dir.join("readme.txt");
    fs::write(&f_txt, "hello").unwrap();

    let db_path = td.path().join("proj.sqlite");

    build_index("proj", &project_dir, &db_path, &cfg, false).expect("index build should succeed");

    // ── Assert ────────────────────────────────────────────────────────────────
    assert!(db_path.is_file(), "SQLite file must exist");

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool("proj", &pool).unwrap();
    let files = idx.get_files("proj").unwrap();
    assert_eq!(files.len(), 1, "exactly one file indexed");
    assert_eq!(files[0], f_txt);
}

#[test]
fn build_index_persists_ssa_summaries() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    fs::create_dir(&project_dir).unwrap();
    fs::write(
        project_dir.join("app.js"),
        r#"var express = require('express');
var app = express();

function cleanHtml(input) {
    return DOMPurify.sanitize(input);
}

app.get('/safe', function(req, res) {
    var name = req.query.name;
    var safe = cleanHtml(name);
    res.send(safe);
});
"#,
    )
    .unwrap();

    let db_path = td.path().join("proj.sqlite");
    build_index("proj", &project_dir, &db_path, &cfg, false).expect("index build should succeed");

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool("proj", &pool).unwrap();
    let ssa = idx.load_all_ssa_summaries().unwrap();
    assert!(
        !ssa.is_empty(),
        "index build should persist SSA summaries for functions with non-trivial SSA effects"
    );
}
