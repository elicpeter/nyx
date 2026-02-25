use crate::cli::IndexAction;
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::Severity;
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
    tracing::debug!("Building index for: {}", project_name);
    fs::File::create(db_path)?;

    let pool = Indexer::init(db_path)?;
    {
        let idx = Indexer::from_pool(project_name, &pool)?;
        idx.clear()?;
    }

    tracing::debug!("Cleaned index for: {}", project_name);

    let (rx, handle) = spawn_file_walker(project_path, config);
    // Drain the channel BEFORE joining — the bounded channel will deadlock
    // if we join first and the walker blocks on send.
    let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
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

    paths
        .into_par_iter()
        .try_for_each(|path| -> NyxResult<()> {
            let mut idx = Indexer::from_pool(project_name, &pool)?;

            // Read once, hash once — pass bytes to both rule execution and
            // summary extraction.  Use pre-computed hash for upsert to avoid
            // a redundant file read inside upsert_file.
            let bytes = std::fs::read(&path)?;
            let hash = Indexer::digest_bytes(&bytes);

            // Run AST-only rules (no taint yet — summaries come later in scan)
            let issues =
                crate::commands::scan::run_rules_on_bytes(&bytes, &path, config, None, None)?;
            let file_id = idx.upsert_file_with_hash(&path, &hash)?;

            let rows: Vec<IssueRow> = issues
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

            // Extract and persist function summaries for cross-file taint
            let sums = crate::commands::scan::extract_summaries_from_bytes(&bytes, &path, config)
                .unwrap_or_default();
            if !sums.is_empty() {
                idx.replace_summaries_for_file(&path, &hash, &sums)?;
            }

            pb.inc(1);
            Ok(())
        })?;
    pb.finish_and_clear();

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
