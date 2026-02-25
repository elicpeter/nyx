use crate::cli::IndexAction;
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::Severity;
use crate::utils::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use blake3;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use console::style;
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
                build_index(&project_name, &build_path, &db_path, config)?;
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
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
    }
    let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();

    paths.into_par_iter().try_for_each(
        |path| -> NyxResult<()> {
            let mut idx = Indexer::from_pool(project_name, &pool)?;

            // Run AST-only rules (no taint yet — summaries come later in scan)
            let issues = crate::commands::scan::run_rules_on_file(&path, config, None, None)?;
            let file_id = idx.upsert_file(&path)?;

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
            let sums = crate::commands::scan::extract_summaries_from_file(&path, config)
                .unwrap_or_default();
            if !sums.is_empty() {
                let bytes = std::fs::read(&path)?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(&bytes);
                let hash = hasher.finalize().as_bytes().to_vec();
                idx.replace_summaries_for_file(&path, &hash, &sums)?;
            }

            Ok(())
        },
    )?;

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

    build_index("proj", &project_dir, &db_path, &cfg).expect("index build should succeed");

    // ── Assert ────────────────────────────────────────────────────────────────
    assert!(db_path.is_file(), "SQLite file must exist");

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool("proj", &pool).unwrap();
    let files = idx.get_files("proj").unwrap();
    assert_eq!(files.len(), 1, "exactly one file indexed");
    assert_eq!(files[0], f_txt);
}
