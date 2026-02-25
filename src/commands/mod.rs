pub mod clean;
pub mod config;
pub mod index;
pub mod list;
pub mod scan;

use crate::cli::{Commands, IndexMode, ScanMode};
use crate::errors::NyxResult;
use crate::patterns::{Severity, SeverityFilter};
use crate::utils::config::{AnalysisMode, Config};
use std::path::Path;

pub fn handle_command(
    command: Commands,
    database_dir: &Path,
    config_dir: &Path,
    config: &mut Config,
) -> NyxResult<()> {
    match command {
        Commands::Scan {
            path,
            index,
            format,
            severity,
            mode,
            all_targets,
            keep_nonprod_severity,
            quiet,
            fail_on,
            // Deprecated aliases
            no_index,
            rebuild_index,
            high_only,
            ast_only,
            cfg_only,
        } => {
            // ── Resolve deprecated aliases ──────────────────────────────

            // Index mode: explicit --index wins, then deprecated flags
            let effective_index = if no_index {
                IndexMode::Off
            } else if rebuild_index {
                IndexMode::Rebuild
            } else {
                index
            };

            // Analysis mode: explicit --mode wins, then deprecated flags
            let effective_mode = if ast_only {
                ScanMode::Ast
            } else if cfg_only {
                ScanMode::Cfg
            } else if all_targets {
                ScanMode::Full
            } else {
                mode
            };

            // Severity filter: explicit --severity wins, then --high-only
            let severity_filter = if let Some(ref expr) = severity {
                Some(SeverityFilter::parse(expr).map_err(|e| {
                    crate::errors::NyxError::Msg(format!("invalid --severity expression: {e}"))
                })?)
            } else if high_only {
                Some(SeverityFilter::parse("HIGH").unwrap())
            } else {
                None
            };

            // Fail-on threshold
            let fail_on_sev = if let Some(ref expr) = fail_on {
                Some(expr.trim().parse::<Severity>().map_err(|e| {
                    crate::errors::NyxError::Msg(format!("invalid --fail-on value: {e}"))
                })?)
            } else {
                None
            };

            // ── Apply to config ─────────────────────────────────────────

            match effective_mode {
                ScanMode::Full => config.scanner.mode = AnalysisMode::Full,
                ScanMode::Ast => config.scanner.mode = AnalysisMode::Ast,
                ScanMode::Cfg | ScanMode::Taint => config.scanner.mode = AnalysisMode::Taint,
            }

            if keep_nonprod_severity {
                config.scanner.include_nonprod = true;
            }

            if quiet {
                config.output.quiet = true;
            }

            scan::handle(
                &path,
                effective_index,
                format,
                severity_filter,
                fail_on_sev,
                database_dir,
                config,
            )?;
        }
        Commands::Index { action } => {
            index::handle(action, database_dir, config)?;
        }
        Commands::List { verbose } => {
            list::handle(verbose, database_dir)?;
        }
        Commands::Clean { project, all } => {
            clean::handle(project, all, database_dir)?;
        }
        Commands::Config { action } => {
            use crate::cli::ConfigAction;
            match action {
                ConfigAction::Show => self::config::show(config)?,
                ConfigAction::Path => self::config::path(config_dir)?,
                ConfigAction::AddRule {
                    lang,
                    matcher,
                    kind,
                    cap,
                } => self::config::add_rule(config_dir, &lang, &matcher, &kind, &cap)?,
                ConfigAction::AddTerminator { lang, name } => {
                    self::config::add_terminator(config_dir, &lang, &name)?
                }
            }
        }
    }
    Ok(())
}
