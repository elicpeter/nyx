pub mod clean;
pub mod config;
pub mod index;
pub mod list;
pub mod scan;

use crate::cli::Commands;
use crate::errors::NyxResult;
use crate::patterns::Severity;
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
            no_index,
            rebuild_index,
            format,
            high_only,
            ast_only,
            cfg_only,
            all_targets,
        } => {
            if high_only {
                config.scanner.min_severity = Severity::High
            };

            if ast_only {
                config.scanner.mode = AnalysisMode::Ast
            };

            if cfg_only {
                config.scanner.mode = AnalysisMode::Taint
            };

            if all_targets {
                config.scanner.mode = AnalysisMode::Full
            };

            scan::handle(&path, no_index, rebuild_index, format, database_dir, config)?;
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
