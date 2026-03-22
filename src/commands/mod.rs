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
            profile,
            all_targets,
            keep_nonprod_severity,
            quiet,
            fail_on,
            no_rank,
            show_suppressed,
            show_all,
            include_quality,
            max_low,
            max_low_per_file,
            max_low_per_rule,
            rollup_examples,
            show_instances,
            min_score,
            min_confidence,
            // Deprecated aliases
            no_index,
            rebuild_index,
            high_only,
            ast_only,
            cfg_only,
        } => {
            // ── Apply profile first (CLI flags override after) ──────────
            if let Some(ref name) = profile {
                config.apply_profile(name)?;
            }

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

            if no_rank {
                config.output.attack_surface_ranking = false;
            }

            // Min-score: CLI wins, then config
            if let Some(s) = min_score {
                config.output.min_score = Some(s);
            }

            // Min-confidence: CLI wins, then config
            if let Some(ref expr) = min_confidence {
                config.output.min_confidence =
                    Some(expr.parse::<crate::evidence::Confidence>().map_err(|e| {
                        crate::errors::NyxError::Msg(format!("invalid --min-confidence value: {e}"))
                    })?);
            }

            if show_all {
                config.output.show_all = true;
            }
            if include_quality {
                config.output.include_quality = true;
            }
            // CLI values override config defaults (clap provides defaults)
            config.output.max_low = max_low;
            config.output.max_low_per_file = max_low_per_file;
            config.output.max_low_per_rule = max_low_per_rule;
            config.output.rollup_examples = rollup_examples;

            let effective_format = format.unwrap_or(config.output.default_format);

            scan::handle(
                &path,
                effective_index,
                effective_format,
                severity_filter,
                fail_on_sev,
                show_suppressed,
                show_instances.as_deref(),
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
