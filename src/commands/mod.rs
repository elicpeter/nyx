pub mod clean;
pub mod config;
pub mod index;
pub mod list;
pub mod scan;
#[cfg(feature = "serve")]
pub mod serve;

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
    // Resolve engine options once for the whole process.  Scan overlays CLI
    // flags below; other subcommands use the config values verbatim.  The
    // install is a no-op after the first call, so Scan's overlay must happen
    // before we reach this point for its own call path — we delay the install
    // to the Scan arm and gate non-scan commands behind a fallback install of
    // the bare config values.
    let install_from_config = |config: &Config| {
        if config.analysis.engine.parse_timeout_ms == 0 {
            tracing::warn!(
                "parse_timeout_ms = 0 disables tree-sitter parse timeout entirely; \
                 this is unsafe for untrusted input."
            );
        }
        let _ = crate::utils::analysis_options::install(config.analysis.engine);
    };

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
            no_state,
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
            // Analysis engine toggles
            constraint_solving,
            no_constraint_solving,
            abstract_interp,
            no_abstract_interp,
            context_sensitive,
            no_context_sensitive,
            symex,
            no_symex,
            cross_file_symex,
            no_cross_file_symex,
            symex_interproc,
            no_symex_interproc,
            smt,
            no_smt,
            backwards_analysis,
            no_backwards_analysis,
            parse_timeout_ms,
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
                ScanMode::Cfg => config.scanner.mode = AnalysisMode::Cfg,
                ScanMode::Taint => config.scanner.mode = AnalysisMode::Taint,
            }

            if keep_nonprod_severity {
                config.scanner.include_nonprod = true;
            }

            if quiet {
                config.output.quiet = true;
            }

            if no_state {
                config.scanner.enable_state_analysis = false;
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

            // ── Analysis engine toggles: resolve CLI → config ───────────
            // Each pair is a tri-state (flag set ⇒ true, no-flag set ⇒ false,
            // neither ⇒ inherit config default).
            let mut engine = config.analysis.engine;
            if constraint_solving {
                engine.constraint_solving = true;
            }
            if no_constraint_solving {
                engine.constraint_solving = false;
            }
            if abstract_interp {
                engine.abstract_interpretation = true;
            }
            if no_abstract_interp {
                engine.abstract_interpretation = false;
            }
            if context_sensitive {
                engine.context_sensitive = true;
            }
            if no_context_sensitive {
                engine.context_sensitive = false;
            }
            if symex {
                engine.symex.enabled = true;
            }
            if no_symex {
                engine.symex.enabled = false;
            }
            if cross_file_symex {
                engine.symex.cross_file = true;
            }
            if no_cross_file_symex {
                engine.symex.cross_file = false;
            }
            if symex_interproc {
                engine.symex.interprocedural = true;
            }
            if no_symex_interproc {
                engine.symex.interprocedural = false;
            }
            if smt {
                engine.symex.smt = true;
            }
            if no_smt {
                engine.symex.smt = false;
            }
            if backwards_analysis {
                engine.backwards_analysis = true;
            }
            if no_backwards_analysis {
                engine.backwards_analysis = false;
            }
            if let Some(ms) = parse_timeout_ms {
                engine.parse_timeout_ms = ms;
            }
            config.analysis.engine = engine;
            if engine.parse_timeout_ms == 0 {
                tracing::warn!(
                    "parse_timeout_ms = 0 disables tree-sitter parse timeout entirely; \
                     this is unsafe for untrusted input."
                );
            }
            if !crate::utils::analysis_options::install(engine) {
                tracing::warn!(
                    "analysis-engine runtime already installed; CLI engine flags ignored"
                );
            }

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
            install_from_config(config);
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
        Commands::Serve {
            path,
            port,
            host,
            no_browser,
        } => {
            install_from_config(config);
            #[cfg(feature = "serve")]
            {
                serve::handle(
                    &path,
                    port,
                    host.as_deref(),
                    no_browser,
                    config_dir,
                    database_dir,
                    config,
                )?;
            }
            #[cfg(not(feature = "serve"))]
            {
                let _ = (path, port, host, no_browser);
                return Err(crate::errors::NyxError::Msg(
                    "The `serve` feature is not enabled. Rebuild with `cargo build --features serve`.".into(),
                ));
            }
        }
    }
    Ok(())
}
