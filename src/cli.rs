use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "nyx")]
#[command(about = "A fast vulnerability scanner with project indexing")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Commands {
    /// Resolve the effective output format, using the config default when the
    /// CLI flag is omitted.
    pub fn effective_format(&self, config: &crate::utils::config::Config) -> OutputFormat {
        match self {
            Commands::Scan { format, .. } => format.unwrap_or(config.output.default_format),
            _ => OutputFormat::Console,
        }
    }

    /// Whether this command produces structured (machine-readable) output on
    /// stdout, meaning human status messages must be suppressed entirely.
    pub fn is_structured_output(&self, config: &crate::utils::config::Config) -> bool {
        let fmt = self.effective_format(config);
        matches!(self, Commands::Scan { .. })
            && (fmt == OutputFormat::Json || fmt == OutputFormat::Sarif)
    }

    /// Whether this is a long-running server command (skip timing output).
    pub fn is_serve(&self) -> bool {
        matches!(self, Commands::Serve { .. })
    }
}

/// Output format for scan results.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Console,
    Json,
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Console => write!(f, "console"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
        }
    }
}

/// Index mode for scan operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
pub enum IndexMode {
    /// Use index if available, build if missing (default)
    #[default]
    Auto,
    /// Skip indexing entirely, scan filesystem directly
    Off,
    /// Force rebuild index before scanning
    Rebuild,
}

/// Analysis mode for scan operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
pub enum ScanMode {
    /// Run all analyses: AST analyses + CFG + taint (default)
    #[default]
    Full,
    /// Run AST analyses only (tree-sitter patterns + auth analysis; no CFG/taint/state)
    Ast,
    /// Run CFG structural analyses + taint only (no AST analyses)
    Cfg,
    /// Alias for cfg (CFG + taint analysis)
    Taint,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan project for vulnerabilities
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Index mode: auto (default), off (no index), rebuild (force rebuild)
        #[arg(long, value_enum, default_value_t = IndexMode::Auto)]
        index: IndexMode,

        /// Output format (defaults to config's default_format, or "console")
        #[arg(short, long, value_enum)]
        format: Option<OutputFormat>,

        /// Severity filter expression: HIGH, HIGH,MEDIUM, or >=MEDIUM
        ///
        /// Filters findings AFTER all severity normalization (e.g. nonprod
        /// downgrades). Only findings matching the expression are emitted.
        /// Case-insensitive. Shell-quote expressions containing ">".
        #[arg(long)]
        severity: Option<String>,

        /// Analysis mode: full (default), ast, cfg, taint
        #[arg(long, value_enum, default_value_t = ScanMode::Full)]
        mode: ScanMode,

        /// Named scan profile to apply (e.g. quick, full, ci, taint_only, conservative_large_repo)
        ///
        /// Profiles override scan-related config settings. CLI flags still
        /// take precedence over profile values.
        #[arg(long)]
        profile: Option<String>,

        /// Scan all targets (alias for --mode full)
        #[arg(long, hide = true)]
        all_targets: bool,

        /// Preserve original severity for test/vendor/build paths
        ///
        /// By default, findings in non-production paths are downgraded by one
        /// severity tier. This flag preserves original severity.
        #[arg(long, alias = "include-nonprod")]
        keep_nonprod_severity: bool,

        /// Suppress all human-readable status output
        #[arg(long)]
        quiet: bool,

        /// Exit with code 1 if any finding meets or exceeds this severity
        ///
        /// Useful for CI gating. Example: --fail-on HIGH
        #[arg(long)]
        fail_on: Option<String>,

        /// Disable state-model analysis (resource lifecycle, auth state)
        #[arg(long)]
        no_state: bool,

        /// Disable attack-surface ranking (findings are sorted by exploitability by default)
        #[arg(long)]
        no_rank: bool,

        /// Show inline-suppressed findings (dimmed, tagged [SUPPRESSED])
        #[arg(long)]
        show_suppressed: bool,

        /// Show all findings: disables category filtering, rollups, and LOW budgets
        #[arg(long = "all")]
        show_all: bool,

        /// Include Quality findings (excluded by default)
        #[arg(long)]
        include_quality: bool,

        /// Maximum total LOW findings to show
        #[arg(long, default_value_t = 20)]
        max_low: u32,

        /// Maximum LOW findings per file
        #[arg(long, default_value_t = 1)]
        max_low_per_file: u32,

        /// Maximum LOW findings per rule
        #[arg(long, default_value_t = 10)]
        max_low_per_rule: u32,

        /// Number of example locations in rollup findings
        #[arg(long, default_value_t = 5)]
        rollup_examples: u32,

        /// Show all instances for a specific rule (bypasses rollup for that rule)
        #[arg(long)]
        show_instances: Option<String>,

        /// Minimum attack-surface score to include in output
        ///
        /// Findings with a rank score below this threshold are suppressed.
        /// Requires ranking to be enabled (has no effect with --no-rank).
        /// Example: --min-score 50
        #[arg(long)]
        min_score: Option<u32>,

        /// Minimum confidence level to include in output
        ///
        /// Values: low, medium, high. Findings below this level are dropped.
        /// JSON/SARIF include all unless filtered.
        #[arg(long)]
        min_confidence: Option<String>,

        // ── Analysis engine toggles (override [analysis.engine] config) ───
        /// Enable path-constraint solving (default: on)
        #[arg(long, overrides_with = "no_constraint_solving")]
        constraint_solving: bool,
        /// Disable path-constraint solving
        #[arg(long, overrides_with = "constraint_solving")]
        no_constraint_solving: bool,

        /// Enable abstract interpretation (default: on)
        #[arg(long, overrides_with = "no_abstract_interp")]
        abstract_interp: bool,
        /// Disable abstract interpretation
        #[arg(long, overrides_with = "abstract_interp")]
        no_abstract_interp: bool,

        /// Enable k=1 context-sensitive callee inlining (default: on)
        #[arg(long, overrides_with = "no_context_sensitive")]
        context_sensitive: bool,
        /// Disable context-sensitive callee inlining
        #[arg(long, overrides_with = "context_sensitive")]
        no_context_sensitive: bool,

        /// Enable the symex pipeline (default: on)
        #[arg(long, overrides_with = "no_symex")]
        symex: bool,
        /// Disable the symex pipeline entirely
        #[arg(long, overrides_with = "symex")]
        no_symex: bool,

        /// Enable cross-file symbolic body execution (default: on)
        #[arg(long, overrides_with = "no_cross_file_symex")]
        cross_file_symex: bool,
        /// Disable cross-file symbolic body execution
        #[arg(long, overrides_with = "cross_file_symex")]
        no_cross_file_symex: bool,

        /// Enable interprocedural symex frame stack (default: on)
        #[arg(long, overrides_with = "no_symex_interproc")]
        symex_interproc: bool,
        /// Disable interprocedural symex
        #[arg(long, overrides_with = "symex_interproc")]
        no_symex_interproc: bool,

        /// Enable SMT solver backend when nyx is built with the `smt` feature (default: on)
        #[arg(long, overrides_with = "no_smt")]
        smt: bool,
        /// Disable SMT solver backend
        #[arg(long, overrides_with = "smt")]
        no_smt: bool,

        /// Override per-file tree-sitter parse timeout (ms). 0 disables the cap.
        #[arg(long)]
        parse_timeout_ms: Option<u64>,

        // ── Deprecated aliases (hidden) ─────────────────────────────────
        /// Deprecated: use --index off
        #[arg(long, hide = true)]
        no_index: bool,

        /// Deprecated: use --index rebuild
        #[arg(long, hide = true)]
        rebuild_index: bool,

        /// Deprecated: use --severity HIGH
        #[arg(long, hide = true)]
        high_only: bool,

        /// Deprecated: use --mode ast
        #[arg(long, hide = true)]
        ast_only: bool,

        /// Deprecated: use --mode cfg
        #[arg(long, hide = true)]
        cfg_only: bool,
    },

    /// Manage project indexes
    Index {
        #[command(subcommand)]
        action: IndexAction,
    },

    /// List all indexed projects
    List {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove project from index
    Clean {
        /// Project name or path to clean
        project: Option<String>,

        /// Clean all projects
        #[arg(long)]
        all: bool,
    },

    /// Manage analysis configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Start the local web UI for browsing scan results
    Serve {
        /// Path to scan root (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Port to bind to (overrides config)
        #[arg(short, long)]
        port: Option<u16>,

        /// Host to bind to (overrides config)
        #[arg(long)]
        host: Option<String>,

        /// Don't open browser automatically
        #[arg(long)]
        no_browser: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Print effective merged configuration as TOML
    Show,

    /// Print configuration directory path
    Path,

    /// Add a label rule to nyx.local
    AddRule {
        /// Language slug (e.g. javascript, rust, python)
        #[arg(long)]
        lang: String,

        /// Function or property name to match
        #[arg(long)]
        matcher: String,

        /// Rule kind: source, sanitizer, or sink
        #[arg(long)]
        kind: String,

        /// Capability: env_var, html_escape, shell_escape, url_encode, json_parse, file_io, or all
        #[arg(long)]
        cap: String,
    },

    /// Add a terminator function to nyx.local
    AddTerminator {
        /// Language slug (e.g. javascript, rust, python)
        #[arg(long)]
        lang: String,

        /// Function name that terminates execution (e.g. process.exit)
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum IndexAction {
    /// Build or update index for current project
    Build {
        /// Path to index (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Force full rebuild
        #[arg(short, long)]
        force: bool,
    },

    /// Show index status and statistics
    Status {
        /// Project path to check
        #[arg(default_value = ".")]
        path: String,
    },
}
