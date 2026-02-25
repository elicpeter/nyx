use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nyx")]
#[command(about = "A fast vulnerability scanner with project indexing")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

impl Commands {
    /// Whether this command produces structured (machine-readable) output on
    /// stdout, meaning human status messages must be suppressed entirely.
    pub fn is_structured_output(&self) -> bool {
        matches!(self, Commands::Scan { format, .. } if format == "json" || format == "sarif")
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan project for vulnerabilities
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Skip using/building index, scan directly
        #[arg(long)]
        no_index: bool,

        /// Force rebuild index before scanning
        #[arg(long)]
        rebuild_index: bool,

        /// Output format (console, json, sarif)
        #[arg(short, long, default_value = "")]
        format: String,

        /// Show only high severity issues
        #[arg(long)]
        high_only: bool,

        #[arg(long)]
        ast_only: bool,

        #[arg(long)]
        cfg_only: bool,

        #[arg(long)]
        all_targets: bool,

        /// Include findings from test/vendor/build paths at original severity
        /// (by default these are downgraded)
        #[arg(long)]
        include_nonprod: bool,
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
