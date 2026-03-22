use crate::cli::OutputFormat;
use crate::errors::NyxResult;
use crate::labels::Cap;
use crate::patterns::Severity;
use console::style;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use toml;

static DEFAULT_CONFIG_TOML: &str = include_str!("../../default-nyx.conf");

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisMode {
    #[default]
    Full,
    Ast,
    Taint,
}

/// The kind of a custom label rule: source, sanitizer, or sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Source,
    Sanitizer,
    Sink,
}

impl fmt::Display for RuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => write!(f, "source"),
            Self::Sanitizer => write!(f, "sanitizer"),
            Self::Sink => write!(f, "sink"),
        }
    }
}

impl FromStr for RuleKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "source" => Ok(Self::Source),
            "sanitizer" => Ok(Self::Sanitizer),
            "sink" => Ok(Self::Sink),
            _ => Err(format!(
                "invalid rule kind: {s:?} (expected source, sanitizer, sink)"
            )),
        }
    }
}

/// Named capability for a custom label rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapName {
    EnvVar,
    HtmlEscape,
    ShellEscape,
    UrlEncode,
    JsonParse,
    FileIo,
    FmtString,
    SqlQuery,
    Deserialize,
    Ssrf,
    CodeExec,
    Crypto,
    All,
}

impl CapName {
    /// Convert to the corresponding `Cap` bitflag.
    pub fn to_cap(self) -> Cap {
        match self {
            Self::EnvVar => Cap::ENV_VAR,
            Self::HtmlEscape => Cap::HTML_ESCAPE,
            Self::ShellEscape => Cap::SHELL_ESCAPE,
            Self::UrlEncode => Cap::URL_ENCODE,
            Self::JsonParse => Cap::JSON_PARSE,
            Self::FileIo => Cap::FILE_IO,
            Self::FmtString => Cap::FMT_STRING,
            Self::SqlQuery => Cap::SQL_QUERY,
            Self::Deserialize => Cap::DESERIALIZE,
            Self::Ssrf => Cap::SSRF,
            Self::CodeExec => Cap::CODE_EXEC,
            Self::Crypto => Cap::CRYPTO,
            Self::All => Cap::all(),
        }
    }
}

impl fmt::Display for CapName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVar => write!(f, "env_var"),
            Self::HtmlEscape => write!(f, "html_escape"),
            Self::ShellEscape => write!(f, "shell_escape"),
            Self::UrlEncode => write!(f, "url_encode"),
            Self::JsonParse => write!(f, "json_parse"),
            Self::FileIo => write!(f, "file_io"),
            Self::FmtString => write!(f, "fmt_string"),
            Self::SqlQuery => write!(f, "sql_query"),
            Self::Deserialize => write!(f, "deserialize"),
            Self::Ssrf => write!(f, "ssrf"),
            Self::CodeExec => write!(f, "code_exec"),
            Self::Crypto => write!(f, "crypto"),
            Self::All => write!(f, "all"),
        }
    }
}

impl FromStr for CapName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "env_var" => Ok(Self::EnvVar),
            "html_escape" => Ok(Self::HtmlEscape),
            "shell_escape" => Ok(Self::ShellEscape),
            "url_encode" => Ok(Self::UrlEncode),
            "json_parse" => Ok(Self::JsonParse),
            "file_io" => Ok(Self::FileIo),
            "fmt_string" => Ok(Self::FmtString),
            "sql_query" => Ok(Self::SqlQuery),
            "deserialize" => Ok(Self::Deserialize),
            "ssrf" => Ok(Self::Ssrf),
            "code_exec" => Ok(Self::CodeExec),
            "crypto" => Ok(Self::Crypto),
            "all" => Ok(Self::All),
            _ => Err(format!(
                "invalid cap name: {s:?} (expected env_var, html_escape, shell_escape, \
                 url_encode, json_parse, file_io, fmt_string, sql_query, deserialize, \
                 ssrf, code_exec, crypto, all)"
            )),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ScannerConfig {
    /// The analysis mode to use.
    pub mode: AnalysisMode,

    /// The minimum severity level to output
    pub min_severity: Severity,

    /// The maximum file size to scan, in megabytes.
    pub max_file_size_mb: Option<u64>,

    /// File extensions to exclude from scanning.
    pub excluded_extensions: Vec<String>,

    /// Directories to exclude from scanning.
    pub excluded_directories: Vec<String>,

    /// Excluded files
    pub excluded_files: Vec<String>,

    /// RESERVED: not yet wired to walker. Whether to respect the global ignore file.
    pub read_global_ignore: bool,

    /// Whether to respect VCS ignore files (`.gitignore`, ..) or not.
    pub read_vcsignore: bool,

    /// Whether to require a `.git` directory to respect gitignore files.
    pub require_git_to_read_vcsignore: bool,

    /// Whether to limit the search to starting file system or not.
    pub one_file_system: bool,

    /// Whether to follow symlinks or not.
    pub follow_symlinks: bool,

    /// Whether to scan hidden files or not.
    pub scan_hidden_files: bool,

    /// Whether to include findings from non-production paths (tests, vendor,
    /// benchmarks, etc.) at their original severity.  When false (default),
    /// findings in these paths are downgraded by one severity tier.
    pub include_nonprod: bool,

    /// Enable the state-model dataflow engine for resource lifecycle and
    /// auth-state analysis.  Default: false (opt-in).
    pub enable_state_analysis: bool,
}
impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            mode: AnalysisMode::Full,
            min_severity: Severity::Low,
            max_file_size_mb: None,
            excluded_extensions: vec![
                "jpg", "png", "gif", "mp4", "avi", "mkv", "zip", "tar", "gz", "exe", "dll", "so",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            excluded_directories: vec![
                "node_modules",
                ".git",
                "target",
                ".vscode",
                ".idea",
                "build",
                "dist",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            excluded_files: vec![].into_iter().map(str::to_owned).collect(),
            read_global_ignore: false,
            read_vcsignore: true,
            require_git_to_read_vcsignore: true,
            one_file_system: false,
            follow_symlinks: false,
            scan_hidden_files: false,
            include_nonprod: false,
            enable_state_analysis: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct DatabaseConfig {
    /// RESERVED: custom database path (not yet wired; DB path is computed from project info).
    pub path: String,

    /// RESERVED: auto-cleanup not yet implemented. Days to keep database files.
    pub auto_cleanup_days: u32,

    /// RESERVED: size limit not yet implemented. Maximum database size in MiB.
    pub max_db_size_mb: u64,

    /// Whether to run a VACUUM on startup.
    pub vacuum_on_startup: bool,
}
impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: String::from(""),
            auto_cleanup_days: 30,
            max_db_size_mb: 1024,
            vacuum_on_startup: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct OutputConfig {
    /// The default output format.
    pub default_format: OutputFormat,

    /// Whether to print anything to the console or not.
    pub quiet: bool,

    /// The maximum number of results to show.
    pub max_results: Option<u32>,

    /// Enable attack-surface ranking to sort findings by exploitability.
    pub attack_surface_ranking: bool,

    /// Minimum attack-surface score to include in output.
    /// Findings below this threshold are dropped after ranking.
    /// `None` means no minimum (all findings shown).
    pub min_score: Option<u32>,

    /// Minimum confidence level to include in output.
    /// `None` means no minimum (all findings shown).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_confidence_opt"
    )]
    pub min_confidence: Option<crate::evidence::Confidence>,

    /// Include Quality-category findings (excluded by default).
    #[serde(default)]
    pub include_quality: bool,

    /// Show all findings: disables category filtering, rollups, and LOW budgets.
    #[serde(default)]
    pub show_all: bool,

    /// Maximum total LOW findings to show.
    #[serde(default = "default_max_low")]
    pub max_low: u32,

    /// Maximum LOW findings per file.
    #[serde(default = "default_max_low_per_file")]
    pub max_low_per_file: u32,

    /// Maximum LOW findings per rule.
    #[serde(default = "default_max_low_per_rule")]
    pub max_low_per_rule: u32,

    /// Number of example locations to store in rollup findings.
    #[serde(default = "default_rollup_examples")]
    pub rollup_examples: u32,
}

fn default_max_low() -> u32 {
    20
}
fn default_max_low_per_file() -> u32 {
    1
}
fn default_max_low_per_rule() -> u32 {
    10
}
fn default_rollup_examples() -> u32 {
    5
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            default_format: OutputFormat::Console,
            quiet: false,
            max_results: None,
            attack_surface_ranking: true,
            min_score: None,
            min_confidence: None,
            include_quality: false,
            show_all: false,
            max_low: 20,
            max_low_per_file: 1,
            max_low_per_rule: 10,
            rollup_examples: 5,
        }
    }
}

/// Deserialize an optional Confidence from a TOML string.
fn deserialize_confidence_opt<'de, D>(
    deserializer: D,
) -> Result<Option<crate::evidence::Confidence>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => s
            .parse::<crate::evidence::Confidence>()
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct PerformanceConfig {
    /// The maximum search depth, or `None` if no maximum search depth should be set.
    ///
    /// A depth of `1` includes all files under the current directory, a depth of `2` also includes
    /// all files under subdirectories of the current directory, etc.
    pub max_depth: Option<usize>,

    /// RESERVED: not yet wired to walker. Minimum depth for reported entries.
    pub min_depth: Option<usize>,

    /// RESERVED: not yet wired to walker. Stop traversing into matching directories.
    pub prune: bool,

    /// The maximum number of worker threads to use, or `None` to auto-detect.
    pub worker_threads: Option<usize>,

    /// The maximum number of entries to index in a single chunk.
    pub batch_size: usize,

    /// Channel capacity = threads × this.
    pub channel_multiplier: usize,

    /// The stack size for Rayon threads, in bytes.
    pub rayon_thread_stack_size: usize,

    /// RESERVED: per-file timeout not yet implemented. Timeout in seconds.
    pub scan_timeout_secs: Option<u64>,

    /// RESERVED: memory limit not yet implemented. Maximum memory in MiB.
    pub memory_limit_mb: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_depth: None,
            min_depth: None,
            prune: false,
            worker_threads: None,
            batch_size: 100usize,
            channel_multiplier: 4usize,
            rayon_thread_stack_size: 8 * 1024 * 1024, // 8 MiB
            scan_timeout_secs: None,
            memory_limit_mb: 512,
        }
    }
}

/// A single user-defined label rule from config.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ConfigLabelRule {
    pub matchers: Vec<String>,
    /// Rule kind: source, sanitizer, or sink.
    pub kind: RuleKind,
    /// Capability name (e.g. html_escape, sql_query, all).
    pub cap: CapName,
    #[serde(default)]
    pub case_sensitive: bool,
}

/// Per-language analysis configuration from config file.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct LanguageAnalysisConfig {
    pub rules: Vec<ConfigLabelRule>,
    pub terminators: Vec<String>,
    pub event_handlers: Vec<String>,
}

/// Top-level analysis rules config, keyed by language slug.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct AnalysisRulesConfig {
    pub languages: HashMap<String, LanguageAnalysisConfig>,
}

/// Configuration for the local web UI server (`nyx serve`).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ServerConfig {
    /// Whether the serve command is enabled.
    pub enabled: bool,
    /// Host to bind to (localhost by default for security).
    pub host: String,
    /// Port to bind to.
    pub port: u16,
    /// Open browser automatically when serve starts.
    pub open_browser: bool,
    /// Auto-reload UI when scan results change.
    pub auto_reload: bool,
    /// Persist scan runs for history view.
    pub persist_runs: bool,
    /// Maximum number of saved runs to keep.
    pub max_saved_runs: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 9700,
            open_browser: true,
            auto_reload: true,
            persist_runs: true,
            max_saved_runs: 50,
        }
    }
}

/// Configuration for scan run persistence and history.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct RunsConfig {
    /// Whether to persist scan run history to disk.
    pub persist: bool,
    /// Maximum number of runs to keep.
    pub max_runs: u32,
    /// Save scan logs with each run.
    pub save_logs: bool,
    /// Save stdout capture with each run.
    pub save_stdout: bool,
    /// Save code snippets in findings.
    pub save_code_snippets: bool,
}

impl Default for RunsConfig {
    fn default() -> Self {
        Self {
            persist: false,
            max_runs: 100,
            save_logs: false,
            save_stdout: false,
            save_code_snippets: true,
        }
    }
}

/// A named scan profile — a partial overlay of scan-related settings.
/// All fields are `Option<T>`: `None` means "don't override".
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ScanProfile {
    pub mode: Option<AnalysisMode>,
    pub min_severity: Option<Severity>,
    pub max_file_size_mb: Option<u64>,
    pub include_nonprod: Option<bool>,
    pub enable_state_analysis: Option<bool>,
    pub default_format: Option<OutputFormat>,
    pub quiet: Option<bool>,
    pub attack_surface_ranking: Option<bool>,
    pub max_results: Option<u32>,
    pub min_score: Option<u32>,
    pub show_all: Option<bool>,
    pub include_quality: Option<bool>,
    pub worker_threads: Option<usize>,
    pub max_depth: Option<usize>,
}

/// Built-in profile definitions.
fn builtin_profile(name: &str) -> Option<ScanProfile> {
    Some(match name {
        "quick" => ScanProfile {
            mode: Some(AnalysisMode::Ast),
            min_severity: Some(Severity::Medium),
            ..Default::default()
        },
        "full" => ScanProfile {
            mode: Some(AnalysisMode::Full),
            min_severity: Some(Severity::Low),
            enable_state_analysis: Some(true),
            ..Default::default()
        },
        "ci" => ScanProfile {
            mode: Some(AnalysisMode::Full),
            min_severity: Some(Severity::Medium),
            quiet: Some(true),
            default_format: Some(OutputFormat::Sarif),
            ..Default::default()
        },
        "taint_only" => ScanProfile {
            mode: Some(AnalysisMode::Taint),
            ..Default::default()
        },
        "conservative_large_repo" => ScanProfile {
            mode: Some(AnalysisMode::Ast),
            min_severity: Some(Severity::High),
            max_file_size_mb: Some(5),
            max_depth: Some(10),
            ..Default::default()
        },
        _ => return None,
    })
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub database: DatabaseConfig,
    pub output: OutputConfig,
    pub performance: PerformanceConfig,
    pub analysis: AnalysisRulesConfig,
    pub server: ServerConfig,
    pub runs: RunsConfig,
    pub profiles: HashMap<String, ScanProfile>,
}

impl Config {
    /// Load config and return `(config, optional_note)`.
    ///
    /// The note is a formatted status message about which config file was
    /// loaded (or that defaults are in use).  The caller decides whether to
    /// print it based on output format / quiet mode.
    pub fn load(config_dir: &Path) -> NyxResult<(Self, Option<String>)> {
        let mut config = Config::default();

        let default_config_path = config_dir.join("nyx.conf");
        if !default_config_path.exists() {
            create_example_config(config_dir)?;
        }

        let user_config_path = config_dir.join("nyx.local");
        let note = if user_config_path.exists() {
            let user_config_content = fs::read_to_string(&user_config_path)?;
            let user_config: Config = toml::from_str(&user_config_content)?;

            config = merge_configs(config, user_config);

            Some(format!(
                "{}: Loaded user config from: {}\n",
                style("note").green().bold(),
                style(user_config_path.display())
                    .underlined()
                    .white()
                    .bold()
            ))
        } else {
            Some(format!(
                "{}: Using {} configuration.\n      Create file in '{}' to customize.\n",
                style("note").green().bold(),
                style("default").bold(),
                style(user_config_path.display())
                    .underlined()
                    .white()
                    .bold()
            ))
        };

        config
            .validate()
            .map_err(crate::errors::NyxError::ConfigValidation)?;

        Ok((config, note))
    }

    /// Resolve a profile by name: user-defined profiles take precedence over built-ins.
    pub fn resolve_profile(&self, name: &str) -> Option<ScanProfile> {
        self.profiles
            .get(name)
            .cloned()
            .or_else(|| builtin_profile(name))
    }

    /// Apply a named profile, overlaying its `Some` fields onto this config.
    /// Returns an error if the profile is not found.
    pub fn apply_profile(&mut self, name: &str) -> NyxResult<()> {
        let profile = self.resolve_profile(name).ok_or_else(|| {
            crate::errors::NyxError::Msg(format!(
                "unknown profile '{name}'. Built-in profiles: quick, full, ci, taint_only, conservative_large_repo"
            ))
        })?;

        if let Some(v) = profile.mode {
            self.scanner.mode = v;
        }
        if let Some(v) = profile.min_severity {
            self.scanner.min_severity = v;
        }
        if let Some(v) = profile.max_file_size_mb {
            self.scanner.max_file_size_mb = Some(v);
        }
        if let Some(v) = profile.include_nonprod {
            self.scanner.include_nonprod = v;
        }
        if let Some(v) = profile.enable_state_analysis {
            self.scanner.enable_state_analysis = v;
        }
        if let Some(v) = profile.default_format {
            self.output.default_format = v;
        }
        if let Some(v) = profile.quiet {
            self.output.quiet = v;
        }
        if let Some(v) = profile.attack_surface_ranking {
            self.output.attack_surface_ranking = v;
        }
        if let Some(v) = profile.max_results {
            self.output.max_results = Some(v);
        }
        if let Some(v) = profile.min_score {
            self.output.min_score = Some(v);
        }
        if let Some(v) = profile.show_all {
            self.output.show_all = v;
        }
        if let Some(v) = profile.include_quality {
            self.output.include_quality = v;
        }
        if let Some(v) = profile.worker_threads {
            self.performance.worker_threads = Some(v);
        }
        if let Some(v) = profile.max_depth {
            self.performance.max_depth = Some(v);
        }

        Ok(())
    }

    /// Validate semantic invariants after loading/merging.
    /// Returns structured errors suitable for display or UI presentation.
    pub fn validate(&self) -> Result<(), Vec<crate::errors::ConfigError>> {
        use crate::errors::{ConfigError, ConfigErrorKind};
        let mut errors = Vec::new();

        // --- server ---
        if self.server.port == 0 {
            errors.push(ConfigError {
                section: "server".into(),
                field: "port".into(),
                message: "port must be 1–65535".into(),
                kind: ConfigErrorKind::OutOfRange,
            });
        }
        if self.server.host.is_empty() {
            errors.push(ConfigError {
                section: "server".into(),
                field: "host".into(),
                message: "host must not be empty".into(),
                kind: ConfigErrorKind::EmptyRequired,
            });
        }
        if self.server.persist_runs && self.server.max_saved_runs == 0 {
            errors.push(ConfigError {
                section: "server".into(),
                field: "max_saved_runs".into(),
                message: "max_saved_runs must be > 0 when persist_runs is true".into(),
                kind: ConfigErrorKind::Conflict,
            });
        }

        // --- runs ---
        if self.runs.persist && self.runs.max_runs == 0 {
            errors.push(ConfigError {
                section: "runs".into(),
                field: "max_runs".into(),
                message: "max_runs must be > 0 when persist is true".into(),
                kind: ConfigErrorKind::Conflict,
            });
        }

        // --- performance ---
        if self.performance.batch_size == 0 {
            errors.push(ConfigError {
                section: "performance".into(),
                field: "batch_size".into(),
                message: "batch_size must be > 0".into(),
                kind: ConfigErrorKind::OutOfRange,
            });
        }
        if self.performance.channel_multiplier == 0 {
            errors.push(ConfigError {
                section: "performance".into(),
                field: "channel_multiplier".into(),
                message: "channel_multiplier must be > 0".into(),
                kind: ConfigErrorKind::OutOfRange,
            });
        }

        // --- output ---
        if self.output.rollup_examples == 0 {
            errors.push(ConfigError {
                section: "output".into(),
                field: "rollup_examples".into(),
                message: "rollup_examples must be > 0".into(),
                kind: ConfigErrorKind::OutOfRange,
            });
        }

        // --- profiles ---
        for name in self.profiles.keys() {
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                errors.push(ConfigError {
                    section: "profiles".into(),
                    field: name.clone(),
                    message: format!(
                        "profile name '{name}' must contain only alphanumeric characters and underscores"
                    ),
                    kind: ConfigErrorKind::InvalidValue,
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn create_example_config(config_dir: &Path) -> NyxResult<()> {
    let example_path = config_dir.join("nyx.conf");
    if !example_path.exists() {
        fs::write(&example_path, DEFAULT_CONFIG_TOML)?;
        tracing::debug!("Example config created at: {}", example_path.display());
    }
    Ok(())
}

/// Merge user config into default config, preserving defaults where the user didn't
/// supply new exclusions and overriding everything else.
fn merge_configs(mut default: Config, user: Config) -> Config {
    // --- ScannerConfig ---
    default.scanner.mode = user.scanner.mode;
    default.scanner.min_severity = user.scanner.min_severity;
    default.scanner.max_file_size_mb = user.scanner.max_file_size_mb;
    default.scanner.read_global_ignore = user.scanner.read_global_ignore;
    default.scanner.read_vcsignore = user.scanner.read_vcsignore;
    default.scanner.require_git_to_read_vcsignore = user.scanner.require_git_to_read_vcsignore;
    default.scanner.one_file_system = user.scanner.one_file_system;
    default.scanner.follow_symlinks = user.scanner.follow_symlinks;
    default.scanner.scan_hidden_files = user.scanner.scan_hidden_files;
    default.scanner.include_nonprod = user.scanner.include_nonprod;
    default.scanner.enable_state_analysis = user.scanner.enable_state_analysis;

    // Merge exclusion lists (default ⊔ user), then sort & dedupe
    default
        .scanner
        .excluded_extensions
        .extend(user.scanner.excluded_extensions);
    default
        .scanner
        .excluded_directories
        .extend(user.scanner.excluded_directories);
    default.scanner.excluded_extensions.sort_unstable();
    default.scanner.excluded_extensions.dedup();
    default.scanner.excluded_directories.sort_unstable();
    default.scanner.excluded_directories.dedup();
    default
        .scanner
        .excluded_files
        .extend(user.scanner.excluded_files);
    default.scanner.excluded_files.sort_unstable();
    default.scanner.excluded_files.dedup();

    // --- DatabaseConfig ---
    default.database.path = user.database.path;
    default.database.auto_cleanup_days = user.database.auto_cleanup_days;
    default.database.max_db_size_mb = user.database.max_db_size_mb;
    default.database.vacuum_on_startup = user.database.vacuum_on_startup;

    // --- OutputConfig ---
    default.output.default_format = user.output.default_format;
    default.output.quiet = user.output.quiet;
    default.output.max_results = user.output.max_results;
    default.output.attack_surface_ranking = user.output.attack_surface_ranking;
    default.output.min_score = user.output.min_score;
    default.output.min_confidence = user.output.min_confidence;
    default.output.include_quality = user.output.include_quality;
    default.output.show_all = user.output.show_all;
    default.output.max_low = user.output.max_low;
    default.output.max_low_per_file = user.output.max_low_per_file;
    default.output.max_low_per_rule = user.output.max_low_per_rule;
    default.output.rollup_examples = user.output.rollup_examples;

    // --- PerformanceConfig ---
    default.performance.max_depth = user.performance.max_depth;
    default.performance.min_depth = user.performance.min_depth;
    default.performance.prune = user.performance.prune;
    default.performance.worker_threads = user.performance.worker_threads;
    default.performance.batch_size = user.performance.batch_size;
    default.performance.channel_multiplier = user.performance.channel_multiplier;
    default.performance.rayon_thread_stack_size = user.performance.rayon_thread_stack_size;
    default.performance.scan_timeout_secs = user.performance.scan_timeout_secs;
    default.performance.memory_limit_mb = user.performance.memory_limit_mb;

    // --- ServerConfig ---
    default.server = user.server;

    // --- RunsConfig ---
    default.runs = user.runs;

    // --- Profiles (user profile with same name fully replaces) ---
    for (name, profile) in user.profiles {
        default.profiles.insert(name, profile);
    }

    // --- AnalysisRulesConfig ---
    for (lang, user_lang_cfg) in user.analysis.languages {
        let entry = default.analysis.languages.entry(lang).or_default();

        // Union-merge rules with dedup
        for rule in user_lang_cfg.rules {
            if !entry.rules.contains(&rule) {
                entry.rules.push(rule);
            }
        }

        // Union-merge terminators with dedup
        for t in user_lang_cfg.terminators {
            if !entry.terminators.contains(&t) {
                entry.terminators.push(t);
            }
        }

        // Union-merge event_handlers with dedup
        for eh in user_lang_cfg.event_handlers {
            if !entry.event_handlers.contains(&eh) {
                entry.event_handlers.push(eh);
            }
        }
    }

    default
}

#[test]
fn merge_configs_dedupes_and_keeps_order() {
    let mut default_cfg = Config::default();
    default_cfg.scanner.excluded_extensions = vec!["rs".into(), "toml".into()];

    let mut user_cfg = Config::default();
    user_cfg.scanner.excluded_extensions = vec!["jpg".into(), "rs".into()];

    let merged = merge_configs(default_cfg, user_cfg);

    assert_eq!(
        merged.scanner.excluded_extensions,
        vec!["jpg", "rs", "toml"]
    );
}

#[test]
fn merge_analysis_rules_unions_and_dedupes() {
    let mut default_cfg = Config::default();
    default_cfg.analysis.languages.insert(
        "javascript".into(),
        LanguageAnalysisConfig {
            rules: vec![ConfigLabelRule {
                matchers: vec!["escapeHtml".into()],
                kind: RuleKind::Sanitizer,
                cap: CapName::HtmlEscape,
                case_sensitive: false,
            }],
            terminators: vec!["process.exit".into()],
            event_handlers: vec![],
        },
    );

    let mut user_cfg = Config::default();
    user_cfg.analysis.languages.insert(
        "javascript".into(),
        LanguageAnalysisConfig {
            rules: vec![
                ConfigLabelRule {
                    matchers: vec!["escapeHtml".into()],
                    kind: RuleKind::Sanitizer,
                    cap: CapName::HtmlEscape,
                    case_sensitive: false,
                },
                ConfigLabelRule {
                    matchers: vec!["sanitizeUrl".into()],
                    kind: RuleKind::Sanitizer,
                    cap: CapName::UrlEncode,
                    case_sensitive: false,
                },
            ],
            terminators: vec!["process.exit".into(), "abort".into()],
            event_handlers: vec!["addEventListener".into()],
        },
    );

    let merged = merge_configs(default_cfg, user_cfg);
    let js = merged.analysis.languages.get("javascript").unwrap();
    assert_eq!(js.rules.len(), 2); // deduped
    assert_eq!(js.terminators, vec!["process.exit", "abort"]);
    assert_eq!(js.event_handlers, vec!["addEventListener"]);
}

#[test]
fn analysis_config_toml_roundtrip() {
    let toml_str = r#"
[analysis.languages.javascript]
terminators = ["process.exit"]
event_handlers = ["addEventListener"]

[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml"]
kind = "sanitizer"
cap = "html_escape"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    let js = cfg.analysis.languages.get("javascript").unwrap();
    assert_eq!(js.rules.len(), 1);
    assert_eq!(js.rules[0].matchers, vec!["escapeHtml"]);
    assert_eq!(js.rules[0].kind, RuleKind::Sanitizer);
    assert_eq!(js.rules[0].cap, CapName::HtmlEscape);
    assert_eq!(js.terminators, vec!["process.exit"]);
    assert_eq!(js.event_handlers, vec!["addEventListener"]);
}

#[test]
fn load_creates_example_and_reads_user_overrides() {
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path();

    let user_toml = r#"
        [scanner]
        one_file_system = true
        excluded_extensions = ["foo"]

        [output]
        quiet = true
    "#;
    fs::write(cfg_path.join("nyx.local"), user_toml).unwrap();

    let (cfg, _note) = Config::load(cfg_path).expect("Config::load should succeed");

    assert!(cfg_path.join("nyx.conf").is_file());

    assert!(cfg.scanner.one_file_system);
    assert!(cfg.output.quiet);
    assert!(cfg.scanner.excluded_extensions.contains(&"foo".to_string()));

    assert!(!cfg.scanner.follow_symlinks);
}

// ─── Phase 1 tests: enum parsing ────────────────────────────────────────────

#[test]
fn enum_roundtrip_output_format() {
    let toml_str = r#"
        [output]
        default_format = "json"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.output.default_format, OutputFormat::Json);

    let toml_str = r#"
        [output]
        default_format = "sarif"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.output.default_format, OutputFormat::Sarif);

    let toml_str = r#"
        [output]
        default_format = "console"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.output.default_format, OutputFormat::Console);
}

#[test]
fn enum_roundtrip_rule_kind() {
    let toml_str = r#"
        [[analysis.languages.javascript.rules]]
        matchers = ["foo"]
        kind = "source"
        cap = "all"

        [[analysis.languages.javascript.rules]]
        matchers = ["bar"]
        kind = "sanitizer"
        cap = "html_escape"

        [[analysis.languages.javascript.rules]]
        matchers = ["baz"]
        kind = "sink"
        cap = "sql_query"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    let js = cfg.analysis.languages.get("javascript").unwrap();
    assert_eq!(js.rules[0].kind, RuleKind::Source);
    assert_eq!(js.rules[1].kind, RuleKind::Sanitizer);
    assert_eq!(js.rules[2].kind, RuleKind::Sink);
}

#[test]
fn enum_roundtrip_cap_name() {
    let caps = [
        "env_var", "html_escape", "shell_escape", "url_encode", "json_parse",
        "file_io", "fmt_string", "sql_query", "deserialize", "ssrf",
        "code_exec", "crypto", "all",
    ];
    for cap_str in caps {
        let toml_str = format!(
            r#"
            [[analysis.languages.rust.rules]]
            matchers = ["x"]
            kind = "source"
            cap = "{cap_str}"
            "#
        );
        let cfg: Config = toml::from_str(&toml_str)
            .unwrap_or_else(|e| panic!("failed to parse cap '{cap_str}': {e}"));
        let rs = cfg.analysis.languages.get("rust").unwrap();
        assert_eq!(rs.rules[0].cap.to_string(), cap_str);
    }
}

#[test]
fn backward_compat_existing_toml() {
    // Simulate a typical pre-enum nyx.local that used string values
    let toml_str = r#"
        [scanner]
        mode = "full"
        min_severity = "Medium"

        [output]
        default_format = "console"
        quiet = true

        [[analysis.languages.javascript.rules]]
        matchers = ["escapeHtml"]
        kind = "sanitizer"
        cap = "html_escape"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.scanner.mode, AnalysisMode::Full);
    assert_eq!(cfg.output.default_format, OutputFormat::Console);
    assert_eq!(
        cfg.analysis.languages["javascript"].rules[0].kind,
        RuleKind::Sanitizer
    );
    assert_eq!(
        cfg.analysis.languages["javascript"].rules[0].cap,
        CapName::HtmlEscape
    );
}

// ─── Phase 2 tests: server and runs config ──────────────────────────────────

#[test]
fn server_config_defaults() {
    let cfg = ServerConfig::default();
    assert!(cfg.enabled);
    assert_eq!(cfg.host, "127.0.0.1");
    assert_eq!(cfg.port, 9700);
    assert!(cfg.open_browser);
    assert!(cfg.auto_reload);
    assert!(cfg.persist_runs);
    assert_eq!(cfg.max_saved_runs, 50);
}

#[test]
fn runs_config_defaults() {
    let cfg = RunsConfig::default();
    assert!(!cfg.persist);
    assert_eq!(cfg.max_runs, 100);
    assert!(!cfg.save_logs);
    assert!(!cfg.save_stdout);
    assert!(cfg.save_code_snippets);
}

#[test]
fn server_config_toml_roundtrip() {
    let toml_str = r#"
        [server]
        enabled = false
        host = "0.0.0.0"
        port = 8080
        open_browser = false
        auto_reload = false
        persist_runs = false
        max_saved_runs = 10
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    assert!(!cfg.server.enabled);
    assert_eq!(cfg.server.host, "0.0.0.0");
    assert_eq!(cfg.server.port, 8080);
    assert!(!cfg.server.open_browser);
    assert!(!cfg.server.auto_reload);
    assert!(!cfg.server.persist_runs);
    assert_eq!(cfg.server.max_saved_runs, 10);
}

#[test]
fn missing_new_sections_use_defaults() {
    let toml_str = r#"
        [scanner]
        mode = "ast"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    // server and runs should have defaults
    assert_eq!(cfg.server.port, 9700);
    assert!(!cfg.runs.persist);
    assert!(cfg.profiles.is_empty());
}

// ─── Phase 3 tests: profiles ────────────────────────────────────────────────

#[test]
fn profile_apply_overrides() {
    let mut cfg = Config::default();
    cfg.apply_profile("ci").unwrap();
    assert_eq!(cfg.scanner.mode, AnalysisMode::Full);
    assert_eq!(cfg.scanner.min_severity, Severity::Medium);
    assert!(cfg.output.quiet);
    assert_eq!(cfg.output.default_format, OutputFormat::Sarif);
}

#[test]
fn profile_not_found_errors() {
    let mut cfg = Config::default();
    let result = cfg.apply_profile("nonexistent");
    assert!(result.is_err());
}

#[test]
fn builtin_profiles_resolve() {
    let cfg = Config::default();
    assert!(cfg.resolve_profile("quick").is_some());
    assert!(cfg.resolve_profile("full").is_some());
    assert!(cfg.resolve_profile("ci").is_some());
    assert!(cfg.resolve_profile("taint_only").is_some());
    assert!(cfg.resolve_profile("conservative_large_repo").is_some());
    assert!(cfg.resolve_profile("nonexistent").is_none());
}

#[test]
fn user_profile_overrides_builtin() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
        "ci".into(),
        ScanProfile {
            mode: Some(AnalysisMode::Ast),
            ..Default::default()
        },
    );
    let profile = cfg.resolve_profile("ci").unwrap();
    // User's ci profile has Ast, not the built-in Full
    assert_eq!(profile.mode, Some(AnalysisMode::Ast));
}

#[test]
fn profile_toml_roundtrip() {
    let toml_str = r#"
        [profiles.my_scan]
        mode = "ast"
        min_severity = "High"
        quiet = true
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    let profile = cfg.profiles.get("my_scan").unwrap();
    assert_eq!(profile.mode, Some(AnalysisMode::Ast));
    assert_eq!(profile.min_severity, Some(Severity::High));
    assert_eq!(profile.quiet, Some(true));
}

// ─── Phase 4 tests: validation ──────────────────────────────────────────────

#[test]
fn validate_good_config() {
    let cfg = Config::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn validate_zero_port() {
    let mut cfg = Config::default();
    cfg.server.port = 0;
    let err = cfg.validate().unwrap_err();
    assert!(err.iter().any(|e| e.field == "port"));
}

#[test]
fn validate_empty_host() {
    let mut cfg = Config::default();
    cfg.server.host = String::new();
    let err = cfg.validate().unwrap_err();
    assert!(err.iter().any(|e| e.field == "host"));
}

#[test]
fn validate_zero_batch_size() {
    let mut cfg = Config::default();
    cfg.performance.batch_size = 0;
    let err = cfg.validate().unwrap_err();
    assert!(err.iter().any(|e| e.field == "batch_size"));
}

#[test]
fn validate_bad_profile_name() {
    let mut cfg = Config::default();
    cfg.profiles
        .insert("has spaces".into(), ScanProfile::default());
    let err = cfg.validate().unwrap_err();
    assert!(err.iter().any(|e| e.section == "profiles"));
}

#[test]
fn validate_returns_all_errors() {
    let mut cfg = Config::default();
    cfg.server.port = 0;
    cfg.server.host = String::new();
    cfg.performance.batch_size = 0;
    let err = cfg.validate().unwrap_err();
    assert!(err.len() >= 3);
}

// ─── Phase 5 test: excluded_files merge ─────────────────────────────────────

#[test]
fn merge_excluded_files_union() {
    let mut default_cfg = Config::default();
    default_cfg.scanner.excluded_files = vec!["a.rs".into(), "b.rs".into()];

    let mut user_cfg = Config::default();
    user_cfg.scanner.excluded_files = vec!["b.rs".into(), "c.rs".into()];

    let merged = merge_configs(default_cfg, user_cfg);
    assert_eq!(
        merged.scanner.excluded_files,
        vec!["a.rs", "b.rs", "c.rs"]
    );
}
