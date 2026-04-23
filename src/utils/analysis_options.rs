//! Analysis-engine options: stable, serializable toggles that control which
//! analysis passes run inside the scanner.
//!
//! These are the release-grade knobs that used to live as ad-hoc `NYX_*`
//! environment variables (`NYX_CONSTRAINT`, `NYX_ABSTRACT_INTERP`, `NYX_SYMEX`,
//! `NYX_CROSS_FILE_SYMEX`, `NYX_SYMEX_INTERPROC`, `NYX_CONTEXT_SENSITIVE`,
//! `NYX_PARSE_TIMEOUT_MS`, `NYX_SMT`).  They are now a single struct loaded
//! from the `[analysis.engine]` section of `nyx.conf` and overridable by CLI
//! flags.
//!
//! Engine code calls [`current`] to read the active options.  Before a scan
//! begins, the CLI entry point installs a resolved [`AnalysisOptions`] via
//! [`install`].  Library consumers that never call `install` get
//! [`AnalysisOptions::default`], which is the documented release default.
//!
//! The legacy `NYX_*` variables still read **only** when no runtime has been
//! installed and serve as a last-resort override for library users; running
//! the `nyx` binary always goes through the configured runtime.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Default parse timeout (milliseconds).  See [`AnalysisOptions::parse_timeout_ms`].
pub const DEFAULT_PARSE_TIMEOUT_MS: u64 = 10_000;

/// Default upper bound on the number of taint origins tracked per lattice
/// value.  Raised from the historical `4` to `32` so realistic codebases
/// with wide joins (many param sources, deep helper chains) no longer
/// silently drop origin attribution.  Tunable via
/// [`AnalysisOptions::max_origins`] — see
/// `src/taint/ssa_transfer/state.rs::effective_max_origins`.
pub const DEFAULT_MAX_ORIGINS: u32 = 32;

/// Minimum permitted `max_origins` value.  A cap of `0` would make origin
/// tracking impossible (every merge would truncate); the test override
/// still accepts `0` through its own path, but runtime config clamps to
/// at least `1` so production scans always carry *some* provenance.
pub const MIN_MAX_ORIGINS: u32 = 1;

/// Options for the symbolic-execution pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SymexOptions {
    /// Run the symex pass at all.  When `false`, findings get no
    /// `symbolic` verdict and cross-file body extraction is skipped.
    pub enabled: bool,
    /// Persist and consult cross-file SSA bodies so symex can model
    /// callees defined in other files.
    pub cross_file: bool,
    /// Dive into intra-file callee bodies during symex (k ≥ 2 via the
    /// interprocedural frame stack).
    pub interprocedural: bool,
    /// Use the SMT backend when available.  Only meaningful when nyx is
    /// compiled with the `smt` feature; silently ignored otherwise.
    pub smt: bool,
}

impl Default for SymexOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            cross_file: true,
            interprocedural: true,
            smt: true,
        }
    }
}

/// Stable configuration for the analysis engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisOptions {
    /// Path-constraint solving.  Prunes infeasible paths from the taint
    /// worklist and records unsat contexts in findings.
    pub constraint_solving: bool,
    /// Abstract interpretation: interval/string/bit domains carried through
    /// the SSA worklist and used to suppress provably safe sinks.
    pub abstract_interpretation: bool,
    /// k=1 context-sensitive inlining for intra-file callees.
    pub context_sensitive: bool,
    /// Symbolic-execution pipeline.
    pub symex: SymexOptions,
    /// Demand-driven backwards taint analysis from sinks.
    ///
    /// When enabled, after forward pass 2 completes, a backwards walk runs
    /// from each sink's tainted SSA operands to corroborate or rule out the
    /// forward finding.  Corroborated findings get a `backwards-confirmed`
    /// note; flows the backward walk proves infeasible get a
    /// `backwards-infeasible` note that caps confidence.  Defaults off.
    pub backwards_analysis: bool,
    /// Per-file tree-sitter parse timeout in milliseconds.  `0` disables the
    /// cap entirely (not recommended outside of controlled benchmarks).
    pub parse_timeout_ms: u64,
    /// Maximum taint origins retained per lattice value.
    ///
    /// Controls both [`crate::taint::domain::VarTaint::origins`] and
    /// the equivalent per-object bound inside the heap state.  When a
    /// merge would exceed this bound, origins are dropped deterministically
    /// (sorted by source location) and an
    /// [`crate::engine_notes::EngineNote::OriginsTruncated`] note is
    /// recorded on the affected finding.  Raising this reduces the
    /// chance of silent under-reporting at the cost of slightly wider
    /// lattice values.  See [`DEFAULT_MAX_ORIGINS`].
    pub max_origins: u32,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            constraint_solving: true,
            abstract_interpretation: true,
            context_sensitive: true,
            symex: SymexOptions::default(),
            backwards_analysis: false,
            parse_timeout_ms: DEFAULT_PARSE_TIMEOUT_MS,
            max_origins: DEFAULT_MAX_ORIGINS,
        }
    }
}

/// Process-wide installed options.  Accessors fall back to
/// [`AnalysisOptions::default`] (with env-var overrides for backward
/// compatibility) until the CLI entry point installs a value.
static RUNTIME: OnceLock<AnalysisOptions> = OnceLock::new();

/// Install the process-wide analysis options.  Subsequent calls are a no-op
/// (by design: a single scan run must not change its own engine toggles
/// mid-flight).  Returns whether the install succeeded.
pub fn install(opts: AnalysisOptions) -> bool {
    RUNTIME.set(opts).is_ok()
}

/// Read the active options.  Returns the installed runtime when present,
/// otherwise defaults merged with env-var fallbacks (legacy path).
pub fn current() -> AnalysisOptions {
    if let Some(rt) = RUNTIME.get() {
        return *rt;
    }
    // Legacy env-var fallback: applies only when no runtime has been
    // installed (primarily for library consumers and old tests).  Logged
    // at debug level so CI/test output isn't spammed.
    AnalysisOptions {
        constraint_solving: env_bool_default("NYX_CONSTRAINT", true),
        abstract_interpretation: env_bool_default("NYX_ABSTRACT_INTERP", true),
        context_sensitive: env_bool_default("NYX_CONTEXT_SENSITIVE", true),
        symex: SymexOptions {
            enabled: env_bool_default("NYX_SYMEX", true),
            cross_file: env_bool_default("NYX_CROSS_FILE_SYMEX", true),
            interprocedural: env_bool_default("NYX_SYMEX_INTERPROC", true),
            smt: env_bool_default("NYX_SMT", true),
        },
        backwards_analysis: env_bool_default("NYX_BACKWARDS", false),
        parse_timeout_ms: env_u64_default("NYX_PARSE_TIMEOUT_MS", DEFAULT_PARSE_TIMEOUT_MS),
        max_origins: env_u32_default("NYX_MAX_ORIGINS", DEFAULT_MAX_ORIGINS).max(MIN_MAX_ORIGINS),
    }
}

fn env_bool_default(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !(v == "0" || v.eq_ignore_ascii_case("false")),
        Err(_) => default,
    }
}

fn env_u64_default(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(v) => v.parse::<u64>().unwrap_or(default),
        Err(_) => default,
    }
}

fn env_u32_default(key: &str, default: u32) -> u32 {
    match std::env::var(key) {
        Ok(v) => v.parse::<u32>().unwrap_or(default),
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented() {
        let opts = AnalysisOptions::default();
        assert!(opts.constraint_solving);
        assert!(opts.abstract_interpretation);
        assert!(opts.context_sensitive);
        assert!(opts.symex.enabled);
        assert!(opts.symex.cross_file);
        assert!(opts.symex.interprocedural);
        assert!(opts.symex.smt);
        assert!(!opts.backwards_analysis, "backwards analysis defaults off");
        assert_eq!(opts.parse_timeout_ms, DEFAULT_PARSE_TIMEOUT_MS);
        assert_eq!(opts.max_origins, DEFAULT_MAX_ORIGINS);
    }

    #[test]
    fn toml_roundtrip() {
        let opts = AnalysisOptions {
            constraint_solving: false,
            abstract_interpretation: true,
            context_sensitive: false,
            symex: SymexOptions {
                enabled: true,
                cross_file: false,
                interprocedural: true,
                smt: false,
            },
            backwards_analysis: true,
            parse_timeout_ms: 5_000,
            max_origins: 64,
        };
        let s = toml::to_string(&opts).unwrap();
        let back: AnalysisOptions = toml::from_str(&s).unwrap();
        assert_eq!(opts, back);
    }
}
