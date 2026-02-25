//! # AST Pattern Conventions
//!
//! Each language file exports a `PATTERNS` slice of [`Pattern`] structs.
//!
//! ## ID format
//!
//! `<lang>.<category>.<specific>` — e.g. `java.deser.readobject`, `py.cmdi.os_system`.
//!
//! Language prefixes: `rs`, `java`, `py`, `js`, `ts`, `c`, `cpp`, `go`, `php`, `rb`.
//!
//! ## Tiers
//!
//! * **Tier A** — structural presence is high-signal (e.g. `gets()`, `eval()`).
//! * **Tier B** — requires a heuristic guard in the query (e.g. SQL with concatenated
//!   arg, format-string with variable first arg).
//!
//! ## Severity
//!
//! * **High** — command exec, deserialization, banned C functions.
//! * **Medium** — SQL concat, reflection, XSS sinks, casts.
//! * **Low** — weak crypto, insecure randomness, code-quality (`unwrap`/`expect`/`panic`).
//!
//! Note: the default `min_severity` filter skips Low patterns; they only appear when
//! the user explicitly lowers the threshold.
//!
//! ## No-duplicate rule
//!
//! If a vulnerability class is already detected by taint analysis (e.g. `eval` as a
//! sink, `system` as a sink), the AST pattern is still kept for `--ast-only` mode but
//! uses a distinct ID namespace (`js.code_exec.eval` vs `taint-unsanitised-flow`).
//! The dedup pass in `ast.rs` prevents exact-duplicate findings at the same location.
//!
//! ## Adding a new pattern
//!
//! 1. Pick the language file under `src/patterns/<lang>.rs`.
//! 2. Choose tier, category, severity per the rules above.
//! 3. Write the tree-sitter query — test with `cargo test --test pattern_tests`.
//! 4. Add a snippet to `tests/fixtures/patterns/<lang>/positive.<ext>`.
//! 5. Add the ID to the positive test assertion in `tests/pattern_tests.rs`.

pub mod c;
pub mod cpp;
mod go;
mod java;
pub mod javascript;
mod php;
mod python;
mod ruby;
pub mod rust;
pub mod typescript;

use console::style;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    /// Bracketed, colored, fixed-width tag for aligned console output.
    ///
    /// Returns e.g. `"[HIGH]  "` or `"[MEDIUM]"` — always 8 visible characters
    /// so the column after the tag lines up regardless of severity.
    pub fn colored_tag(self) -> String {
        // Visible widths: "[HIGH]" = 6, "[MEDIUM]" = 8, "[LOW]" = 5.
        // Pad the *whole* tag to 8 visible chars (the longest, "[MEDIUM]").
        let (label, styled_fn): (&str, fn(&str) -> String) = match self {
            Severity::High => ("HIGH", |s| style(s).red().bold().to_string()),
            Severity::Medium => ("MEDIUM", |s| style(s).yellow().bold().to_string()),
            Severity::Low => ("LOW", |s| style(s).cyan().bold().to_string()),
        };
        let bracket_len = label.len() + 2; // "[" + label + "]"
        let pad = 8usize.saturating_sub(bracket_len);
        format!("[{}]{:pad$}", styled_fn(label), "", pad = pad)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let styled = match *self {
            Severity::High => style("HIGH").red().bold().to_string(),
            Severity::Medium => style("MEDIUM").yellow().bold().to_string(),
            Severity::Low => style("LOW").cyan().bold().to_string(),
        };
        f.write_str(&styled)
    }
}

impl Severity {
    /// Textual value stored in SQLite.
    pub fn as_db_str(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl FromStr for Severity {
    // TODO: FIX
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            _ => Ok(Severity::Low),
        }
    }
}

/// Pattern confidence tier.
///
/// * **A** – Structural presence alone is high-signal (e.g. `gets()`, `eval()`).
/// * **B** – Requires a simple heuristic guard in the query (e.g. SQL with
///   concatenated arg, file-open with non-literal path).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PatternTier {
    A,
    B,
}

/// Vulnerability class that a pattern detects.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PatternCategory {
    CommandExec,
    CodeExec,
    Deserialization,
    SqlInjection,
    PathTraversal,
    Xss,
    Crypto,
    Secrets,
    InsecureTransport,
    Reflection,
    MemorySafety,
    Prototype,
    CodeQuality,
}

/// One AST pattern with a tree-sitter query and meta-data.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Pattern {
    /// Unique identifier — `<lang>.<category>.<specific>` preferred.
    pub id: &'static str,
    /// Human-readable explanation.
    pub description: &'static str,
    /// tree-sitter query string.
    pub query: &'static str,
    /// Rough severity bucket.
    pub severity: Severity,
    /// Confidence tier (A = structural, B = heuristic-guarded).
    pub tier: PatternTier,
    /// Vulnerability class.
    pub category: PatternCategory,
}

/// Global, lazily-initialised registry: lang-name → pattern slice
static REGISTRY: Lazy<HashMap<&'static str, &'static [Pattern]>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // ---- Rust ----
    m.insert("rust", rust::PATTERNS);

    // ---- TypeScript ----
    m.insert("typescript", typescript::PATTERNS);
    m.insert("ts", typescript::PATTERNS);
    m.insert("tsx", typescript::PATTERNS);

    // ---- JavaScript ----
    m.insert("javascript", javascript::PATTERNS);
    m.insert("js", javascript::PATTERNS);

    // ---- C & C++ ----
    m.insert("c", c::PATTERNS);
    m.insert("cpp", cpp::PATTERNS);
    m.insert("c++", cpp::PATTERNS);

    // ---- Other patterns in the folder ----
    m.insert("java", java::PATTERNS);
    m.insert("go", go::PATTERNS);
    m.insert("php", php::PATTERNS);
    m.insert("python", python::PATTERNS);
    m.insert("py", python::PATTERNS);
    m.insert("ruby", ruby::PATTERNS);
    m.insert("rb", ruby::PATTERNS);

    tracing::debug!("AST-pattern registry initialised ({} patterns)", m.len());

    m
});

/// Return all patterns for the requested language (case-insensitive).
///
/// Unknown patterns yield an **empty** `Vec`.
pub fn load(lang: &str) -> Vec<Pattern> {
    let key = lang.to_ascii_lowercase();
    REGISTRY.get(key.as_str()).copied().unwrap_or(&[]).to_vec()
}

#[test]
fn severity_as_db_str_roundtrip() {
    for &s in &[Severity::High, Severity::Medium, Severity::Low] {
        let db = s.as_db_str();
        assert!(matches!(db, "HIGH" | "MEDIUM" | "LOW"));

        assert_eq!(db.parse::<Severity>().unwrap(), s);
        assert_eq!(db.to_lowercase().parse::<Severity>().unwrap(), s);
    }
}

#[test]
fn severity_display_contains_uppercase_name() {
    assert!(Severity::High.to_string().contains("HIGH"));
    assert!(Severity::Medium.to_string().contains("MEDIUM"));
    assert!(Severity::Low.to_string().contains("LOW"));
}

#[test]
fn load_returns_correct_pattern_slices() {
    let rust = load("rust");
    assert!(!rust.is_empty(), "Rust patterns should be loaded");

    let ts = load("typescript");
    let tsx = load("tsx");
    assert_eq!(ts, tsx, "alias ‘tsx’ must map to TypeScript patterns");

    assert_eq!(load("RUST"), rust);

    assert!(load("brainfuck").is_empty());
}
