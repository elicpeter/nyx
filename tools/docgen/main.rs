//! Regenerates the per-language AST-pattern tables in `docs/rules.md`.
//!
//! Reads `nyx_scanner::patterns::PATTERNS` for each language via the public
//! `load()` registry, sorts by severity then ID, and writes markdown between
//! `<!-- BEGIN AUTOGEN rules-by-language -->` / `<!-- END AUTOGEN ... -->`
//! sentinel comments. Other sections of `rules.md` are untouched.
//!
//! Usage: `cargo run --features docgen --bin nyx-docgen [-- <path>]`
//! (default path: `docs/rules.md`).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use nyx_scanner::evidence::Confidence;
use nyx_scanner::patterns::{PatternTier, Severity, load};

const LANGS: &[(&str, &str)] = &[
    ("c", "C"),
    ("cpp", "C++"),
    ("go", "Go"),
    ("java", "Java"),
    ("javascript", "JavaScript"),
    ("php", "PHP"),
    ("python", "Python"),
    ("ruby", "Ruby"),
    ("rust", "Rust"),
    ("typescript", "TypeScript"),
];

const BEGIN_MARKER: &str = "<!-- BEGIN AUTOGEN rules-by-language -->";
const END_MARKER: &str = "<!-- END AUTOGEN rules-by-language -->";

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    }
}

fn tier_label(t: PatternTier) -> &'static str {
    match t {
        PatternTier::A => "A",
        PatternTier::B => "B",
    }
}

fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "High",
        Confidence::Medium => "Medium",
        Confidence::Low => "Low",
    }
}

fn render_lang(slug: &str, display: &str) -> Option<String> {
    let mut patterns = load(slug);
    if patterns.is_empty() {
        return None;
    }
    // Severity ordering is High < Medium < Low (declaration order, derived Ord),
    // so an ascending sort yields the desired High → Medium → Low display order.
    patterns.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.id.cmp(b.id)));

    let mut out = String::new();
    out.push_str(&format!("### {}: {} patterns\n\n", display, patterns.len()));
    out.push_str("| Rule ID | Severity | Tier | Confidence |\n");
    out.push_str("|---|---|---|---|\n");
    for p in &patterns {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            p.id,
            severity_label(p.severity),
            tier_label(p.tier),
            confidence_label(p.confidence),
        ));
    }
    Some(out)
}

fn render_all() -> String {
    let sections: Vec<String> = LANGS
        .iter()
        .filter_map(|(slug, display)| render_lang(slug, display))
        .collect();
    sections.join("\n")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let target = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "docs/rules.md".to_string());
    let path = PathBuf::from(&target);

    let original = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path.display(), e);
            process::exit(2);
        }
    };

    let begin = match original.find(BEGIN_MARKER) {
        Some(i) => i,
        None => {
            eprintln!(
                "error: BEGIN marker not found in {}\nexpected: {}",
                path.display(),
                BEGIN_MARKER
            );
            process::exit(2);
        }
    };
    let end = match original.find(END_MARKER) {
        Some(i) => i,
        None => {
            eprintln!(
                "error: END marker not found in {}\nexpected: {}",
                path.display(),
                END_MARKER
            );
            process::exit(2);
        }
    };
    if end < begin {
        eprintln!(
            "error: END marker appears before BEGIN marker in {}",
            path.display()
        );
        process::exit(2);
    }

    let prefix_end = begin + BEGIN_MARKER.len();
    let prefix = &original[..prefix_end];
    let suffix = &original[end..];
    let body = render_all();
    let new = format!("{}\n\n{}\n{}", prefix, body, suffix);

    if new == original {
        eprintln!("docs/rules.md is already up to date.");
        return;
    }

    if let Err(e) = fs::write(&path, &new) {
        eprintln!("error: cannot write {}: {}", path.display(), e);
        process::exit(2);
    }
    eprintln!("wrote {}", path.display());
}
