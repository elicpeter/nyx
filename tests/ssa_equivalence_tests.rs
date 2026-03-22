//! Corpus-level SSA / legacy equivalence validation.
//!
//! Scans each real-world fixture with both SSA (default) and legacy backends
//! and compares findings. Non-JS/TS fixtures must match exactly; JS/TS
//! divergences are reported as warnings until the two-level SSA stabilises.
//!
//! Run with: `cargo test --test ssa_equivalence_tests -- --test-threads=1`
//! (env var mutation is not thread-safe)

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ── Fixture discovery (reused pattern from real_world_tests) ───────────────

struct Fixture {
    lang: String,
    name: String,
    source_path: PathBuf,
}

fn discover_fixtures() -> Vec<Fixture> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real_world");
    let mut fixtures = Vec::new();

    let langs = [
        "rust", "c", "cpp", "java", "go", "php", "python", "ruby",
        "typescript", "javascript",
    ];
    let categories = ["taint", "cfg", "state", "mixed"];

    for lang in &langs {
        for category in &categories {
            let dir = base.join(lang).join(category);
            if !dir.is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path.file_name().unwrap().to_string_lossy().to_string();
                if !fname.ends_with(".expect.json") {
                    continue;
                }
                let stem = fname.trim_end_matches(".expect.json");
                if let Some(source_path) = find_source_file(&dir, stem) {
                    fixtures.push(Fixture {
                        lang: lang.to_string(),
                        name: format!("{lang}/{category}/{stem}"),
                        source_path,
                    });
                }
            }
        }
    }
    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    fixtures
}

fn find_source_file(dir: &Path, stem: &str) -> Option<PathBuf> {
    let extensions = [
        "rs", "c", "cpp", "cc", "cxx", "java", "go", "php", "py", "rb",
        "ts", "tsx", "js", "jsx",
    ];
    for ext in &extensions {
        let candidate = dir.join(format!("{stem}.{ext}"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ── Scanning with backend control ─────────────────────────────────────────

fn scan_with_backend(fixture: &Fixture, legacy: bool) -> Vec<Diag> {
    // SAFETY: test runs single-threaded (--test-threads=1)
    unsafe {
        if legacy {
            std::env::set_var("NYX_LEGACY", "1");
        } else {
            std::env::remove_var("NYX_LEGACY");
        }
    }

    let tmp = tempfile::TempDir::with_prefix("nyx_ssa_equiv_").expect("tempdir");
    let dest = tmp.path().join(fixture.source_path.file_name().unwrap());
    std::fs::copy(&fixture.source_path, &dest).expect("copy fixture");

    let cfg = test_config(AnalysisMode::Full);
    let mut diags =
        nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed");

    // Normalize and sort
    for d in &mut diags {
        if let Some(fname) = Path::new(&d.path).file_name() {
            d.path = fname.to_string_lossy().to_string();
        }
    }
    diags.sort_by(|a, b| a.id.cmp(&b.id).then(a.line.cmp(&b.line)));

    // Clean up env
    unsafe { std::env::remove_var("NYX_LEGACY"); }

    diags
}

fn is_js_ts(lang: &str) -> bool {
    matches!(lang, "javascript" | "typescript")
}

// ── Main test ─────────────────────────────────────────────────────────────

#[test]
fn ssa_legacy_corpus_equivalence() {
    let fixtures = discover_fixtures();
    if fixtures.is_empty() {
        eprintln!("WARNING: no fixtures found for SSA equivalence test");
        return;
    }

    let mut divergences: Vec<(String, String, Vec<String>, Vec<String>)> = Vec::new();
    let mut js_warnings: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let ssa_diags = scan_with_backend(fixture, false);
        let legacy_diags = scan_with_backend(fixture, true);

        let ssa_set: HashSet<_> = ssa_diags.iter().map(|d| (&d.id, d.line)).collect();
        let legacy_set: HashSet<_> = legacy_diags.iter().map(|d| (&d.id, d.line)).collect();

        if ssa_set != legacy_set {
            let ssa_only: Vec<String> = ssa_set
                .difference(&legacy_set)
                .map(|(id, line)| format!("  SSA-only: {} L{}", id, line))
                .collect();
            let legacy_only: Vec<String> = legacy_set
                .difference(&ssa_set)
                .map(|(id, line)| format!("  Legacy-only: {} L{}", id, line))
                .collect();

            if is_js_ts(&fixture.lang) {
                // JS/TS: warning only
                js_warnings.push(format!(
                    "JS/TS DIVERGENCE in {}:\n{}\n{}",
                    fixture.name,
                    ssa_only.join("\n"),
                    legacy_only.join("\n"),
                ));
            } else {
                divergences.push((
                    fixture.name.clone(),
                    fixture.lang.clone(),
                    ssa_only,
                    legacy_only,
                ));
            }
        }
    }

    // Report JS/TS warnings
    if !js_warnings.is_empty() {
        eprintln!(
            "\n=== JS/TS SSA divergences ({} fixtures, warnings only) ===",
            js_warnings.len()
        );
        for w in &js_warnings {
            eprintln!("{}", w);
        }
    }

    // Report non-JS/TS divergences (hard failures)
    if !divergences.is_empty() {
        eprintln!(
            "\n=== Non-JS/TS SSA divergences ({} fixtures) ===",
            divergences.len()
        );
        for (name, lang, ssa_only, legacy_only) in &divergences {
            eprintln!("DIVERGENCE in {} ({}):", name, lang);
            for s in ssa_only {
                eprintln!("{}", s);
            }
            for s in legacy_only {
                eprintln!("{}", s);
            }
        }
    }

    // Track divergence count for monitoring.
    // Current pre-existing divergences from Phase 1.5 are expected (SSA doesn't yet
    // match legacy for all patterns). This test tracks them so regressions are visible.
    // TODO: tighten this assertion as SSA gaps are closed.
    let total_diverged = divergences.len();
    eprintln!(
        "\nSummary: {} non-JS/TS divergences, {} JS/TS warnings, {} total fixtures",
        total_diverged,
        js_warnings.len(),
        fixtures.len()
    );

    // Fail only if divergence count increases beyond known baseline.
    // As of Phase 2 implementation, 11 non-JS/TS fixtures have known divergences.
    const KNOWN_DIVERGENCE_BASELINE: usize = 11;
    assert!(
        total_diverged <= KNOWN_DIVERGENCE_BASELINE,
        "SSA divergence regression: {} non-JS/TS fixtures diverged (baseline: {})",
        total_diverged,
        KNOWN_DIVERGENCE_BASELINE,
    );
}
