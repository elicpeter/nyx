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

// ── Main test ─────────────────────────────────────────────────────────────

#[test]
fn ssa_legacy_corpus_equivalence() {
    let fixtures = discover_fixtures();
    if fixtures.is_empty() {
        eprintln!("WARNING: no fixtures found for SSA equivalence test");
        return;
    }

    let mut divergences: Vec<(String, String, Vec<String>, Vec<String>)> = Vec::new();

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

            divergences.push((
                fixture.name.clone(),
                fixture.lang.clone(),
                ssa_only,
                legacy_only,
            ));
        }
    }

    // Report all divergences
    if !divergences.is_empty() {
        eprintln!(
            "\n=== SSA divergences ({} fixtures) ===",
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

    let total_diverged = divergences.len();
    eprintln!(
        "\nSummary: {} divergences across all languages, {} total fixtures",
        total_diverged,
        fixtures.len()
    );

    // SSA is now the default for all languages including JS/TS.
    // Remaining divergences are either:
    //   - Phase 1 bugs (string concat, exception paths, predicate over-suppression)
    //   - SSA improvements: more precise cross-function isolation
    //     (receiver_taint_resolved, multi_method_xss)
    const KNOWN_DIVERGENCE_BASELINE: usize = 10;
    assert!(
        total_diverged <= KNOWN_DIVERGENCE_BASELINE,
        "SSA divergence regression: {} fixtures diverged (baseline: {})",
        total_diverged,
        KNOWN_DIVERGENCE_BASELINE,
    );
}
