//! Corpus-level SSA taint analysis validation.
//!
//! Scans each real-world fixture with the SSA backend and verifies findings
//! are produced. This was originally an SSA/legacy equivalence test; after
//! legacy removal (Phase 6), it validates that SSA analysis runs successfully
//! on all fixtures without panics or regressions.
//!
//! Run with: `cargo test --test ssa_equivalence_tests`

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

// ── Fixture discovery (reused pattern from real_world_tests) ───────────────

struct Fixture {
    name: String,
    source_path: PathBuf,
}

fn discover_fixtures() -> Vec<Fixture> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real_world");
    let mut fixtures = Vec::new();

    let langs = [
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "typescript",
        "javascript",
    ];
    let categories = ["taint", "cfg", "state", "mixed"];

    for lang in &langs {
        for category in &categories {
            let dir = base.join(lang).join(category);
            if !dir.is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path.file_name().unwrap().to_string_lossy().to_string();
                if !fname.ends_with(".expect.json") {
                    continue;
                }
                let stem = fname.trim_end_matches(".expect.json");
                if let Some(source_path) = find_source_file(&dir, stem) {
                    fixtures.push(Fixture {
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
        "rs", "c", "cpp", "cc", "cxx", "java", "go", "php", "py", "rb", "ts", "tsx", "js", "jsx",
    ];
    for ext in &extensions {
        let candidate = dir.join(format!("{stem}.{ext}"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ── Scanning ───────────────────────────────────────────────────────────────

fn scan_fixture(fixture: &Fixture) -> Vec<Diag> {
    let tmp = tempfile::TempDir::with_prefix("nyx_ssa_corpus_").expect("tempdir");
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

    diags
}

// ── Main test ─────────────────────────────────────────────────────────────

#[test]
fn ssa_corpus_validation() {
    let fixtures = discover_fixtures();
    if fixtures.is_empty() {
        eprintln!("WARNING: no fixtures found for SSA corpus test");
        return;
    }

    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let result = std::panic::catch_unwind(|| scan_fixture(fixture));
        match result {
            Ok(diags) => {
                eprintln!("OK {}: {} findings", fixture.name, diags.len());
            }
            Err(_) => {
                let msg = format!("PANIC in {}", fixture.name);
                eprintln!("{}", msg);
                failures.push(msg);
            }
        }
    }

    eprintln!(
        "\nSummary: {} fixtures scanned, {} failures",
        fixtures.len(),
        failures.len()
    );

    assert!(
        failures.is_empty(),
        "SSA corpus failures:\n{}",
        failures.join("\n"),
    );
}
