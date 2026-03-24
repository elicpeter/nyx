mod common;

use common::{assert_no_findings, scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::collections::HashSet;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// ── Per-fixture tests ──────────────────────────────────────────────────────

#[test]
fn rust_web_app() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn express_app() {
    let dir = fixture_path("express_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn flask_app() {
    let dir = fixture_path("flask_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn go_server() {
    let dir = fixture_path("go_server");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn c_utils() {
    let dir = fixture_path("c_utils");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn java_service() {
    let dir = fixture_path("java_service");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn mixed_project() {
    let dir = fixture_path("mixed_project");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_taint() {
    let dir = fixture_path("cross_file_taint");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_ssa_propagation() {
    let dir = fixture_path("cross_file_ssa_propagation");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_ssa_source() {
    let dir = fixture_path("cross_file_ssa_source");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_ssa_sanitizer() {
    let dir = fixture_path("cross_file_ssa_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Cross-file param sink precision ───────────────────────────────────────

#[test]
fn cross_file_param_sink_precision() {
    let dir = fixture_path("cross_file_param_sink_precision");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_mixed_cap_sink() {
    let dir = fixture_path("cross_file_mixed_cap_sink");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── SCC SSA summary refinement ────────────────────────────────────────────

#[test]
fn cross_file_scc_ssa() {
    let dir = fixture_path("cross_file_scc_ssa");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Cross-cutting tests ───────────────────────────────────────────────────

#[test]
fn ast_only_mode_excludes_taint() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Ast);

    assert_no_findings(&diags, "taint-");
    assert_no_findings(&diags, "cfg-");
}

#[test]
fn taint_only_mode_excludes_ast() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Taint);

    // Taint mode should not produce AST-only pattern findings
    assert_no_findings(&diags, "rs.quality.unwrap");
    assert_no_findings(&diags, "rs.quality.expect");
}

#[test]
fn dedup_no_double_report() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // The same (path, line, col, rule_id) tuple should never appear twice.
    // Different rule IDs at the same location are fine (e.g., taint + cfg-auth-gap).
    let mut seen: HashSet<(String, usize, usize, String)> = HashSet::new();
    let mut exact_dupes = Vec::new();
    for d in &diags {
        let key = (d.path.clone(), d.line, d.col, d.id.clone());
        if !seen.insert(key) {
            exact_dupes.push(format!("{}:{}:{} {}", d.path, d.line, d.col, d.id));
        }
    }
    assert!(
        exact_dupes.is_empty(),
        "Exact duplicate findings (same location + rule ID) found ({}):\n  {}",
        exact_dupes.len(),
        exact_dupes.join("\n  ")
    );
}

#[test]
fn mixed_project_multi_language() {
    let dir = fixture_path("mixed_project");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Findings should span at least 2 different file extensions
    let extensions: HashSet<&str> = diags
        .iter()
        .filter_map(|d| {
            std::path::Path::new(&d.path)
                .extension()
                .and_then(|e| e.to_str())
        })
        .collect();

    assert!(
        extensions.len() >= 2,
        "Expected findings from >= 2 language file extensions, got: {:?}",
        extensions
    );

    // Total findings >= 3 across languages
    assert!(
        diags.len() >= 3,
        "Expected >= 3 total findings in mixed project, got {}",
        diags.len()
    );
}

// ── Binary smoke test ──────────────────────────────────────────────────────

#[test]
fn binary_json_output() {
    let fixture = fixture_path("rust_web_app");
    #[allow(deprecated)]
    let cmd = assert_cmd::Command::cargo_bin("nyx")
        .expect("nyx binary should exist")
        .arg("scan")
        .arg(fixture.to_str().unwrap())
        .arg("--no-index")
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to execute nyx binary");

    assert!(
        cmd.status.success(),
        "nyx scan exited with non-zero status: {:?}\nstderr: {}",
        cmd.status,
        String::from_utf8_lossy(&cmd.stderr)
    );

    let stdout = String::from_utf8_lossy(&cmd.stdout);
    // Find the JSON array in stdout (config notes and "Finished" surround it)
    let json_start = stdout.find('[').expect("Expected JSON array in stdout");
    let json_end = stdout.rfind(']').expect("Expected closing bracket in JSON") + 1;
    let json_str = &stdout[json_start..json_end];
    let parsed: Vec<serde_json::Value> =
        serde_json::from_str(json_str).expect("stdout should contain valid JSON array");

    assert!(
        !parsed.is_empty(),
        "Expected at least 1 finding in JSON output"
    );
}
