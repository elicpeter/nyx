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

#[test]
fn cross_file_scc_convergence() {
    let dir = fixture_path("cross_file_scc_convergence");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_symex_body() {
    let dir = fixture_path("cross_file_symex_body");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_symex_js() {
    let dir = fixture_path("cross_file_symex_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── New multi-file fixtures ────────────────────────────────────────────────

// --- True positives ---------------------------------------------------------

/// Go: HTTP handler in handler.go passes r.FormValue("cmd") to runCommand()
/// defined in executor.go, which calls exec.Command — shell execution sink.
#[test]
fn cross_file_go_handler_exec() {
    let dir = fixture_path("cross_file_go_handler_exec");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Java: UserController.java reads getParameter("name") and passes it to
/// UserRepository.findByName(), which concatenates it into executeQuery().
/// Cross-file taint propagates via param_to_sink in the resolved summary.
#[test]
fn cross_file_java_sqli() {
    let dir = fixture_path("cross_file_java_sqli");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// TypeScript: router.ts reads req.query.url and forwards it to
/// fetchRemote() in httpClient.ts, which passes it to fetch() — SSRF.
#[test]
fn cross_file_ts_ssrf() {
    let dir = fixture_path("cross_file_ts_ssrf");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: source.js exports getInput(data); app.js destructures it under
/// the alias fetchUserCmd and passes req.query.cmd through it to execSync.
/// Import alias resolution maps fetchUserCmd → getInput for cross-file taint.
#[test]
fn cross_file_js_aliased_import() {
    let dir = fixture_path("cross_file_js_aliased_import");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: req.body.returnTo (inline source member expression in call arg)
/// flows through cross-file safeRedirect() passthrough to res.redirect() sink.
/// Exercises arg_source_caps detection for source member expressions nested
/// directly inside sink call arguments.
#[test]
fn cross_file_js_redirect() {
    let dir = fixture_path("cross_file_js_redirect");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: req.query.q flows through cross-file globalSearch() which
/// concatenates the param into raw SQL and passes it to db.query().
/// Tests cross-file param_to_sink propagation for SQL injection.
#[test]
fn cross_file_js_sqli() {
    let dir = fixture_path("cross_file_js_sqli");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python: 3-file chain — os.environ in input_reader.py → passthrough in
/// transform.py → subprocess.call in executor.py.  Taint must survive two
/// inter-file hops with no sanitisation.
#[test]
fn cross_file_py_nested_chain() {
    let dir = fixture_path("cross_file_py_nested_chain");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python: object attribute carries taint across files — JobRequest.cmd is
/// populated from os.environ in models.py; handler.py reads req.cmd and
/// passes it to subprocess.call.
#[test]
fn cross_file_py_object_field() {
    let dir = fixture_path("cross_file_py_object_field");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// --- True negatives ---------------------------------------------------------

/// Python: shlex.quote (SHELL_ESCAPE sanitiser) is defined in shell_utils.py
/// and called from handler.py before subprocess.call — no finding expected.
#[test]
fn cross_file_py_shlex_sanitizer() {
    let dir = fixture_path("cross_file_py_shlex_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: xss() HTML sanitiser defined in security.js is applied before
/// document.write in app.js — no taint-unsanitised-flow expected.
#[test]
fn cross_file_js_html_sanitized() {
    let dir = fixture_path("cross_file_js_html_sanitized");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python: constants.py returns a hardcoded string literal; runner.py uses it
/// in subprocess.call — no taint source exists, so no finding expected.
#[test]
fn cross_file_py_const_passthrough() {
    let dir = fixture_path("cross_file_py_const_passthrough");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Go: validation.go converts r.FormValue("id") with strconv.Atoi (Cap::all
/// sanitiser) before handler.go calls db.QueryRow — no SQL taint expected.
#[test]
fn cross_file_go_int_validated() {
    let dir = fixture_path("cross_file_go_int_validated");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// --- Near-miss cases --------------------------------------------------------

/// Python near miss — TRUE POSITIVE:
/// html_guard.py applies html.escape (HTML_ESCAPE cap) before a SQL
/// concatenation in app.py.  The HTML sanitiser does not cover SQL_QUERY
/// capability, so the flow is still vulnerable — Nyx should detect it.
/// Tests that the engine does not over-sanitise with the wrong cap type.
#[test]
fn cross_file_near_miss_wrong_sanitizer() {
    let dir = fixture_path("cross_file_near_miss_wrong_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript near miss — TRUE NEGATIVE:
/// session.js stores user input in `lastUser` but getDefaultQuery() returns
/// the constant `defaultQuery`.  app.js passes the result to pool.query().
/// A coarse analysis might falsely flag this; a precise one should not.
/// Tests that the engine does not conflate distinct module-level variables.
#[test]
fn cross_file_near_miss_field_isolation() {
    let dir = fixture_path("cross_file_near_miss_field_isolation");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── New sink coverage fixtures ────────────────────────────────────────────

/// JS: execAsync wraps child_process.exec; user input flows through the
/// wrapper to the inner exec call — SHELL_ESCAPE finding expected.
#[test]
fn exec_async_wrapper() {
    let dir = fixture_path("exec_async_wrapper");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JS: res.download(path.join(root, req.query.path)) — path traversal
/// via Express res.download FILE_IO sink.
#[test]
fn path_traversal_download() {
    let dir = fixture_path("path_traversal_download");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JS: md5(password) and crypto.createHash("sha1") — weak hash patterns.
#[test]
fn weak_hash_password() {
    let dir = fixture_path("weak_hash_password");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JS: hardcoded secret/password in object literal.
#[test]
fn hardcoded_secret() {
    let dir = fixture_path("hardcoded_secret");
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
