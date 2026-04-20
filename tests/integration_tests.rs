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
fn rust_framework_rules() {
    let dir = fixture_path("rust_framework_rules");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn rust_module_path_resolution() {
    // Two modules define `pub fn validate(&str) -> String` with the same arity.
    // `main.rs` has `use crate::auth::token::validate;` and calls `validate(&cmd)`.
    // A correct use-map driven resolver must target `auth::token::validate`
    // (pass-through sanitizer) and NOT `auth::session::validate` (shell sink);
    // the expectations forbid any taint finding on main.rs.
    let dir = fixture_path("rust_module_path_resolution");
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
fn koa_app() {
    let dir = fixture_path("koa_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn fastify_app() {
    let dir = fixture_path("fastify_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_integration() {
    let dir = fixture_path("auth_analysis_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_frameworks_integration() {
    let dir = fixture_path("auth_analysis_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_noise_frameworks() {
    let dir = fixture_path("auth_analysis_noise_frameworks");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_python_frameworks_integration() {
    let dir = fixture_path("auth_analysis_python_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_ruby_frameworks_integration() {
    let dir = fixture_path("auth_analysis_ruby_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_go_java_frameworks_integration() {
    let dir = fixture_path("auth_analysis_go_java_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_rust_frameworks_integration() {
    let dir = fixture_path("auth_analysis_rust_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_admin_multilang_integration() {
    let dir = fixture_path("auth_analysis_admin_multilang_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_ownership_multilang_integration() {
    let dir = fixture_path("auth_analysis_ownership_multilang_integration");
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
/// Exercises source node pre-emission for source member expressions nested
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

/// Same-file identity collision — ADVERSARIAL.
/// `runTask` is defined as a free function (shell-exec sink) AND as a
/// method on multiple classes in the same file with conflicting
/// security behaviours.  A bare `runTask(tainted)` top-level call MUST
/// resolve to the free function (its summary carries a SHELL_ESCAPE
/// sink) — the pre-fix resolver returned Ambiguous for this call and
/// silently dropped the finding.  Regression guard for the bare-call
/// free-function preference (resolve_callee step 5.5).
#[test]
fn same_name_collisions_js() {
    let dir = fixture_path("same_name_collisions_js");
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

/// JS: throw in error-check branch should be recognized as a terminator,
/// suppressing cfg-error-fallthrough false positives.
#[test]
fn error_throw_terminates() {
    let dir = fixture_path("error_throw_terminates");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
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

// ── EJS / config / debug endpoint fixtures ──────────────────────────────────

/// EJS template: detects unescaped `<%- query %>` and `<%- resultHtml %>`
/// but not `<%- include(...) %>` or `<%= safe %>`.
#[test]
fn ejs_xss() {
    let dir = fixture_path("ejs_xss");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Express session config: detects httpOnly: false, secure: false,
/// sameSite: "none", and hardcoded secret.
#[test]
fn insecure_session_config() {
    let dir = fixture_path("insecure_session_config");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Debug endpoint: process.env → res.json() should be caught by taint.
#[test]
fn debug_endpoint() {
    let dir = fixture_path("debug_endpoint");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Internal path-prefix redirects should be suppressed; open redirects should fire.
#[test]
fn internal_redirect_taint() {
    let dir = fixture_path("internal_redirect_taint");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Route registration methods (router.get/post) and session lifecycle should
/// not propagate taint or generate findings.
#[test]
fn route_registration_noise() {
    let dir = fixture_path("route_registration_noise");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn route_registration_noise_frameworks() {
    let dir = fixture_path("route_registration_noise_frameworks");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Dynamic HTTP module dispatch: lib = require("http"), lib.request(url)
/// should be resolved as SSRF sink via module alias tracking.
#[test]
fn dynamic_dispatch_ssrf() {
    let dir = fixture_path("dynamic_dispatch_ssrf");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Cross-file info leak: service returns process.env data (source-independent
/// taint), caller passes to res.json() sink.
#[test]
fn cross_file_info_leak() {
    let dir = fixture_path("cross_file_info_leak");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python `subprocess.run(cmd, shell=True)` where `cmd` is user-controlled —
/// the multi-kwarg SHELL_ESCAPE gate activates.  Validates end-to-end wiring
/// of `CallMeta.kwargs` through `classify_gated_sink`'s `dangerous_kwargs`
/// path (presence-aware shell=True → dangerous).
#[test]
fn python_subprocess_shell_true_tainted() {
    let dir = fixture_path("python_subprocess_shell_true");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python `subprocess.run([cmd], shell=False)` — shell kwarg present but not
/// dangerous.  The gate must not fire and no taint flow should be reported.
#[test]
fn python_subprocess_shell_false_safe() {
    let dir = fixture_path("python_subprocess_shell_false_safe");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python `subprocess.run([cmd])` — no shell kwarg (default shell=False).
/// The gate must not fire and no taint flow should be reported.
#[test]
fn python_subprocess_shell_default_safe() {
    let dir = fixture_path("python_subprocess_shell_default_safe");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
