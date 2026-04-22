//! Panic-recovery regression tests for the filesystem scan pipeline.
//!
//! Nyx runs per-file analysis on untrusted input in parallel via rayon.  A
//! panic inside one file's analyser currently propagates out of the rayon
//! `flat_map_iter` closure and kills the whole scan.  These tests lock in
//! that observable contract so future work on opt-in panic recovery can tell
//! whether it wired up correctly.
//!
//! Injection mechanism: the `NYX_TEST_FORCE_PANIC_PATH` env var, read by
//! `src/ast.rs::maybe_inject_test_panic` at the top of `run_rules_on_bytes`
//! and `analyse_file_fused`.  Any file path containing the env-var value
//! triggers a deterministic panic.  The hook has zero behaviour when the env
//! var is unset, so unrelated tests are unaffected.

use nyx_scanner::scan_no_index;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Mutex;

/// Env-var writes are process-global — integration tests run multiple
/// `#[test]` functions in one binary, and rayon dispatches the analyser on
/// background threads that read the env table concurrently.  Serialize the
/// set/clear dance so a test that expects "no injection" never races a test
/// that sets the marker.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const INJECT_ENV: &str = "NYX_TEST_FORCE_PANIC_PATH";
const PANIC_MARKER: &str = "__NYX_PANIC__";

fn hostile_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 4;
    cfg.performance.channel_multiplier = 1;
    // Explicit: panic recovery is off by default; these tests assert the
    // "panic propagates" contract when this flag is false.
    cfg.scanner.enable_panic_recovery = false;
    cfg
}

/// Config variant that opts into the per-file panic-recovery path added in
/// release/0.5.0.  Inherits every other setting from `hostile_cfg`.
fn recovery_cfg() -> Config {
    let mut cfg = hostile_cfg();
    cfg.scanner.enable_panic_recovery = true;
    cfg
}

/// Run a scan with the panic-injection env var set and the marker restricted
/// to `marker_path_fragment`.  The env var is cleared after the closure even
/// if it panics.
fn with_panic_injection<F, R>(marker_path_fragment: &str, f: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: integration tests are single-process but multi-threaded via
    // rayon. The mutex above serializes env writes; within the critical
    // section, setting and reading the env var is well-defined.
    unsafe {
        std::env::set_var(INJECT_ENV, marker_path_fragment);
    }
    let result = std::panic::catch_unwind(f);
    unsafe {
        std::env::remove_var(INJECT_ENV);
    }
    drop(guard);
    result
}

/// With injection armed and a file whose path contains the marker, the scan
/// MUST fail in a way the caller can observe — either a propagated panic or
/// a returned error.  Silently succeeding would mean findings from poisoned
/// analysis were emitted as legitimate output.  We also verify the clean
/// file on disk is a plausible target (the injection only fires for the
/// marker path; a non-marker file must not produce a panic under this hook).
#[test]
fn scan_surfaces_injected_panic_from_worker() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Clean file — if the injection hook incorrectly fired on every path we
    // would see this one panic too.
    std::fs::write(
        root.join("normal.js"),
        b"const cp = require('child_process');\n\
          function run(cmd){ cp.exec(cmd); }\n",
    )
    .unwrap();

    // File whose path contains the marker — must trigger the injected panic.
    let poisoned = format!("{PANIC_MARKER}.js");
    std::fs::write(
        root.join(&poisoned),
        b"const cp = require('child_process');\n\
          function run(cmd){ cp.exec(cmd); }\n",
    )
    .unwrap();

    let root_buf = root.to_path_buf();
    let cfg = hostile_cfg();

    let outcome = with_panic_injection(
        PANIC_MARKER,
        AssertUnwindSafe(|| scan_no_index(&root_buf, &cfg)),
    );

    // Current behaviour (pre-`enable_panic_recovery`): the scan panics
    // out of rayon.  If a future phase adds panic containment, the scan
    // would instead return Ok with a warning — that counts as surfacing
    // the failure and is also acceptable here.  The thing we refuse to
    // accept silently is a successful scan that claims the poisoned file
    // was analysed without incident.
    match outcome {
        Err(_panic) => {
            // Panic propagated — expected today.
        }
        Ok(Err(_nyx_err)) => {
            // Graceful error — acceptable if recovery ever lands.
        }
        Ok(Ok(_diags)) => {
            // If the scan completes successfully, the poisoned file was
            // quietly dropped.  That would only be acceptable if a
            // diagnostic recorded the failure, which is not yet wired
            // up.  Fail loudly so the behaviour change is reviewed.
            panic!(
                "scan completed successfully while {INJECT_ENV} injection armed; \
                 either the hook did not fire or recovery silently swallowed the failure"
            );
        }
    }
}

/// Unrelated clean files must never trip the hook when the env var is unset.
/// Guard against accidental always-on behaviour in `maybe_inject_test_panic`.
#[test]
fn clean_scan_without_injection_does_not_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    std::fs::write(
        root.join("normal.js"),
        b"const cp = require('child_process');\n\
          function run(cmd){ cp.exec(cmd); }\n",
    )
    .unwrap();
    std::fs::write(root.join(format!("{PANIC_MARKER}.js")), b"var safe = 1;\n").unwrap();

    // Ensure the marker is not armed for this test even if a prior test
    // leaked state (belt-and-suspenders — `with_panic_injection` already
    // cleans up, but concurrent test binaries share a process env).
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::remove_var(INJECT_ENV);
    }
    let diags = scan_no_index(root, &hostile_cfg())
        .expect("clean scan with injection disarmed must succeed");
    drop(guard);

    // The JS file has cp.exec(cmd) on a tainted arg — at minimum one
    // finding should surface, proving the scan actually analysed files
    // rather than silently short-circuiting.
    assert!(
        diags
            .iter()
            .any(|d| Path::new(&d.path).ends_with("normal.js")),
        "expected a finding from normal.js, got {diags:?}",
    );
}

/// The injection hook MUST NOT fire when the env-var value is empty.  A stray
/// `export NYX_TEST_FORCE_PANIC_PATH=` in a developer's shell would otherwise
/// break every scan.
#[test]
fn empty_injection_marker_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    std::fs::write(root.join("normal.js"), b"var x = 1;\n").unwrap();

    let root_buf = root.to_path_buf();
    let outcome = with_panic_injection(
        "",
        AssertUnwindSafe(|| scan_no_index(&root_buf, &hostile_cfg())),
    );

    match outcome {
        Ok(Ok(_diags)) => {}
        other => panic!("empty injection marker should not trigger panic; got {other:?}"),
    }
}

/// With `enable_panic_recovery = true`, a panic in one file must not abort
/// the scan.  The poisoned file produces zero findings (its analyser never
/// finished), but the clean file's findings are preserved.  This is the
/// primary contract the feature exists to deliver.
#[test]
fn recovery_mode_skips_poisoned_file_and_continues() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Clean file with a tainted cp.exec — we expect at least one finding.
    std::fs::write(
        root.join("normal.js"),
        b"const cp = require('child_process');\n\
          function run(cmd){ cp.exec(cmd); }\n",
    )
    .unwrap();

    // Poisoned file whose path contains the panic marker.
    let poisoned = format!("{PANIC_MARKER}.js");
    std::fs::write(
        root.join(&poisoned),
        b"const cp = require('child_process');\n\
          function run(cmd){ cp.exec(cmd); }\n",
    )
    .unwrap();

    let root_buf = root.to_path_buf();
    let cfg = recovery_cfg();

    let outcome = with_panic_injection(
        PANIC_MARKER,
        AssertUnwindSafe(|| scan_no_index(&root_buf, &cfg)),
    );

    let diags = match outcome {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            panic!("recovery-mode scan returned error instead of skipping poisoned file: {e}")
        }
        Err(panic) => panic!(
            "recovery-mode scan propagated a panic that should have been contained: {panic:?}"
        ),
    };

    // The clean file must still surface its finding — proof the rayon
    // pipeline kept running after the poisoned worker panicked.
    assert!(
        diags
            .iter()
            .any(|d| Path::new(&d.path).ends_with("normal.js")),
        "expected a finding from normal.js after recovering from poisoned file; got {diags:?}",
    );

    // The poisoned file analyser panicked before it could emit anything, so
    // it must contribute no findings at all.  If any appeared they would be
    // based on partial (possibly unsound) state.
    assert!(
        !diags
            .iter()
            .any(|d| Path::new(&d.path).ends_with(poisoned.as_str())),
        "poisoned file {poisoned} must not produce findings in recovery mode; got {diags:?}",
    );
}
