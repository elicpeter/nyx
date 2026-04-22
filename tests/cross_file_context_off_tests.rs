//! Context-sensitive off-path tests: with `NYX_CONTEXT_SENSITIVE=0`
//! (the runtime switch for the inline context-sensitive pipeline) the
//! analyser falls back to summary-based resolution across file
//! boundaries.  Cross-file inline is *strictly additive* over this
//! path: the four fixtures in `tests/fixtures/cross_file_context_*`
//! must still satisfy their `expectations.json` under summary-only
//! resolution, and the sanitiser fixture must remain free of taint
//! findings.
//!
//! This binary is split from `cross_file_context_tests.rs` because
//! Cargo compiles each `tests/*.rs` file into its own test binary —
//! separate processes — so the `NYX_CONTEXT_SENSITIVE` env flip here
//! does not race against the default-on tests running in parallel.
//!
//! The switch is read by `AnalysisOptions::current()` via the legacy
//! env-var fallback (no `install()` call happens in a test binary), so
//! toggling the env var takes effect on every scan through this
//! process.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn count_prefix(diags: &[Diag], prefix: &str) -> usize {
    diags.iter().filter(|d| d.id.starts_with(prefix)).count()
}

/// Install CS-off for this entire test binary.  Because every test
/// file compiles into its own binary, no sibling test sees this flip.
fn disable_context_sensitive() {
    // SAFETY: env-var mutation is unsound under concurrent reads; we
    // call this at the start of every test in this binary *before*
    // `scan_no_index` reaches `AnalysisOptions::current()`.  No other
    // thread is observing the env var concurrently because Cargo
    // spawns one thread per test and each one sets the same value.
    unsafe {
        std::env::set_var("NYX_CONTEXT_SENSITIVE", "0");
    }
}

/// Cross-file inline must be strictly additive: the summary path was
/// already correct for this fixture before cross-file inline landed,
/// and the inline override must not drop recall when we disable it.
#[test]
fn two_call_sites_still_passes_without_context_sensitivity() {
    disable_context_sensitive();
    let dir = fixture_path("cross_file_context_two_call_sites");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// The cross-file sanitiser regression guard: with summary-only
/// resolution the `xss` library is still a registered sanitiser and
/// the taint finding must not surface.  This also rules out the
/// possibility that cross-file inline was the only thing suppressing
/// the finding in the default-on tests.
#[test]
fn sanitizer_still_clean_without_context_sensitivity() {
    disable_context_sensitive();
    let dir = fixture_path("cross_file_context_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    assert_eq!(
        count_prefix(&diags, "taint-unsanitised-flow"),
        0,
        "sanitiser fixture must remain clean under summary-only \
         resolution. Full diags: {:?}",
        diags
            .iter()
            .map(|d| format!("{}:{}:{}", d.path, d.line, d.id))
            .collect::<Vec<_>>()
    );
}

/// Deep chain (A->B->C) finding persists under summary-only
/// resolution via the AST-pattern `py.cmdi` path.  Cross-file inline
/// does not change the AST-pattern suite, so this assertion is a
/// simple regression guard.
#[test]
fn deep_chain_still_passes_without_context_sensitivity() {
    disable_context_sensitive();
    let dir = fixture_path("cross_file_context_deep_chain");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Callback fixture produces its finding via the summary-level
/// callback-argument mechanism (apply's summary + direct
/// `child_process.exec` arg).  CS=off must keep that finding because
/// the mechanism lives outside the inline pipeline.
#[test]
fn callback_fixture_still_passes_without_context_sensitivity() {
    disable_context_sensitive();
    let dir = fixture_path("cross_file_context_callback");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
