//! Phase 6 regression guard: edit-and-rescan parity for anonymous functions.
//!
//! The scanner identifies anonymous / closure / lambda bodies by
//! `FuncKey.disambig`.  Before Phase 6 that field was the function node's
//! `start_byte`, so inserting a line *above* an unchanged anonymous
//! function shifted its identity and invalidated persisted callback
//! bindings and SSA summaries that referenced it — producing different
//! diagnostics for semantically identical code.
//!
//! Phase 6 replaced the disambig with a depth-first preorder index over
//! the file's function nodes.  That index is stable against edits that do
//! not add or remove functions, so these tests assert:
//!
//!   * A local edit above an anonymous function leaves the finding set
//!     unchanged modulo line-number shifts.
//!   * A cross-file callback flow where one file gets a comment added
//!     above the exported anonymous function still resolves end-to-end on
//!     the rescan.
//!
//! Both tests share the *same* on-disk SQLite index between scans to
//! exercise the stable-disambig invariant against real cached
//! `FuncKey`s.

#[allow(dead_code)]
mod common;

use common::test_config;
use nyx_scanner::commands::index::build_index;
use nyx_scanner::commands::scan::{Diag, scan_with_index_parallel};
use nyx_scanner::database::index::Indexer;
use nyx_scanner::utils::config::AnalysisMode;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
//  Fingerprint that ignores line shifts of a known delta.
// ─────────────────────────────────────────────────────────────────────────────

/// Stable per-finding key across a known `line_delta` shift.  Includes
/// enough structural fields to distinguish genuine divergence from a
/// pure line-offset reshuffle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ShiftedKey {
    rel_path: String,
    adjusted_line: i64,
    col: usize,
    rule_id: String,
    severity: String,
    path_validated: bool,
}

/// Normalize a rule id so the embedded `(source N:M)` suffix on taint
/// findings — which names the *source* line — is shifted by `line_delta`
/// instead of compared literally.
fn normalize_rule_id(id: &str, line_delta: i64) -> String {
    let Some(open) = id.find("(source ") else {
        return id.to_string();
    };
    let Some(close_rel) = id[open..].find(')') else {
        return id.to_string();
    };
    let body = &id[open + "(source ".len()..open + close_rel];
    let Some((l, c)) = body.split_once(':') else {
        return id.to_string();
    };
    let (Ok(line), Ok(col)) = (l.parse::<i64>(), c.parse::<i64>()) else {
        return id.to_string();
    };
    let rest = &id[open + close_rel + 1..];
    format!(
        "{}(source {}:{}){}",
        &id[..open],
        line - line_delta,
        col,
        rest,
    )
}

fn shifted_key(d: &Diag, fixture_root: &Path, line_delta: i64) -> ShiftedKey {
    let rel = Path::new(&d.path)
        .strip_prefix(fixture_root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| d.path.clone())
        .replace('\\', "/");
    ShiftedKey {
        rel_path: rel,
        adjusted_line: d.line as i64 - line_delta,
        col: d.col,
        rule_id: normalize_rule_id(&d.id, line_delta),
        severity: d.severity.as_db_str().to_string(),
        path_validated: d.path_validated,
    }
}

fn shifted_set(diags: &[Diag], fixture_root: &Path, line_delta: i64) -> BTreeSet<ShiftedKey> {
    diags
        .iter()
        .map(|d| shifted_key(d, fixture_root, line_delta))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Scan helper: reuse the same DB pool across scans.
// ─────────────────────────────────────────────────────────────────────────────

fn indexed_scan(
    project: &str,
    pool: &Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    root: &Path,
    mode: AnalysisMode,
) -> Vec<Diag> {
    let cfg = test_config(mode);
    scan_with_index_parallel(project, Arc::clone(pool), &cfg, false, root).expect("indexed scan")
}

fn cold_build_index(project: &str, root: &Path, db_path: &Path, mode: AnalysisMode) {
    let cfg = test_config(mode);
    build_index(project, root, db_path, &cfg, false).expect("build_index");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Test 1 — local edit above a nested anonymous function.
// ─────────────────────────────────────────────────────────────────────────────

const LOCAL_FIXTURE_BEFORE: &str = "\
function apply(fn, data) { return fn(data); }
const cmd = process.env.USER_CMD;
apply(function (x) { require('child_process').exec(x); }, cmd);
";

/// Insert a single blank line at the top of the file.
fn prepend_blank(s: &str) -> String {
    format!("\n{s}")
}

#[test]
fn anon_fn_finding_stable_across_blank_line_prepend() {
    let td = tempfile::tempdir().expect("tempdir");
    let root = td.path().to_path_buf();
    let js_path = root.join("handler.js");
    fs::write(&js_path, LOCAL_FIXTURE_BEFORE).expect("write fixture");

    let db_path = root.join("incremental.sqlite");
    cold_build_index("incr-local", &root, &db_path, AnalysisMode::Full);
    let pool = Indexer::init(&db_path).expect("init pool");

    // Step 1: baseline scan.
    let before_diags = indexed_scan("incr-local", &pool, &root, AnalysisMode::Full);
    let before = shifted_set(&before_diags, &root, 0);

    // Must actually exercise an anonymous-function flow, otherwise the
    // test is vacuously green.
    assert!(
        !before.is_empty(),
        "baseline must emit at least one finding to exercise anon-fn identity; got none.\n\
         Raw diags: {:#?}",
        before_diags
    );

    // Step 2: prepend a blank line (shifts every byte offset but changes
    // no semantics).  Re-scan using the *same* on-disk index so cross-
    // scan state (summaries, callback bindings) is exercised.
    fs::write(&js_path, prepend_blank(LOCAL_FIXTURE_BEFORE)).expect("rewrite fixture");
    let after_diags = indexed_scan("incr-local", &pool, &root, AnalysisMode::Full);
    let after = shifted_set(&after_diags, &root, 1);

    assert_eq!(
        before, after,
        "edit-and-rescan parity broken: findings diverge after unrelated blank-line prepend.\n\
         Before (line delta 0): {:#?}\n\
         After  (line delta 1): {:#?}\n\
         Raw before: {:#?}\n\
         Raw after:  {:#?}",
        before, after, before_diags, after_diags
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Test 2 — cross-file callback resolution after comment-line insert.
// ─────────────────────────────────────────────────────────────────────────────

const CROSS_FILE_A_BEFORE: &str = "\
module.exports = function (cmd) {
    require('child_process').exec(cmd);
};
";

const CROSS_FILE_A_AFTER: &str = "\
// unrelated comment added above the exported callback
module.exports = function (cmd) {
    require('child_process').exec(cmd);
};
";

const CROSS_FILE_B: &str = "\
const run = require('./a');
run(process.env.INPUT);
";

#[test]
fn cross_file_anon_callback_stable_across_comment_insert() {
    let td = tempfile::tempdir().expect("tempdir");
    let root = td.path().to_path_buf();
    let a = root.join("a.js");
    let b = root.join("b.js");
    fs::write(&a, CROSS_FILE_A_BEFORE).expect("write a.js");
    fs::write(&b, CROSS_FILE_B).expect("write b.js");

    let db_path = root.join("incremental.sqlite");
    cold_build_index("incr-cross", &root, &db_path, AnalysisMode::Full);
    let pool = Indexer::init(&db_path).expect("init pool");

    let before_diags = indexed_scan("incr-cross", &pool, &root, AnalysisMode::Full);

    // The cross-file flow should resolve: b.js → a.js (exported anon
    // function) → child_process.exec.  Count taint findings in either
    // file as the structural invariant — rank/line may legitimately
    // differ between scans, but the *presence* of a taint finding on
    // the sink side must not regress.
    fn taint_count_in(diags: &[Diag], rel: &str) -> usize {
        diags
            .iter()
            .filter(|d| {
                d.id.starts_with("taint-unsanitised-flow")
                    && d.path.replace('\\', "/").ends_with(rel)
            })
            .count()
    }

    let before_count =
        taint_count_in(&before_diags, "a.js") + taint_count_in(&before_diags, "b.js");
    assert!(
        before_count > 0,
        "baseline must emit a cross-file taint finding through the exported anon callback; \
         got none.  Raw diags: {:#?}",
        before_diags
    );

    // Edit a.js: prepend a comment line above the exported anon fn.
    fs::write(&a, CROSS_FILE_A_AFTER).expect("rewrite a.js");
    let after_diags = indexed_scan("incr-cross", &pool, &root, AnalysisMode::Full);
    let after_count = taint_count_in(&after_diags, "a.js") + taint_count_in(&after_diags, "b.js");

    assert_eq!(
        before_count, after_count,
        "cross-file anon callback resolution regressed after unrelated comment insert \
         (before={before_count}, after={after_count}).\n\
         Raw before: {:#?}\n\
         Raw after:  {:#?}",
        before_diags, after_diags
    );
}
