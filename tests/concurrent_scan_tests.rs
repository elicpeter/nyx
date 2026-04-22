//! Thread-safety regression for concurrent scans over the same directory.
//!
//! Production defaults run the scanner with `worker_threads > 1`, and callers
//! embedding `nyx_scanner` (the forthcoming `serve` UI, CI wrappers, scripted
//! harnesses) may invoke `scan_no_index` from multiple threads in the same
//! process.  Shared engine state — label tables, framework-detection caches,
//! tree-sitter thread-local parsers, rayon globals, `once_cell` statics —
//! must tolerate two simultaneous walks without races, panics, or diverging
//! outputs.
//!
//! This test is intentionally a smoke test: it runs two scans concurrently,
//! joins, and asserts the outputs are identical after canonicalization.  A
//! data-race regression typically surfaces here as either a panic, a missing
//! diag, or nondeterministic ordering after sort.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::scan_no_index;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::Path;
use std::thread;

fn test_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    // Use multiple workers on each scan so both outer threads exercise the
    // rayon pool concurrently.
    cfg.performance.worker_threads = Some(2);
    cfg.performance.batch_size = 8;
    cfg.performance.channel_multiplier = 1;
    cfg
}

/// Build a mixed-language tempdir with a handful of files that each produce
/// deterministic findings.  Languages chosen to cover most of the shared
/// pipeline state (parser caches, label tables, SSA lowering).
fn build_tree(root: &Path) {
    // JS: command injection via cp.exec(req.query.cmd).
    std::fs::write(
        root.join("cmdi.js"),
        b"const cp = require('child_process');\n\
          const express = require('express');\n\
          const app = express();\n\
          app.get('/x', (req, res) => { cp.exec(req.query.cmd); res.send('ok'); });\n",
    )
    .unwrap();

    // Python: os.system on tainted input.
    std::fs::write(
        root.join("cmdi.py"),
        b"import os, flask\n\
          app = flask.Flask(__name__)\n\
          @app.route('/x')\n\
          def h():\n\
          \x20\x20\x20\x20cmd = flask.request.args.get('cmd')\n\
          \x20\x20\x20\x20os.system(cmd)\n\
          \x20\x20\x20\x20return 'ok'\n",
    )
    .unwrap();

    // Go: exec.Command with tainted query param.
    std::fs::write(
        root.join("cmdi.go"),
        b"package main\n\
          import (\n\
          \t\"net/http\"\n\
          \t\"os/exec\"\n\
          )\n\
          func handler(w http.ResponseWriter, r *http.Request) {\n\
          \tcmd := r.URL.Query().Get(\"cmd\")\n\
          \texec.Command(cmd).Run()\n\
          }\n",
    )
    .unwrap();

    // Ruby: system() on params.
    std::fs::write(
        root.join("cmdi.rb"),
        b"require 'sinatra'\n\
          get '/x' do\n\
          \x20\x20system(params[:cmd])\n\
          end\n",
    )
    .unwrap();
}

/// Canonicalize a diag list for equality comparison.  Finding output ordering
/// depends on rayon scheduling — the individual fields must be identical but
/// the sequence is not.  We sort by a stable composite key and stringify
/// (Diag itself doesn't derive Ord).
fn canonical_fingerprint(diags: &[Diag]) -> Vec<String> {
    let mut v: Vec<String> = diags
        .iter()
        .map(|d| format!("{}|{}|{}|{}|{:?}", d.path, d.line, d.col, d.id, d.severity))
        .collect();
    v.sort();
    v
}

#[test]
fn two_concurrent_scans_produce_identical_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    build_tree(&root);

    // Capture an initial single-threaded run so we have a reference point —
    // if the concurrent run produced a subset we want to know whether that
    // matches a known-good baseline or diverges from it.
    let baseline = scan_no_index(&root, &test_cfg()).expect("baseline scan must succeed");
    let baseline_fp = canonical_fingerprint(&baseline);
    assert!(
        !baseline_fp.is_empty(),
        "baseline scan produced no findings — test fixture lost signal"
    );

    let root_a = root.clone();
    let root_b = root.clone();
    let a = thread::spawn(move || scan_no_index(&root_a, &test_cfg()));
    let b = thread::spawn(move || scan_no_index(&root_b, &test_cfg()));

    let res_a = a.join().expect("scan thread A panicked");
    let res_b = b.join().expect("scan thread B panicked");

    let diags_a = res_a.expect("scan A returned error");
    let diags_b = res_b.expect("scan B returned error");

    let fp_a = canonical_fingerprint(&diags_a);
    let fp_b = canonical_fingerprint(&diags_b);

    assert_eq!(
        fp_a, fp_b,
        "concurrent scans diverged: A={fp_a:?}\nB={fp_b:?}"
    );
    assert_eq!(
        fp_a, baseline_fp,
        "concurrent scan diverged from baseline: concurrent={fp_a:?}\nbaseline={baseline_fp:?}"
    );
}

/// Four concurrent scans over the same tree — larger blast radius for
/// serialization bugs in shared caches.  Runs on a small tree to keep
/// CI time reasonable.
#[test]
fn four_concurrent_scans_all_succeed_identically() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    build_tree(&root);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let r = root.clone();
            thread::spawn(move || scan_no_index(&r, &test_cfg()))
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("scan thread panicked"))
        .collect();

    let mut fingerprints: Vec<Vec<String>> = Vec::new();
    for (i, r) in results.into_iter().enumerate() {
        let diags = r.unwrap_or_else(|e| panic!("concurrent scan #{i} returned error: {e}"));
        fingerprints.push(canonical_fingerprint(&diags));
    }

    let first = &fingerprints[0];
    for (i, fp) in fingerprints.iter().enumerate().skip(1) {
        assert_eq!(fp, first, "scan #{i} diverged from scan #0");
    }
}
