//! CLI argument validation regression tests.
//!
//! Nyx's surface is a `clap` parser plus a handful of downstream validators
//! (`SeverityFilter::parse`, `Severity::from_str`, `Confidence::from_str`,
//! `apply_profile`).  These tests lock in the user-visible contract that
//! bad input exits non-zero with a message that names the offending flag —
//! a scanner that silently accepts a typo'd severity and returns zero
//! findings is a footgun in CI.
//!
//! The scanner binary reads its configuration from a platform-dependent
//! project directory (macOS: `$HOME/Library/Application Support/nyx`;
//! Linux: `$XDG_CONFIG_HOME/nyx`).  Each test redirects both env vars to a
//! tempdir so the developer's real config is never touched and runs are
//! reproducible.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

/// Build a scan command with a fresh config dir and a writable tempdir as
/// the scan target.  The caller layers extra args on top.
fn scan_cmd(tmp_home: &std::path::Path, scan_target: &std::path::Path) -> (Command, PathBuf) {
    let mut cmd = Command::cargo_bin("nyx").expect("nyx binary must exist");
    cmd.env("HOME", tmp_home)
        .env("XDG_CONFIG_HOME", tmp_home.join(".config"))
        .env("XDG_DATA_HOME", tmp_home.join(".local/share"))
        // Avoid the welcome banner / animation from interfering with exit codes.
        .env("NO_COLOR", "1");
    cmd.arg("scan").arg(scan_target);
    (cmd, scan_target.to_path_buf())
}

/// Prepare a scan tempdir with a single clean file so the scanner has a
/// valid target and only the flag being tested should produce an error.
fn prepare_scan_target() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ok.js"), b"var x = 1;\n").unwrap();
    dir
}

/// Nonexistent scan path: `Path::new(path).canonicalize()?` in `scan::handle`
/// returns an io::Error, which NyxError wraps and the process exits non-zero.
#[test]
fn scan_with_nonexistent_path_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let fake = home.path().join("does/not/exist/anywhere");
    let (mut cmd, _) = scan_cmd(home.path(), &fake);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(fake.to_string_lossy().as_ref()).or(
            // On some platforms the error wraps the path inside an IO error
            // message; accept either direct mention or a canonicalize-shaped
            // error so the assertion isn't brittle to errno text.
            predicate::str::contains("canonicalize")
                .or(predicate::str::contains("No such file"))
                .or(predicate::str::contains("not found")),
        ));
}

/// Clap enforces `ValueEnum` for `--format`; an unknown value fails at parse
/// time with a usage message that lists the valid enum values.
#[test]
fn scan_with_unknown_format_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--format").arg("unknown-format-xyz");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("format").and(predicate::str::contains("unknown-format-xyz").or(
            predicate::str::contains("possible values").or(predicate::str::contains("invalid value")),
        )));
}

/// Clap enforces `ValueEnum` for `--mode`; an unknown value fails at parse
/// time.
#[test]
fn scan_with_unknown_mode_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--mode").arg("bogus-mode-xyz");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("mode").and(
            predicate::str::contains("bogus-mode-xyz").or(predicate::str::contains("invalid value")),
        ));
}

/// `--severity BOGUS` fails at `SeverityFilter::parse` with a message naming
/// the flag.
#[test]
fn scan_with_invalid_severity_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--severity").arg("BOGUSSEV");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("severity"));
}

/// `--fail-on BOGUS` fails at `Severity::from_str`.
#[test]
fn scan_with_invalid_fail_on_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--fail-on").arg("BOGUSSEV");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("fail-on").or(predicate::str::contains("severity")));
}

/// `--min-confidence bogus` fails at `Confidence::from_str`.
#[test]
fn scan_with_invalid_min_confidence_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--min-confidence").arg("ultra-extreme");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("min-confidence").or(predicate::str::contains("confidence")));
}

/// `--profile nonexistent-profile` fails at `config.apply_profile` which
/// errors with "unknown profile".
#[test]
fn scan_with_unknown_profile_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--profile").arg("not-a-real-profile-xyz");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("profile"));
}

/// Sanity check: the scan command with no flags on a valid target succeeds.
/// Guards against a regression where the redirected `HOME` / `XDG_CONFIG_HOME`
/// setup breaks scans (which would invalidate every negative test above).
#[test]
fn scan_with_no_extra_flags_on_clean_target_succeeds() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--format").arg("json");

    cmd.assert().success();
}
