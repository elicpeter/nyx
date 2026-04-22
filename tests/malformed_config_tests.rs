//! Malformed-config regression tests.
//!
//! Nyx reads its user configuration from `<config_dir>/nyx.local` (TOML).
//! The CLI path is `main.rs → Config::load(config_dir)`; this file exercises
//! `Config::load` directly so the tests cover the exact same code path the
//! binary uses, independent of platform-specific `ProjectDirs` behaviour
//! around redirecting `HOME`/`XDG_CONFIG_HOME`.
//!
//! The goal of each test is the same as it would be via the binary: a bad
//! config file must produce a diagnostic error (not a panic, not a silent
//! default), and the error message must be actionable enough that a user
//! can find the offending file.
//!
//! `nyx.conf` is auto-created by `Config::load` if missing, so the tests
//! rely on `nyx.local` as the user-overridable surface.

use nyx_scanner::errors::NyxError;
use nyx_scanner::utils::config::Config;
use std::path::Path;

/// Write `contents` into `<dir>/nyx.local` and invoke `Config::load`.  Also
/// pre-creates an empty `nyx.conf` so `Config::load` does not need to write
/// one during the test (keeps the tempdir state deterministic).
fn load_with_local(dir: &Path, contents: &str) -> Result<Config, NyxError> {
    std::fs::write(dir.join("nyx.local"), contents).unwrap();
    // Seed a minimal nyx.conf so `Config::load` skips the example-creation
    // step.  The default merge path still runs on top.
    if !dir.join("nyx.conf").exists() {
        std::fs::write(dir.join("nyx.conf"), "").unwrap();
    }
    Config::load(dir).map(|(cfg, _note)| cfg)
}

/// Syntactically invalid TOML must surface a `Toml` parse error rather than
/// panicking or silently loading defaults.  The error message carries the
/// parser's location info; we do not pin the exact wording because it
/// depends on the `toml` crate version.
#[test]
fn syntactically_invalid_toml_returns_parse_error() {
    let tmp = tempfile::tempdir().unwrap();

    // `foo = [[` is an unterminated array-of-tables header — pure syntax
    // error at the lexer level.
    let result = load_with_local(tmp.path(), "foo = [[\n");

    match result {
        Err(NyxError::Toml(e)) => {
            let msg = e.to_string();
            assert!(
                !msg.is_empty(),
                "toml parse error should carry a diagnostic message",
            );
        }
        Ok(_) => panic!("invalid TOML must not load as a valid config"),
        Err(other) => panic!("expected NyxError::Toml, got {other:?}"),
    }
}

/// Valid TOML but wrong field type (string where int expected) must fail
/// deserialisation, not be silently coerced.
#[test]
fn type_mismatch_in_known_field_returns_error() {
    let tmp = tempfile::tempdir().unwrap();

    // `performance.worker_threads` is typed `Option<usize>` — a bare string
    // is unambiguously wrong and must be rejected.
    let contents = "\
[performance]\n\
worker_threads = \"auto\"\n\
";
    let result = load_with_local(tmp.path(), contents);

    match result {
        Err(NyxError::Toml(e)) => {
            let msg = e.to_string();
            // Deserialisation errors should name either the field or the
            // expected type — be lenient on exact wording.
            assert!(
                msg.contains("worker_threads")
                    || msg.to_lowercase().contains("integer")
                    || msg.to_lowercase().contains("expected")
                    || msg.to_lowercase().contains("invalid type"),
                "type-mismatch error should mention the field or expected type: {msg}",
            );
        }
        Ok(_) => panic!("type mismatch must not deserialize as valid config"),
        Err(other) => panic!("expected NyxError::Toml, got {other:?}"),
    }
}

/// A semantically-invalid config (e.g. `server.port = 0`) must be caught by
/// `Config::validate`, surfacing as a `ConfigValidation` error that lists
/// the offending section and field.  This is a second layer of defence past
/// deserialisation — types parse fine, but values are out of range.
#[test]
fn out_of_range_value_fails_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let contents = "\
[server]\n\
port = 0\n\
";
    let result = load_with_local(tmp.path(), contents);

    match result {
        Err(NyxError::ConfigValidation(errs)) => {
            assert!(
                errs.iter().any(|e| e.section == "server" && e.field == "port"),
                "validation should flag server.port: {errs:?}",
            );
        }
        Ok(_) => panic!("server.port = 0 must fail validation"),
        Err(other) => panic!("expected ConfigValidation error, got {other:?}"),
    }
}

/// Unknown top-level section: document current behaviour.  `Config` uses
/// `#[serde(default)]` without `deny_unknown_fields`, so unknown sections
/// are silently dropped.  This test pins that contract so a future change
/// (e.g. switching to strict mode) is explicit rather than surprising.
///
/// If strict-mode is later desired, this test should be flipped to assert
/// the error path — but in either case the behaviour is explicit.
#[test]
fn unknown_top_level_section_is_tolerated_today() {
    let tmp = tempfile::tempdir().unwrap();
    let contents = "\
[not_a_real_section]\n\
some_field = \"value\"\n\
[scanner]\n\
# a known section, so the file as a whole still parses\n\
";
    let result = load_with_local(tmp.path(), contents);

    // Current contract: unknown sections silently ignored.  A config with
    // only junk keys still loads.
    let cfg = result.expect("unknown sections should not fail load today");
    assert_eq!(cfg.scanner.mode, Config::default().scanner.mode);
}

/// Unknown field inside a known section: same warn-or-ignore contract as
/// unknown sections.  Serde drops unknown keys by default.
#[test]
fn unknown_field_in_known_section_is_tolerated_today() {
    let tmp = tempfile::tempdir().unwrap();
    let contents = "\
[scanner]\n\
mode = \"full\"\n\
bogus_unknown_field = 42\n\
";
    let result = load_with_local(tmp.path(), contents);
    let cfg = result.expect("unknown field in known section should not fail load today");
    // mode was set in the user file; verify it landed.
    assert!(matches!(
        cfg.scanner.mode,
        nyx_scanner::utils::config::AnalysisMode::Full
    ));
}

/// Empty `nyx.local` (zero-byte file) must load cleanly — the merge overlays
/// nothing onto defaults.
#[test]
fn empty_user_config_uses_defaults() {
    let tmp = tempfile::tempdir().unwrap();
    let result = load_with_local(tmp.path(), "");
    let cfg = result.expect("empty nyx.local must load as pure defaults");
    let defaults = Config::default();
    assert_eq!(cfg.scanner.mode, defaults.scanner.mode);
    assert_eq!(cfg.server.port, defaults.server.port);
}

/// An invalid profile name (non-alphanumeric, non-underscore) must be
/// flagged by `Config::validate`.  Locks in the existing validator contract.
#[test]
fn invalid_profile_name_fails_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let contents = "\
[profiles.\"has-a-dash\"]\n\
mode = \"ast\"\n\
";
    let result = load_with_local(tmp.path(), contents);
    match result {
        Err(NyxError::ConfigValidation(errs)) => {
            assert!(
                errs.iter().any(|e| e.section == "profiles"),
                "validation should flag the profiles section: {errs:?}",
            );
        }
        Ok(_) => panic!("profile name 'has-a-dash' should fail validation"),
        Err(other) => panic!("expected ConfigValidation error, got {other:?}"),
    }
}
