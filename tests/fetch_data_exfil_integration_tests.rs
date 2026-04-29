//! Integration tests for the `Cap::DATA_EXFIL` detector class.
//!
//! Validates per-cap attribution at multi-gate call sites: a single `fetch`
//! call carries both an SSRF gate (URL flow) and a DATA_EXFIL gate (body /
//! headers / json flow), and a tainted body must not surface as SSRF and
//! vice versa.  Also sanity-checks the SARIF output so the new finding
//! class produces a distinct rule id.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;

fn js_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("js")
}

fn diags_for(file: &str) -> Vec<Diag> {
    let dir = js_fixture_dir();
    let all = scan_fixture_dir(&dir, AnalysisMode::Full);
    all.into_iter().filter(|d| d.path.ends_with(file)).collect()
}

#[test]
fn fetch_body_data_exfil_emits_data_exfil_not_ssrf() {
    let diags = diags_for("fetch_body_data_exfil.js");
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    let plain_taint = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .count();
    assert!(
        exfil >= 1,
        "expected at least one taint-data-exfiltration finding, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "fixed-URL fetch with tainted body must NOT emit SSRF \
         (taint-unsanitised-flow), got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn fetch_ssrf_url_tainted_emits_ssrf_not_data_exfil() {
    let diags = diags_for("fetch_ssrf_url_tainted.js");
    let ssrf = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .count();
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    assert!(
        ssrf >= 1,
        "expected at least one taint-unsanitised-flow (SSRF) finding, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        exfil,
        0,
        "tainted-URL fetch must NOT emit DATA_EXFIL, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn sarif_distinguishes_data_exfil_rule_id_from_ssrf() {
    use nyx_scanner::output::build_sarif;

    let dir = js_fixture_dir();
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    let sarif = build_sarif(&diags, &dir);

    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("SARIF rules array");
    let rule_ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();

    assert!(
        rule_ids.contains(&"taint-data-exfiltration"),
        "SARIF rules must contain taint-data-exfiltration, got: {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"taint-unsanitised-flow"),
        "SARIF rules must contain taint-unsanitised-flow, got: {rule_ids:?}"
    );

    // Each finding should reference exactly one rule, and the cap-specific
    // class must not be folded back into the generic taint bucket.
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results array");
    let exfil_results = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("taint-data-exfiltration"))
        .count();
    let ssrf_results = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("taint-unsanitised-flow"))
        .count();
    assert!(
        exfil_results >= 1,
        "expected >= 1 SARIF result with ruleId taint-data-exfiltration, got {exfil_results}",
    );
    assert!(
        ssrf_results >= 1,
        "expected >= 1 SARIF result with ruleId taint-unsanitised-flow, got {ssrf_results}",
    );
}
