//! Symex encoding/decoding transform classification, Java / Go / Ruby.
//!
//! Each fixture sets up a tainted source flowing through a known
//! escape/encode helper into a sink whose vulnerability class is *not*
//! neutralised by that helper (e.g., `URLEncoder.encode` into a SQL
//! sink). The taint engine still emits a finding because the engine's
//! sanitizer label only strips the matching cap; symex layers a
//! structured `Encode(...)` node onto the symbolic value and the
//! witness rendering surfaces the transform name.
//!
//! The acceptance check is per-language: at least one taint diagnostic
//! lands, and at least one such diagnostic carries an
//! `evidence.symbolic.witness` string mentioning the transform's
//! display name (`urlEncode`, `htmlEscape`, etc.), proving the new
//! Java/Go/Ruby classifiers in `src/symex/strings.rs` are wired through
//! to witness generation.

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("symex")
        .join(name)
}

fn scan_isolated(fixture: &Path) -> Vec<Diag> {
    let tmp = tempfile::TempDir::with_prefix("nyx_symex_transform_").expect("tempdir");
    let dest = tmp.path().join(fixture.file_name().unwrap());
    std::fs::copy(fixture, &dest).expect("copy fixture");
    let cfg = test_config(AnalysisMode::Full);
    nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed")
}

/// Find a taint finding whose symex witness contains *any* of the given
/// token alternatives. Either the transform display name (e.g.
/// `urlEncode`) appears verbatim, produced by the
/// `detect_transform_mismatch` annotation when the symex value tree still
/// carries a tainted symbol, or the witness has been concrete-folded
/// through `encode_concrete_for_witness`, in which case the encoded
/// artifact (e.g. a percent-escape) appears in place of the original
/// characters. Both prove the new transform classifier is wired through
/// to witness generation.
fn find_witness_with_any<'a>(diags: &'a [Diag], tokens: &[&str]) -> Option<&'a Diag> {
    diags.iter().find(|d| {
        d.evidence
            .as_ref()
            .and_then(|e| e.symbolic.as_ref())
            .and_then(|s| s.witness.as_deref())
            .is_some_and(|w| tokens.iter().any(|t| w.contains(t)))
    })
}

fn assert_renderable_witness(diags: &[Diag], lang: &str, tokens: &[&str]) {
    let taint_diags: Vec<&Diag> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-"))
        .collect();
    assert!(
        !taint_diags.is_empty(),
        "[{lang}] expected ≥1 taint finding, got 0.\n  diags = {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>()
    );

    let with_witness = find_witness_with_any(diags, tokens);
    assert!(
        with_witness.is_some(),
        "[{lang}] expected ≥1 taint finding whose evidence.symbolic.witness \
         contains any of {:?}, got none.\n  witness summaries = {:#?}",
        tokens,
        taint_diags
            .iter()
            .map(|d| {
                let w = d
                    .evidence
                    .as_ref()
                    .and_then(|e| e.symbolic.as_ref())
                    .and_then(|s| s.witness.as_deref())
                    .unwrap_or("<none>");
                format!("{}:{} [{}] witness = {:?}", d.path, d.line, d.id, w)
            })
            .collect::<Vec<_>>()
    );
}

// Each test accepts the transform display name (`urlEncode`) OR a
// percent-escape artifact (`%28`, etc.). Either proves the symex
// classifier reached the witness layer:
//   - `urlEncode` appears via `detect_transform_mismatch` when the symex
//     value tree carries a tainted symbol with the wrong-class encode
//   - a percent-escape appears when `evaluate_concrete` folded
//     `Encode(UrlEncode, …)` through `encode_concrete_for_witness`
// The raw callee name is intentionally NOT accepted, it would appear
// even in the Display fallback when the classifier fails, making the
// assertion meaningless.

#[test]
fn symex_url_encoder_java_witness() {
    let path = fixture_path("symex_url_encoder_java.java");
    let diags = scan_isolated(&path);
    assert_renderable_witness(&diags, "java_url_encoder", &["urlEncode"]);
}

#[test]
fn symex_query_escape_go_witness() {
    let path = fixture_path("symex_query_escape_go.go");
    let diags = scan_isolated(&path);
    assert_renderable_witness(&diags, "go_query_escape", &["urlEncode"]);
}

#[test]
fn symex_cgi_escape_ruby_witness() {
    let path = fixture_path("symex_cgi_escape_ruby.rb");
    let diags = scan_isolated(&path);
    assert_renderable_witness(
        &diags,
        "ruby_cgi_escape",
        &["urlEncode", "%20", "%28", "%29", "%3D", "%26"],
    );
}
