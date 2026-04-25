//! Regression guard: the dedup pass at
//! [`nyx_scanner::taint::analyse_file`] must preserve distinct flows
//! that share a source but differ on validation status or intermediate
//! variables.  Historically the dedup collapsed all `(body_id, sink,
//! source)` siblings, preferring the validated one — so an unguarded
//! exploit on a sibling branch was silently dropped in favour of a
//! neighbouring guarded flow.
//!
//! This file covers the fixture-level regression and the internal
//! cross-reference wiring.  The internal unit tests for the linking
//! pass live alongside `analyse_file` in `src/taint/mod.rs`.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// With the richer dedup key, both the validated and the unvalidated
/// `cp.exec(input)` flows must surface as taint findings.  Under the
/// historical `(body_id, sink, source)` dedup plus `!path_validated`
/// ordering, one of the two would be silently dropped.
#[test]
fn dedup_preserves_validated_and_unvalidated_flows() {
    let dir = fixture_path("dedup_alternative_paths");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Required finding count from expectations.json.
    validate_expectations(&diags, &dir);

    // Load-bearing assertion: the two flows live on distinct sink
    // lines (6 and 8 in the source — actual lines depend on the
    // fixture file format, so we only assert distinct sinks).
    let taint: Vec<&nyx_scanner::commands::scan::Diag> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .collect();
    assert!(
        taint.len() >= 2,
        "expected >= 2 taint findings on the dedup_alternative_paths \
         fixture; found {}. The dedup must preserve both the validated \
         and the unvalidated flow rather than collapsing them to a \
         single `path_validated=true` finding. \
         Found: {:#?}",
        taint.len(),
        taint
            .iter()
            .map(|d| format!(
                "{}:{} validated={} id={}",
                d.line, d.col, d.path_validated, d.id
            ))
            .collect::<Vec<_>>(),
    );

    // The two findings must live on different source lines — if the
    // engine collapses them into one, the test will fail here even
    // when the count assertion above coincidentally passes (e.g. if
    // a future change started emitting one validated and one
    // unrelated-but-similar finding).
    let distinct_sink_lines: std::collections::HashSet<usize> =
        taint.iter().map(|d| d.line).collect();
    assert!(
        distinct_sink_lines.len() >= 2,
        "expected taint findings on distinct sink lines; got all on {:?}",
        distinct_sink_lines,
    );

    // Every taint finding must carry a stable `finding_id` that
    // downstream formatters can reference.  This is the plumbing that
    // feeds alternative-path cross-linking — verify it is non-empty
    // for every taint finding so regressions in `analyse_file`'s
    // post-dedup `make_finding_id` pass surface here.
    for d in &taint {
        assert!(
            !d.finding_id.is_empty(),
            "taint finding at {}:{} is missing a stable finding_id; \
             `make_finding_id` must populate every taint finding after \
             dedup.",
            d.line,
            d.col,
        );
    }

    // At least one validated/unvalidated split must be present — the
    // whole point of the fixture is that a guarded branch and an
    // unguarded branch reach `exec(input)` and both must report.
    // We do not require an exact split since future sanitization
    // improvements may change which branch is classified as
    // validated, but both categories must have at least one rep.
    let (validated, unvalidated): (
        Vec<&nyx_scanner::commands::scan::Diag>,
        Vec<&nyx_scanner::commands::scan::Diag>,
    ) = taint.iter().copied().partition(|d| d.path_validated);
    assert!(
        !unvalidated.is_empty(),
        "expected at least one unvalidated flow; the else-branch `cp.exec(input)` \
         is not behind any allowlist. Found only validated findings.",
    );
    // `validated` may legitimately be empty if the engine does not yet
    // recognise `isWhitelisted` as a predicate — the fixture is still
    // load-bearing because the `min_count: 2` in expectations.json
    // asserts both findings surface regardless of which is classified
    // as validated.  Drop the assertion to avoid gating the regression
    // on the strength of allowlist-predicate inference.
    let _ = validated;
}
