//! Attack surface ranking for scan diagnostics.
//!
//! Computes a deterministic score for each [`Diag`] using only in-memory
//! information (severity, evidence, source kind, rule ID, validation state).
//! The score is used to sort findings so that truncation keeps the most
//! exploitable / important results.

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence};
use crate::patterns::Severity;
use std::hash::{DefaultHasher, Hash, Hasher};

/// Computed attack-surface ranking for a single diagnostic.
#[derive(Debug, Clone)]
pub struct AttackRank {
    pub score: f64,
    /// Breakdown of score components (for debug/display purposes).
    pub components: Vec<(String, String)>,
}

/// Compute an attack-surface score for `diag`.
///
/// The score is a positive `f64`; higher means more exploitable / important.
/// Components are returned for optional debug/display.
pub fn compute_attack_rank(diag: &Diag) -> AttackRank {
    let mut score = 0.0_f64;
    let mut components: Vec<(String, String)> = Vec::new();

    // ── 1. Severity base ────────────────────────────────────────────────
    let sev_score = match diag.severity {
        Severity::High => 60.0,
        Severity::Medium => 30.0,
        Severity::Low => 10.0,
    };
    score += sev_score;
    components.push(("severity".into(), format!("{sev_score}")));

    // ── 2. Analysis kind bonus ──────────────────────────────────────────
    //
    // Taint-confirmed findings are the strongest signal.  State findings
    // (resource lifecycle / auth) are next.  CFG-structural findings
    // without taint evidence rank lower.  AST-only pattern matches are
    // the weakest.
    let kind_bonus = analysis_kind_bonus(&diag.id, diag.evidence.as_ref());
    score += kind_bonus;
    if kind_bonus != 0.0 {
        components.push(("analysis_kind".into(), format!("{kind_bonus}")));
    }

    // ── 3. Evidence strength / source-kind priority ─────────────────────
    let evidence_bonus = evidence_strength(diag);
    score += evidence_bonus;
    if evidence_bonus != 0.0 {
        components.push(("evidence".into(), format!("{evidence_bonus}")));
    }

    // ── 4. State finding sub-ranking ────────────────────────────────────
    let state_bonus = state_finding_bonus(&diag.id);
    score += state_bonus;
    if state_bonus != 0.0 {
        components.push(("state_rule".into(), format!("{state_bonus}")));
    }

    // ── 5. Path validation penalty ──────────────────────────────────────
    //
    // If a taint path is guarded by a validation predicate, the finding
    // has higher informational value but lower exploitability because the
    // guard may prevent the vulnerability from being triggered.  Apply a
    // small penalty (–5) to push validated paths below otherwise-equal
    // unvalidated ones without changing the overall ranking tier.
    let path_validated = diag.evidence.as_ref().map_or(diag.path_validated, |ev| {
        ev.notes.iter().any(|n| n == "path_validated")
    });
    if path_validated {
        score -= 5.0;
        components.push(("path_validated_penalty".into(), "-5".into()));
    }

    // ── 6. Confidence adjustment ─────────────────────────────────────
    if let Some(conf) = diag.confidence {
        let conf_adj = match conf {
            Confidence::High => 3.0,
            Confidence::Medium => 0.0,
            Confidence::Low => -5.0,
        };
        score += conf_adj;
        if conf_adj != 0.0 {
            components.push(("confidence".into(), format!("{conf_adj}")));
        }
    }

    AttackRank { score, components }
}

/// Deterministic sort key for a diagnostic.
///
/// Two diags with identical scores are tie-broken by:
///   severity (High < Medium < Low in the `Ord` impl, so we negate)
///   → rule ID → file path → line → col → message hash
///
/// Returns a tuple suitable for `sort_by`.
pub fn sort_key(diag: &Diag) -> impl Ord {
    let sev_ord: u8 = match diag.severity {
        Severity::High => 0,
        Severity::Medium => 1,
        Severity::Low => 2,
    };
    let msg_hash = {
        let mut h = DefaultHasher::new();
        diag.message.hash(&mut h);
        h.finish()
    };
    (
        sev_ord,
        diag.id.clone(),
        diag.path.clone(),
        diag.line,
        diag.col,
        msg_hash,
    )
}

/// Sort diagnostics in-place by descending attack-surface score, then by
/// deterministic tie-breaker.  Populates `rank_score` on each `Diag`.
pub fn rank_diags(diags: &mut [Diag]) {
    let ranks: Vec<AttackRank> = diags.iter().map(|d| compute_attack_rank(d)).collect();
    for (d, rank) in diags.iter_mut().zip(ranks.iter()) {
        d.rank_score = Some(rank.score);
        if !rank.components.is_empty() {
            d.rank_reason = Some(rank.components.clone());
        }
    }
    diags.sort_by(|a, b| {
        let sa = a.rank_score.unwrap_or(0.0);
        let sb = b.rank_score.unwrap_or(0.0);
        sb.partial_cmp(&sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| sort_key(a).cmp(&sort_key(b)))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Scoring helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Bonus based on analysis kind inferred from rule ID + evidence.
fn analysis_kind_bonus(rule_id: &str, evidence: Option<&Evidence>) -> f64 {
    if rule_id.starts_with("taint-") {
        // Taint-confirmed flow is the strongest signal
        10.0
    } else if rule_id.starts_with("state-") {
        // State-model findings (resource / auth) are strong
        8.0
    } else if rule_id.starts_with("cfg-") {
        // CFG-structural findings: boost if evidence exists
        if evidence.is_some_and(|e| !e.is_empty()) {
            5.0
        } else {
            3.0
        }
    } else {
        // AST-only pattern match
        0.0
    }
}

/// Bonus from evidence strength: number of evidence items and source-kind
/// priority.
fn evidence_strength(diag: &Diag) -> f64 {
    let mut bonus = 0.0;

    if let Some(ev) = &diag.evidence {
        // Count structured evidence items (capped at 4)
        let item_count = ev.source.is_some() as usize
            + ev.sink.is_some() as usize
            + (ev.guards.len() + ev.sanitizers.len()).min(2);
        bonus += item_count.min(4) as f64;

        // Source-kind priority from evidence notes
        for note in &ev.notes {
            if let Some(kind) = note.strip_prefix("source_kind:") {
                bonus += source_kind_priority(kind);
                break;
            }
        }
    } else {
        // Fallback for DB-cached diags without structured evidence
        bonus += (diag.labels.len() as f64).min(4.0);
        for (label, value) in &diag.labels {
            if label == "Source" {
                bonus += source_kind_priority(value);
            }
        }
    }

    bonus
}

/// Priority bonus based on the source kind string found in evidence.
///
/// UserInput / EnvironmentConfig / Unknown are most exploitable.
/// FileSystem / Database are lower because the attacker needs a more
/// indirect vector.
fn source_kind_priority(source_value: &str) -> f64 {
    // Structured SourceKind enum values (from evidence.notes "source_kind:X")
    match source_value {
        "UserInput" => return 6.0,
        "EnvironmentConfig" => return 5.0,
        "FileSystem" => return 3.0,
        "Database" => return 2.0,
        "CaughtException" => return 2.0,
        "Unknown" => return 4.0,
        _ => {}
    }

    // Fallback: substring matching for legacy labels
    let lower = source_value.to_ascii_lowercase();
    if lower.contains("stdin")
        || lower.contains("argv")
        || lower.contains("request")
        || lower.contains("form")
        || lower.contains("query")
        || lower.contains("param")
        || lower.contains("header")
        || lower.contains("body")
        || lower.contains("read_line")
    {
        // Strong user-input signals
        6.0
    } else if lower.contains("env") || lower.contains("var(") || lower.contains("getenv") {
        // Environment / config — still attacker-controllable in many deployments
        5.0
    } else if lower.contains("read") || lower.contains("file") || lower.contains("open") {
        // File system — needs indirect vector
        3.0
    } else if lower.contains("query") || lower.contains("fetch") || lower.contains("select") {
        // Database — needs prior injection
        2.0
    } else {
        // Unknown / unrecognised — treat as moderately exploitable
        4.0
    }
}

/// Bonus for specific state-analysis rule IDs.
fn state_finding_bonus(rule_id: &str) -> f64 {
    match rule_id {
        "state-use-after-close" => 6.0,
        "state-unauthed-access" => 6.0,
        "state-double-close" => 3.0,
        "state-resource-leak" => 2.0,          // must-leak
        "state-resource-leak-possible" => 1.0, // may-leak
        _ => 0.0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_diag(
        severity: Severity,
        id: &str,
        path: &str,
        line: usize,
        labels: Vec<(String, String)>,
        path_validated: bool,
    ) -> Diag {
        Diag {
            path: path.into(),
            line,
            col: 1,
            severity,
            id: id.into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated,
            guard_kind: None,
            message: None,
            labels,
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
        }
    }

    // ── Ordering tests ──────────────────────────────────────────────────

    #[test]
    fn high_taint_user_input_ranks_above_medium_file_io() {
        let high_taint = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![
                ("Source".into(), "read_line() at 1:1".into()),
                ("Sink".into(), "exec()".into()),
            ],
            false,
        );
        let med_file = make_diag(
            Severity::Medium,
            "taint-unsanitised-flow (source 5:1)",
            "src/lib.rs",
            20,
            vec![
                ("Source".into(), "File::open() at 5:1".into()),
                ("Sink".into(), "write()".into()),
            ],
            false,
        );

        let score_high = compute_attack_rank(&high_taint).score;
        let score_med = compute_attack_rank(&med_file).score;
        assert!(
            score_high > score_med,
            "high taint user-input ({score_high}) should rank above medium file-io ({score_med})"
        );
    }

    #[test]
    fn must_leak_ranks_above_may_leak() {
        let must = make_diag(
            Severity::Medium,
            "state-resource-leak",
            "src/db.rs",
            30,
            vec![],
            false,
        );
        let may = make_diag(
            Severity::Low,
            "state-resource-leak-possible",
            "src/db.rs",
            35,
            vec![],
            false,
        );

        let score_must = compute_attack_rank(&must).score;
        let score_may = compute_attack_rank(&may).score;
        assert!(
            score_must > score_may,
            "must-leak ({score_must}) should rank above may-leak ({score_may})"
        );
    }

    #[test]
    fn cfg_without_evidence_ranks_below_taint_confirmed() {
        let taint = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![
                ("Source".into(), "env::var(\"CMD\") at 1:1".into()),
                ("Sink".into(), "exec()".into()),
            ],
            false,
        );
        let cfg_only = make_diag(
            Severity::High,
            "cfg-unguarded-sink",
            "src/main.rs",
            10,
            vec![],
            false,
        );

        let score_taint = compute_attack_rank(&taint).score;
        let score_cfg = compute_attack_rank(&cfg_only).score;
        assert!(
            score_taint > score_cfg,
            "taint-confirmed ({score_taint}) should rank above cfg-only ({score_cfg})"
        );
    }

    #[test]
    fn determinism_input_order_independent() {
        let d1 = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "a.rs",
            1,
            vec![("Source".into(), "stdin at 1:1".into())],
            false,
        );
        let d2 = make_diag(
            Severity::Medium,
            "cfg-unguarded-sink",
            "b.rs",
            2,
            vec![],
            false,
        );
        let d3 = make_diag(Severity::Low, "rs.code_exec.eval", "c.rs", 3, vec![], false);

        let mut order_a = vec![d1.clone(), d2.clone(), d3.clone()];
        let mut order_b = vec![d3, d1, d2];

        rank_diags(&mut order_a);
        rank_diags(&mut order_b);

        let ids_a: Vec<_> = order_a.iter().map(|d| (&d.id, d.line)).collect();
        let ids_b: Vec<_> = order_b.iter().map(|d| (&d.id, d.line)).collect();
        assert_eq!(
            ids_a, ids_b,
            "ranking must be deterministic regardless of input order"
        );
    }

    #[test]
    fn path_validated_penalty_applied() {
        let unvalidated = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![("Source".into(), "env::var(\"X\") at 1:1".into())],
            false,
        );
        let validated = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![("Source".into(), "env::var(\"X\") at 1:1".into())],
            true,
        );

        let score_unval = compute_attack_rank(&unvalidated).score;
        let score_val = compute_attack_rank(&validated).score;
        assert!(
            score_unval > score_val,
            "unvalidated ({score_unval}) should rank above validated ({score_val})"
        );
    }

    #[test]
    fn state_use_after_close_ranks_above_may_leak() {
        let uac = make_diag(
            Severity::High,
            "state-use-after-close",
            "x.rs",
            1,
            vec![],
            false,
        );
        let may = make_diag(
            Severity::Low,
            "state-resource-leak-possible",
            "x.rs",
            2,
            vec![],
            false,
        );

        let score_uac = compute_attack_rank(&uac).score;
        let score_may = compute_attack_rank(&may).score;
        assert!(score_uac > score_may);
    }

    #[test]
    fn unauthed_access_ranks_above_resource_leak() {
        let unauth = make_diag(
            Severity::High,
            "state-unauthed-access",
            "x.rs",
            1,
            vec![],
            false,
        );
        let leak = make_diag(
            Severity::Medium,
            "state-resource-leak",
            "x.rs",
            2,
            vec![],
            false,
        );

        let score_ua = compute_attack_rank(&unauth).score;
        let score_lk = compute_attack_rank(&leak).score;
        assert!(score_ua > score_lk);
    }

    #[test]
    fn ast_only_ranks_below_all_others_at_same_severity() {
        let ast = make_diag(
            Severity::High,
            "rs.code_exec.eval",
            "x.rs",
            1,
            vec![],
            false,
        );
        let cfg = make_diag(
            Severity::High,
            "cfg-unguarded-sink",
            "x.rs",
            2,
            vec![],
            false,
        );
        let taint = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "x.rs",
            3,
            vec![("Source".into(), "env::var(\"X\") at 1:1".into())],
            false,
        );
        let state = make_diag(
            Severity::High,
            "state-use-after-close",
            "x.rs",
            4,
            vec![],
            false,
        );

        let s_ast = compute_attack_rank(&ast).score;
        let s_cfg = compute_attack_rank(&cfg).score;
        let s_taint = compute_attack_rank(&taint).score;
        let s_state = compute_attack_rank(&state).score;

        assert!(s_ast < s_cfg, "AST ({s_ast}) < CFG ({s_cfg})");
        assert!(s_ast < s_taint, "AST ({s_ast}) < taint ({s_taint})");
        assert!(s_ast < s_state, "AST ({s_ast}) < state ({s_state})");
    }

    #[test]
    fn structured_evidence_source_kind_matches_legacy() {
        // Structured evidence with source_kind:UserInput note should give
        // the same source-kind bonus as a legacy "Source" label with user input.
        let mut structured = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![],
            false,
        );
        structured.evidence = Some(crate::evidence::Evidence {
            source: Some(crate::evidence::SpanEvidence {
                path: "src/main.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("read_line()".into()),
            }),
            sink: Some(crate::evidence::SpanEvidence {
                path: "src/main.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec!["source_kind:UserInput".into()],
            ..Default::default()
        });

        let legacy = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![
                ("Source".into(), "read_line() at 1:1".into()),
                ("Sink".into(), "exec()".into()),
            ],
            false,
        );

        let score_structured = compute_attack_rank(&structured).score;
        let score_legacy = compute_attack_rank(&legacy).score;
        assert_eq!(
            score_structured, score_legacy,
            "structured ({score_structured}) should equal legacy ({score_legacy})"
        );
    }

    #[test]
    fn evidence_item_count_capped_at_4() {
        let mut d = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![],
            false,
        );
        let span = || crate::evidence::SpanEvidence {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            kind: "guard".into(),
            snippet: None,
        };
        d.evidence = Some(crate::evidence::Evidence {
            source: Some(span()),
            sink: Some(span()),
            guards: vec![span(), span(), span()], // 3 guards
            sanitizers: vec![span()],             // 1 sanitizer
            state: None,
            notes: vec![],
            ..Default::default()
        });

        // item_count = 1 (source) + 1 (sink) + min(2, 3+1) = 4
        // evidence bonus should be exactly 4.0 (from items) + 4.0 (unknown source kind) = 8.0
        // ... but no source_kind note, so no source priority bonus
        let score = evidence_strength(&d);
        assert!(
            (score - 4.0).abs() < f64::EPSILON,
            "evidence item count should be capped at 4, got {score}"
        );
    }

    #[test]
    fn path_validated_from_evidence_notes() {
        let mut d = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "src/main.rs",
            10,
            vec![],
            false, // path_validated is false on Diag
        );
        d.evidence = Some(crate::evidence::Evidence {
            source: None,
            sink: None,
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec!["path_validated".into()],
            ..Default::default()
        });

        let rank = compute_attack_rank(&d);
        assert!(
            rank.components
                .iter()
                .any(|(k, _)| k == "path_validated_penalty"),
            "path_validated note in evidence should trigger penalty"
        );
    }

    // ── Confidence tests ────────────────────────────────────────────

    #[test]
    fn confidence_high_boosts_score() {
        let d_none = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "x.rs",
            1,
            vec![("Source".into(), "stdin at 1:1".into())],
            false,
        );
        let mut d_high = d_none.clone();
        d_high.confidence = Some(crate::evidence::Confidence::High);

        let score_none = compute_attack_rank(&d_none).score;
        let score_high = compute_attack_rank(&d_high).score;
        assert!(
            score_high > score_none,
            "High confidence ({score_high}) should score above None ({score_none})"
        );
    }

    #[test]
    fn confidence_low_demotes_score() {
        let d_none = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "x.rs",
            1,
            vec![("Source".into(), "stdin at 1:1".into())],
            false,
        );
        let mut d_low = d_none.clone();
        d_low.confidence = Some(crate::evidence::Confidence::Low);

        let score_none = compute_attack_rank(&d_none).score;
        let score_low = compute_attack_rank(&d_low).score;
        assert!(
            score_low < score_none,
            "Low confidence ({score_low}) should score below None ({score_none})"
        );
    }

    #[test]
    fn confidence_does_not_override_severity_tier() {
        // High-severity + Low-confidence should still beat Medium-severity + High-confidence.
        let mut high_sev_low_conf = make_diag(
            Severity::High,
            "taint-unsanitised-flow (source 1:1)",
            "x.rs",
            1,
            vec![("Source".into(), "stdin at 1:1".into())],
            false,
        );
        high_sev_low_conf.confidence = Some(crate::evidence::Confidence::Low);

        let mut med_sev_high_conf = make_diag(
            Severity::Medium,
            "taint-unsanitised-flow (source 2:1)",
            "x.rs",
            2,
            vec![("Source".into(), "stdin at 2:1".into())],
            false,
        );
        med_sev_high_conf.confidence = Some(crate::evidence::Confidence::High);

        let score_high_sev = compute_attack_rank(&high_sev_low_conf).score;
        let score_med_sev = compute_attack_rank(&med_sev_high_conf).score;
        assert!(
            score_high_sev > score_med_sev,
            "High-sev/Low-conf ({score_high_sev}) should still beat Med-sev/High-conf ({score_med_sev})"
        );
    }

    #[test]
    fn rank_reason_populated() {
        let d1 = make_diag(Severity::High, "taint-unsanitised-flow (source 1:1)", "a.rs", 1, vec![], false);
        let d2 = make_diag(Severity::Medium, "cfg-unguarded-sink", "b.rs", 2, vec![], false);
        let mut diags = vec![d1, d2];
        rank_diags(&mut diags);
        for d in &diags {
            assert!(d.rank_reason.is_some(), "rank_reason should be populated after rank_diags()");
            assert!(!d.rank_reason.as_ref().unwrap().is_empty(), "rank_reason should not be empty");
        }
    }
}
