//! Health-score scoring engine.
//!
//! `compute_health_score()` in `routes/overview.rs` was the original v1
//! formula.  This module hosts the v2 formula extracted as a pure
//! function over a `HealthInputs` struct so the scoring math is unit-
//! testable without app/database state, and so the regression test in
//! `tests/health_score_calibration.rs` can pin reference inputs to
//! expected score bands.
//!
//! The full calibration record is in `docs/health-score-audit.md`.
//! The customer-facing methodology is in `docs/health-score.md`.

use crate::commands::scan::Diag;
use crate::evidence::Confidence;
use crate::server::models::{BacklogStats, FindingSummary, HealthComponent, HealthScore};

// ── Tunables ─────────────────────────────────────────────────────────────────

/// Below this file count we apply no size adjustment.  A small repo with
/// one HIGH should hurt; we don't want a 50-file demo to get a free pass
/// just because it's small.
const SIZE_FLOOR_FILES: f64 = 500.0;

/// Maximum size dampening factor (sqrt-scaled).  At sqrt(20) ≈ 4.47x we
/// stop dampening — so a 5MLOC monorepo doesn't get an *extra* discount
/// over a 1MLOC repo for the same HIGH count.
const MAX_SIZE_RATIO: f64 = 20.0;

/// Below this finding count, the Triage-coverage component is shown for
/// transparency but contributes weight 0.0.  Punishing brand-new users
/// for not having triaged things they didn't need to triage was the
/// single biggest v1 fairness bug.
const TRIAGE_FLOOR: usize = 20;

/// Stale findings age threshold lives in `BacklogStats::stale_count`
/// (currently 30 days).  We use that count, but only apply the penalty
/// when there's at least one HIGH — stale LOWs are noise, stale HIGHs
/// are the failure mode we care about.
const STALE_PENALTY_PER_FINDING: f64 = 4.0;
const STALE_PENALTY_CAP: f64 = 20.0;

// ── Public API ───────────────────────────────────────────────────────────────

/// Pure inputs to the health-score calculation.  No app state, no DB
/// handles, no `ScanHistory` — those upstream concerns are flattened into
/// the few primitives the scorer actually consumes.
#[derive(Debug, Clone, Copy)]
pub struct HealthInputs<'a> {
    pub summary: &'a FindingSummary,
    pub findings: &'a [Diag],
    pub triage_coverage: f64,
    pub new_since_last: usize,
    pub fixed_since_last: usize,
    pub reintroduced: usize,
    /// Files scanned in the latest scan.  Used as a proxy for repo size
    /// when applying size-aware severity dampening.  `None` disables
    /// the size adjustment (matches v1 behaviour for callers that
    /// don't have file-count plumbed yet).
    pub repo_files: Option<u64>,
    /// Backlog stats from the overview pipeline.  Used for the
    /// stale-HIGH penalty.  `None` is fine on first scans (no aging
    /// data yet).
    pub backlog: Option<&'a BacklogStats>,
    /// Whether we have at least two completed scans to compare against.
    /// Without history, Trend is meaningless (every value defaults to
    /// "no change" = 50) — same fairness bug that drove the Triage
    /// floor.  When `false`, the Trend component is shown but
    /// contributes weight 0.
    pub has_history: bool,
}

/// Compute the health score from pure inputs.
pub fn compute(inp: &HealthInputs<'_>) -> HealthScore {
    let high = inp.summary.by_severity.get("HIGH").copied().unwrap_or(0);
    let med = inp.summary.by_severity.get("MEDIUM").copied().unwrap_or(0);
    let low = inp.summary.by_severity.get("LOW").copied().unwrap_or(0);
    let total = inp.summary.total;

    // Quality lints: code-hygiene rules carry their own family marker
    // (`*.quality.*` or `quality.*`).  They're discounted heavily so a
    // clippy-style cleanup deck doesn't dominate the score.
    let quality_count = inp
        .findings
        .iter()
        .filter(|f| f.id.contains(".quality.") || f.id.starts_with("quality."))
        .count();
    let security_low = low.saturating_sub(quality_count.min(low));

    // ── Component 1: Severity pressure ───────────────────────────────
    let severity_score = severity_component(
        high,
        med,
        security_low,
        quality_count,
        inp.repo_files,
        inp.backlog,
    );

    // ── Component 2: Confidence quality ──────────────────────────────
    let conf_score = if inp.findings.is_empty() {
        100u8
    } else {
        let mut hi = 0usize;
        let mut me = 0usize;
        for f in inp.findings {
            match f.confidence {
                Some(Confidence::High) => hi += 1,
                Some(Confidence::Medium) => me += 1,
                _ => {}
            }
        }
        let raw = (hi as f64 + me as f64 * 0.5) / inp.findings.len() as f64;
        (raw * 100.0).round().clamp(0.0, 100.0) as u8
    };

    // ── Component 3: Trend ───────────────────────────────────────────
    let trend_score = {
        let net = inp.fixed_since_last as i64 - inp.new_since_last as i64;
        (50 + net * 5).clamp(0, 100) as u8
    };

    // ── Component 4: Triage coverage ─────────────────────────────────
    // When the finding count is below TRIAGE_FLOOR, we keep the
    // component visible (so the dashboard explains *why* it's not
    // counted) but contribute weight 0 — a fresh user with two
    // findings shouldn't be punished 20% of their score for not
    // having gone through the triage flow.
    let triage_active = total >= TRIAGE_FLOOR;
    let triage_score = (inp.triage_coverage * 100.0).round().clamp(0.0, 100.0) as u8;

    // ── Component 5: Regression resistance ───────────────────────────
    let regression_score = if inp.reintroduced == 0 {
        100u8
    } else {
        ((100i64 - inp.reintroduced as i64 * 10).max(0)) as u8
    };

    let components = vec![
        HealthComponent {
            label: "Severity pressure".into(),
            score: severity_score,
            weight: 0.30,
            detail: severity_detail_string(
                high,
                med,
                security_low,
                quality_count,
                inp.repo_files,
                inp.backlog,
            ),
        },
        HealthComponent {
            label: "Confidence quality".into(),
            score: conf_score,
            weight: 0.15,
            detail: "Higher confidence = clearer signal from the scanner".into(),
        },
        HealthComponent {
            label: "Trend".into(),
            score: trend_score,
            weight: if inp.has_history { 0.20 } else { 0.0 },
            detail: if inp.has_history {
                format!(
                    "Net {} since last scan ({} fixed, {} new)",
                    inp.fixed_since_last as i64 - inp.new_since_last as i64,
                    inp.fixed_since_last,
                    inp.new_since_last
                )
            } else {
                "Not applicable: no prior scan to compare against (re-scan to populate)".into()
            },
        },
        HealthComponent {
            label: "Triage coverage".into(),
            score: triage_score,
            weight: if triage_active { 0.20 } else { 0.0 },
            detail: if triage_active {
                format!(
                    "{:.0}% of findings have a triage state",
                    inp.triage_coverage * 100.0
                )
            } else {
                format!(
                    "Not applicable: only {total} finding{} (need ≥{TRIAGE_FLOOR} to evaluate)",
                    plural_s(total)
                )
            },
        },
        HealthComponent {
            label: "Regression resistance".into(),
            score: regression_score,
            weight: 0.15,
            detail: if inp.reintroduced == 0 {
                "No previously-fixed findings have returned".into()
            } else {
                format!(
                    "{} previously-fixed finding{} returned",
                    inp.reintroduced,
                    plural_s(inp.reintroduced)
                )
            },
        },
    ];

    // Weighted blend, renormalized so a dropped component (weight=0)
    // doesn't drag the final score down.
    let weight_sum: f64 = components.iter().map(|c| c.weight).sum();
    let blended: f64 = components
        .iter()
        .map(|c| c.score as f64 * c.weight)
        .sum();
    let raw_score = (blended / weight_sum.max(0.0001)).clamp(0.0, 100.0);

    // Final-score ceiling keyed on HIGH count.  The
    // `high_count_ceiling` we apply to the severity *component* alone
    // gets diluted when other components drop out (e.g. on a
    // fresh-scan repo with one HIGH and nothing else, severity
    // contributes only 30% of a 60% weight pool, leaving plenty of
    // room for an unfair A).  This cap is the security-engineer
    // backstop: "any HIGH means no A; many HIGHs means no B."
    // Applied to the *blended* score so it can't be averaged away.
    let high_total_cap = high_total_ceiling(high);
    let score = raw_score.min(high_total_cap).round() as u8;

    let grade = grade_for(score).to_string();

    HealthScore {
        score,
        grade,
        components,
    }
}

// ── Internals ────────────────────────────────────────────────────────────────

fn severity_component(
    high: usize,
    med: usize,
    security_low: usize,
    quality_count: usize,
    repo_files: Option<u64>,
    backlog: Option<&BacklogStats>,
) -> u8 {
    let weighted_raw = (high as f64) * 10.0
        + (med as f64) * 3.0
        + (security_low as f64) * 0.5
        + (quality_count as f64) * 0.2;

    let size_factor = size_dampening_factor(repo_files);
    let weighted_adjusted = weighted_raw / size_factor;

    // Logarithmic mapping — the same shape as v1, parameterized so test
    // cases can verify boundary values mathematically.
    let raw_score = if weighted_adjusted <= 0.0 {
        100.0
    } else {
        100.0 - 30.0 * (1.0 + weighted_adjusted / 5.0).log10()
    };

    // HIGH-count ceilings.  Independent of size: a 5MLOC repo with one
    // unhandled HIGH still has an unhandled HIGH.  These caps express
    // the security-engineer prior "any HIGH means you don't get an A
    // on severity".
    let high_cap = high_count_ceiling(high);
    let mut score = raw_score.min(high_cap).clamp(0.0, 100.0);

    // Stale-HIGH penalty.  Only fires when there's at least one HIGH
    // *and* the backlog has 30d+ stale findings.  This is a sentinel
    // for the "rotting bug" failure mode where untriaged HIGHs sit
    // open for months and the score still looks fine.
    let stale = stale_high_penalty(high, backlog);
    score = (score - stale).clamp(0.0, 100.0);

    score.round() as u8
}

fn size_dampening_factor(repo_files: Option<u64>) -> f64 {
    match repo_files {
        None => 1.0,
        Some(f) => {
            let ratio = (f as f64 / SIZE_FLOOR_FILES).max(1.0).min(MAX_SIZE_RATIO);
            ratio.sqrt()
        }
    }
}

fn high_count_ceiling(high: usize) -> f64 {
    match high {
        0 => 100.0,
        1..=2 => 84.0,    // any HIGH → severity component caps at B+
        3..=5 => 75.0,    // 3-5 HIGHs → severity caps at C
        _ => 65.0,        // 6+ HIGHs → severity caps at D
    }
}

/// Final-score ceiling keyed on HIGH count.  Applied *after* blending
/// so it can't be averaged away by other components.  This is the
/// "any HIGH means no A" guarantee — non-negotiable regardless of
/// triage hygiene, confidence, trend, or repo size.
fn high_total_ceiling(high: usize) -> f64 {
    match high {
        0 => 100.0,
        1..=2 => 89.0,    // 1-2 HIGHs → at most a B
        3..=5 => 79.0,    // 3-5 HIGHs → at most a C
        _ => 69.0,        // 6+ HIGHs → at most a D
    }
}

fn stale_high_penalty(high: usize, backlog: Option<&BacklogStats>) -> f64 {
    let Some(b) = backlog else { return 0.0 };
    if high == 0 || b.stale_count == 0 {
        return 0.0;
    }
    let raw = b.stale_count as f64 * STALE_PENALTY_PER_FINDING;
    raw.min(STALE_PENALTY_CAP)
}

fn severity_detail_string(
    high: usize,
    med: usize,
    security_low: usize,
    quality_count: usize,
    repo_files: Option<u64>,
    backlog: Option<&BacklogStats>,
) -> String {
    let weighted_raw = (high as f64) * 10.0
        + (med as f64) * 3.0
        + (security_low as f64) * 0.5
        + (quality_count as f64) * 0.2;
    let size_factor = size_dampening_factor(repo_files);

    let mut parts = vec![format!("{weighted_raw:.0} weighted points")];

    parts.push(if quality_count > 0 {
        format!(
            "{high} High, {med} Medium, {security_low} Low (security) + {quality_count} quality"
        )
    } else {
        format!("{high} High, {med} Medium, {security_low} Low")
    });

    if let Some(f) = repo_files {
        if (size_factor - 1.0).abs() > 0.01 {
            parts.push(format!(
                "size factor {size_factor:.2}× ({f} files scanned)"
            ));
        }
    }

    let stale = stale_high_penalty(high, backlog);
    if stale > 0.0 {
        if let Some(b) = backlog {
            parts.push(format!(
                "−{stale:.0} stale-HIGH penalty ({} finding{} >30d open)",
                b.stale_count,
                plural_s(b.stale_count)
            ));
        }
    }

    parts.join(" · ")
}

fn grade_for(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

fn plural_s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{FindingCategory, Severity};

    fn diag(severity: Severity, id: &str, conf: Option<Confidence>) -> Diag {
        Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity,
            id: id.into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: Vec::new(),
            confidence: conf,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
        }
    }

    fn summary_of(findings: &[Diag]) -> FindingSummary {
        let mut s = FindingSummary {
            total: findings.len(),
            ..Default::default()
        };
        for d in findings {
            *s.by_severity
                .entry(d.severity.as_db_str().to_string())
                .or_insert(0) += 1;
        }
        s
    }

    fn inputs<'a>(
        summary: &'a FindingSummary,
        findings: &'a [Diag],
        triage: f64,
        files: Option<u64>,
        backlog: Option<&'a BacklogStats>,
    ) -> HealthInputs<'a> {
        HealthInputs {
            summary,
            findings,
            triage_coverage: triage,
            new_since_last: 0,
            fixed_since_last: 0,
            reintroduced: 0,
            repo_files: files,
            backlog,
            has_history: true,
        }
    }

    fn inputs_first_scan<'a>(
        summary: &'a FindingSummary,
        findings: &'a [Diag],
        triage: f64,
        files: Option<u64>,
        backlog: Option<&'a BacklogStats>,
    ) -> HealthInputs<'a> {
        HealthInputs {
            has_history: false,
            ..inputs(summary, findings, triage, files, backlog)
        }
    }

    #[test]
    fn clean_first_scan_scores_a() {
        // No findings, no history (first scan): both Triage and Trend
        // drop out — clean repo gets a clean A.
        let findings: Vec<Diag> = vec![];
        let s = summary_of(&findings);
        let inp = inputs_first_scan(&s, &findings, 0.0, Some(100), None);
        let h = compute(&inp);
        assert!(
            h.score >= 90,
            "clean first-scan repo should grade ≥A, got {}",
            h.score
        );
        assert_eq!(h.grade, "A");
    }

    #[test]
    fn clean_repo_with_history_scores_a_or_b() {
        // Clean repo *with* history (history present, but no
        // change-since-last) drops Triage but keeps Trend at 50.  This
        // grades ~88 (B).  The B is honest: nothing got better either,
        // so we don't claim improvement.
        let findings: Vec<Diag> = vec![];
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.0, Some(100), None);
        let h = compute(&inp);
        assert!(h.score >= 80, "clean-with-history repo expected ≥B, got {}", h.score);
    }

    #[test]
    fn one_high_only_caps_severity_at_b_plus() {
        let findings = vec![diag(Severity::High, "rs.taint.sqli", Some(Confidence::High))];
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.0, Some(100), None);
        let h = compute(&inp);
        // Severity component must respect the high_count_ceiling=84 cap.
        let sev = h.components.iter().find(|c| c.label == "Severity pressure").unwrap();
        assert!(sev.score <= 84, "1 HIGH should cap severity ≤84, got {}", sev.score);
    }

    #[test]
    fn many_high_only_caps_severity_at_d() {
        let findings: Vec<Diag> = (0..10)
            .map(|_| diag(Severity::High, "rs.taint.sqli", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.0, Some(100), None);
        let h = compute(&inp);
        let sev = h.components.iter().find(|c| c.label == "Severity pressure").unwrap();
        assert!(sev.score <= 65, "6+ HIGHs should cap severity ≤65, got {}", sev.score);
    }

    #[test]
    fn one_high_total_score_capped_at_b() {
        // The "1-HIGH-only on first scan" trap: if other components drop
        // out, the severity component's cap gets diluted in the blend.
        // The total-score ceiling backstops it.
        let findings = vec![diag(Severity::High, "rs.taint.x", Some(Confidence::High))];
        let s = summary_of(&findings);
        let inp = inputs_first_scan(&s, &findings, 0.0, Some(100), None);
        let h = compute(&inp);
        assert!(
            h.score <= 89,
            "1 HIGH on first scan must not grade A (≤89 = B), got {}",
            h.score
        );
        assert_ne!(h.grade, "A", "1 HIGH should never grade A");
    }

    #[test]
    fn six_plus_high_total_score_capped_at_d() {
        // "6+ HIGHs means at most a D", regardless of how clean the
        // rest of the posture is.  This is the defensible bottom-floor
        // for an angry-customer interrogation.
        let findings: Vec<Diag> = (0..8)
            .map(|_| diag(Severity::High, "rs.taint.x", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        // Even with 100% triage and history showing improvement, the
        // total-score ceiling still binds.
        let inp = HealthInputs {
            summary: &s,
            findings: &findings,
            triage_coverage: 1.0,
            new_since_last: 0,
            fixed_since_last: 50,
            reintroduced: 0,
            repo_files: Some(100_000), // huge repo, max size dampening
            backlog: None,
            has_history: true,
        };
        let h = compute(&inp);
        assert!(
            h.score <= 69,
            "6+ HIGHs must not grade above D (≤69), got {} ({})",
            h.score, h.grade
        );
    }

    #[test]
    fn thousand_low_only_does_not_score_zero() {
        // The "1000 LOWs only" case: v1 mapped this to severity ≈ 18,
        // total ≈ 26 (F).  Because LOWs are weighted 0.5 and we apply a
        // log curve, this should at minimum not zero out.  Importantly
        // a sea-of-LOWs repo also benefits from the no-HIGH ceiling
        // (≤100 instead of being capped down).
        let findings: Vec<Diag> = (0..1000)
            .map(|_| diag(Severity::Low, "rs.foo", Some(Confidence::Medium)))
            .collect();
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.0, Some(2000), None);
        let h = compute(&inp);
        let sev = h.components.iter().find(|c| c.label == "Severity pressure").unwrap();
        // 1000 * 0.5 = 500 weighted; size_factor=sqrt(2000/500)=2; adj=250
        // → 100 - 30*log10(51) ≈ 100 - 51.2 = 48.8 → 49.
        // The exact value depends on size_factor and isn't load-bearing
        // for the bound we want to assert here.
        assert!(sev.score >= 30, "1000 LOWs should keep severity ≥30, got {}", sev.score);
        assert!(sev.score <= 70, "1000 LOWs should keep severity ≤70, got {}", sev.score);
    }

    #[test]
    fn quality_lints_only_barely_dent_severity() {
        // 200 quality lints (all LOW) — should still score very well.
        let findings: Vec<Diag> = (0..200)
            .map(|_| diag(Severity::Low, "rs.quality.unwrap", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.0, Some(500), None);
        let h = compute(&inp);
        let sev = h.components.iter().find(|c| c.label == "Severity pressure").unwrap();
        // 200 quality * 0.2 = 40 weighted; size_factor=1; → 100 - 30*log10(9) ≈ 71.4
        assert!(sev.score >= 60, "quality-only repo should keep severity ≥60, got {}", sev.score);
    }

    #[test]
    fn triage_dropped_when_total_under_floor() {
        let findings = vec![diag(Severity::Medium, "rs.foo", Some(Confidence::High))];
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.0, Some(100), None);
        let h = compute(&inp);
        let triage = h.components.iter().find(|c| c.label == "Triage coverage").unwrap();
        assert_eq!(triage.weight, 0.0, "Triage should drop out under TRIAGE_FLOOR");
        assert!(triage.detail.contains("Not applicable"), "Triage detail should explain why");
    }

    #[test]
    fn triage_active_when_total_at_or_above_floor() {
        let findings: Vec<Diag> = (0..TRIAGE_FLOOR)
            .map(|_| diag(Severity::Low, "rs.foo", Some(Confidence::Medium)))
            .collect();
        let s = summary_of(&findings);
        let inp = inputs(&s, &findings, 0.5, Some(100), None);
        let h = compute(&inp);
        let triage = h.components.iter().find(|c| c.label == "Triage coverage").unwrap();
        assert!((triage.weight - 0.20).abs() < 0.0001);
        assert_eq!(triage.score, 50);
    }

    #[test]
    fn size_aware_severity_dampens_large_repo() {
        // Same 3 HIGHs, different size: a 100-file repo and a 10000-file
        // repo.  The big-repo severity score should be *higher* (better)
        // because the same HIGH count is spread over more code.
        let findings: Vec<Diag> = (0..3)
            .map(|_| diag(Severity::High, "rs.taint.x", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let small = compute(&inputs(&s, &findings, 0.0, Some(100), None));
        let large = compute(&inputs(&s, &findings, 0.0, Some(10000), None));
        let small_sev = small.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        let large_sev = large.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        assert!(
            large_sev >= small_sev,
            "size-aware: 10000-file repo severity {large_sev} should be ≥ 100-file repo {small_sev}"
        );
        // But the high_count_ceiling clamp at 75 (3 HIGHs) bites both.
        assert!(small_sev <= 75 && large_sev <= 75, "high-count ceiling must apply at all sizes");
    }

    #[test]
    fn size_dampening_capped_for_huge_repos() {
        // A 5MLOC repo (~50000 files) shouldn't get an extra discount
        // beyond a 1MLOC repo (~10000 files) on the same HIGH count.
        let findings: Vec<Diag> = (0..3)
            .map(|_| diag(Severity::High, "rs.taint.x", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let mlloc = compute(&inputs(&s, &findings, 0.0, Some(10_000), None));
        let mlloc5 = compute(&inputs(&s, &findings, 0.0, Some(50_000), None));
        let s1 = mlloc.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        let s5 = mlloc5.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        // Because of the size ratio cap the two should differ by at
        // most 1 point (rounding).  This is the explicit "no free
        // pass" guarantee.
        assert!(
            (s5 as i32 - s1 as i32).abs() <= 1,
            "size cap broken: 1MLOC severity {s1} vs 5MLOC severity {s5}"
        );
    }

    #[test]
    fn stale_high_penalty_kicks_in() {
        let findings = vec![diag(Severity::High, "rs.taint.x", Some(Confidence::High))];
        let s = summary_of(&findings);
        let backlog_clean = BacklogStats {
            oldest_open_days: Some(2),
            median_age_days: Some(1),
            stale_count: 0,
            age_buckets: vec![],
        };
        let backlog_stale = BacklogStats {
            oldest_open_days: Some(120),
            median_age_days: Some(60),
            stale_count: 5,
            age_buckets: vec![],
        };
        let fresh = compute(&inputs(&s, &findings, 0.0, Some(100), Some(&backlog_clean)));
        let rotting = compute(&inputs(&s, &findings, 0.0, Some(100), Some(&backlog_stale)));
        let f_sev = fresh.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        let r_sev = rotting.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        assert!(
            r_sev < f_sev,
            "stale-HIGH penalty did not fire: fresh={f_sev} rotting={r_sev}"
        );
    }

    #[test]
    fn stale_penalty_skipped_when_no_high() {
        // Stale findings without a HIGH should NOT trigger the penalty
        // — the penalty signals "rotting HIGH bug", not "old LOW noise".
        let findings = vec![diag(Severity::Low, "rs.x", Some(Confidence::Medium))];
        let s = summary_of(&findings);
        let backlog_stale = BacklogStats {
            oldest_open_days: Some(120),
            median_age_days: Some(60),
            stale_count: 5,
            age_buckets: vec![],
        };
        let r = compute(&inputs(&s, &findings, 0.0, Some(100), Some(&backlog_stale)));
        let r_sev = r.components.iter().find(|c| c.label == "Severity pressure").unwrap().score;
        // Without HIGHs the LOW gets weighted 0.5, almost no severity
        // pressure, so we just check it's not penalized into the floor.
        assert!(r_sev > 90, "stale LOWs alone should not crush severity, got {r_sev}");
    }

    #[test]
    fn grade_thresholds() {
        assert_eq!(grade_for(100), "A");
        assert_eq!(grade_for(90), "A");
        assert_eq!(grade_for(89), "B");
        assert_eq!(grade_for(80), "B");
        assert_eq!(grade_for(79), "C");
        assert_eq!(grade_for(70), "C");
        assert_eq!(grade_for(69), "D");
        assert_eq!(grade_for(60), "D");
        assert_eq!(grade_for(59), "F");
        assert_eq!(grade_for(0), "F");
    }
}
