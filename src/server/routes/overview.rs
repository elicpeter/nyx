#![allow(clippy::collapsible_if)]

use crate::commands::scan::Diag;
use crate::database::index::{Indexer, ScanRecord};
use crate::evidence::Confidence;
use crate::server::app::AppState;
use crate::server::models::{
    Insight, NoisyRule, OverviewResponse, ScanSummary, TrendPoint, by_language_from_findings,
    compute_fingerprint, summarize_findings, top_directories_from_findings, top_n_from_map,
};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use std::collections::{HashMap, HashSet};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/overview/trends", get(overview_trends))
}

/// GET /api/overview — aggregated dashboard data.
async fn overview(State(state): State<AppState>) -> Json<OverviewResponse> {
    // 1. Load latest findings (in-memory → DB fallback)
    let findings = crate::server::routes::findings::load_latest_findings(&state);

    // 2. Collect recent scans (in-memory + DB, deduped)
    let recent_scans = collect_recent_scans(&state, 10);

    // 3. Basic summary
    let summary = summarize_findings(&findings);
    let by_language = by_language_from_findings(&findings);

    // 4. Find latest completed scan info
    let latest_completed = recent_scans.iter().find(|s| s.status == "completed");
    let latest_scan_id = latest_completed.map(|s| s.id.clone());
    let latest_scan_at = latest_completed.and_then(|s| s.started_at.clone());
    let latest_scan_duration = latest_completed.and_then(|s| s.duration_secs);

    // 5. New/fixed since last scan
    let (new_since_last, fixed_since_last) = compute_delta(&state, &findings);

    // 6. High confidence rate
    let high_confidence_rate = if findings.is_empty() {
        0.0
    } else {
        let high_count = findings
            .iter()
            .filter(|d| d.confidence == Some(Confidence::High))
            .count();
        high_count as f64 / findings.len() as f64
    };

    // 7. Triage coverage
    let triage_coverage = compute_triage_coverage(&state, &findings);

    // 8. Top files, dirs, rules
    let top_files = top_n_from_map(&summary.by_file, 10);
    let top_directories = top_directories_from_findings(&findings, 10);
    let top_rules = top_n_from_map(&summary.by_rule, 10);

    // 9. Noisy rules
    let noisy_rules = compute_noisy_rules(&state, &findings, &summary.by_rule);

    // 10. Insights
    let insights = generate_insights(
        &summary,
        new_since_last,
        fixed_since_last,
        triage_coverage,
        &noisy_rules,
    );

    // 11. State
    let state_str = if recent_scans.iter().all(|s| s.status != "completed") {
        "empty".to_string()
    } else if is_fresh_scan(latest_completed) {
        "fresh".to_string()
    } else {
        "normal".to_string()
    };

    Json(OverviewResponse {
        state: state_str,
        total_findings: summary.total,
        new_since_last,
        fixed_since_last,
        high_confidence_rate,
        triage_coverage,
        latest_scan_duration_secs: latest_scan_duration,
        latest_scan_id,
        latest_scan_at,
        by_severity: summary.by_severity,
        by_category: summary.by_category,
        by_language,
        top_files,
        top_directories,
        top_rules,
        noisy_rules,
        recent_scans: recent_scans.into_iter().take(10).collect(),
        insights,
    })
}

/// GET /api/overview/trends — scan-over-scan finding counts.
async fn overview_trends(State(state): State<AppState>) -> Json<Vec<TrendPoint>> {
    let mut points = Vec::new();

    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(scans) = idx.list_scans(20) {
                let completed: Vec<&ScanRecord> =
                    scans.iter().filter(|s| s.status == "completed").collect();

                // Cap at 10 for performance
                for scan in completed.iter().rev().take(10) {
                    let total = scan.finding_count.unwrap_or(0) as usize;
                    let by_severity = scan
                        .findings_json
                        .as_deref()
                        .and_then(|json| serde_json::from_str::<Vec<Diag>>(json).ok())
                        .map(|diags| {
                            let mut sev: HashMap<String, usize> = HashMap::new();
                            for d in &diags {
                                *sev.entry(d.severity.as_db_str().to_string()).or_insert(0) += 1;
                            }
                            sev
                        })
                        .unwrap_or_default();

                    points.push(TrendPoint {
                        scan_id: scan.id.clone(),
                        timestamp: scan.started_at.clone().unwrap_or_default(),
                        total,
                        by_severity,
                    });
                }
            }
        }
    }

    Json(points)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Collect recent scans from in-memory jobs + DB, deduped by ID.
fn collect_recent_scans(state: &AppState, limit: usize) -> Vec<ScanSummary> {
    let mut seen = HashSet::new();
    let mut scans = Vec::new();

    // In-memory first
    for job in state.job_manager.list_jobs() {
        if seen.insert(job.id.clone()) {
            scans.push(ScanSummary {
                id: job.id.clone(),
                status: format!("{:?}", job.status).to_ascii_lowercase(),
                started_at: job.started_at.map(|t| t.to_rfc3339()),
                duration_secs: job.duration_secs,
                finding_count: job.findings.as_ref().map(|f| f.len() as i64),
            });
        }
    }

    // DB fallback
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(records) = idx.list_scans(limit as i64) {
                for r in records {
                    if seen.insert(r.id.clone()) {
                        scans.push(ScanSummary {
                            id: r.id,
                            status: r.status,
                            started_at: r.started_at,
                            duration_secs: r.duration_secs,
                            finding_count: r.finding_count,
                        });
                    }
                }
            }
        }
    }

    // Sort by started_at descending
    scans.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    scans.truncate(limit);
    scans
}

/// Compute new/fixed finding counts by comparing the two most recent completed scans.
fn compute_delta(state: &AppState, current_findings: &[Diag]) -> (usize, usize) {
    if current_findings.is_empty() {
        return (0, 0);
    }

    let current_fps: HashSet<String> = current_findings.iter().map(compute_fingerprint).collect();

    // Find previous completed scan's findings
    let previous_fps = load_previous_scan_fingerprints(state);
    if previous_fps.is_empty() {
        return (0, 0);
    }

    let new_count = current_fps.difference(&previous_fps).count();
    let fixed_count = previous_fps.difference(&current_fps).count();
    (new_count, fixed_count)
}

/// Load fingerprints from the second-most-recent completed scan.
fn load_previous_scan_fingerprints(state: &AppState) -> HashSet<String> {
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(scans) = idx.list_scans(10) {
                let completed: Vec<&ScanRecord> = scans
                    .iter()
                    .filter(|s| s.status == "completed" && s.findings_json.is_some())
                    .collect();

                // Skip the first (latest) completed scan — we want the previous one
                if let Some(prev) = completed.get(1) {
                    if let Some(json) = prev.findings_json.as_deref() {
                        if let Ok(diags) = serde_json::from_str::<Vec<Diag>>(json) {
                            return diags.iter().map(compute_fingerprint).collect();
                        }
                    }
                }
            }
        }
    }
    HashSet::new()
}

/// Compute triage coverage: fraction of findings with non-"open" triage state.
fn compute_triage_coverage(state: &AppState, findings: &[Diag]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let Some(ref pool) = state.db_pool else {
        return 0.0;
    };
    let Ok(idx) = Indexer::from_pool("_scans", pool) else {
        return 0.0;
    };

    let triage_map = idx.get_all_triage_states().unwrap_or_default();
    let suppression_rules = idx.get_suppression_rules().unwrap_or_default();

    let mut non_open = 0usize;
    for d in findings {
        let fp = compute_fingerprint(d);
        // Check explicit triage state
        if let Some((triage_state, _, _)) = triage_map.get(&fp) {
            if triage_state != "open" {
                non_open += 1;
                continue;
            }
        }
        // Check suppression rules
        let path = &d.path;
        let rule_id = &d.id;
        for rule in &suppression_rules {
            let matches = match rule.suppress_by.as_str() {
                "fingerprint" => fp == rule.match_value,
                "rule" => *rule_id == rule.match_value,
                "rule_in_file" => {
                    let key = format!("{rule_id}:{path}");
                    key == rule.match_value
                }
                "file" => *path == rule.match_value,
                _ => false,
            };
            if matches {
                non_open += 1;
                break;
            }
        }
    }

    non_open as f64 / findings.len() as f64
}

/// Compute noisy rules: high finding count + high suppression rate.
fn compute_noisy_rules(
    state: &AppState,
    findings: &[Diag],
    by_rule: &HashMap<String, usize>,
) -> Vec<NoisyRule> {
    let Some(ref pool) = state.db_pool else {
        return vec![];
    };
    let Ok(idx) = Indexer::from_pool("_scans", pool) else {
        return vec![];
    };

    let triage_map = idx.get_all_triage_states().unwrap_or_default();
    let suppression_rules = idx.get_suppression_rules().unwrap_or_default();

    // Count suppressed findings per rule
    let mut suppressed_per_rule: HashMap<String, usize> = HashMap::new();
    for d in findings {
        let fp = compute_fingerprint(d);
        let is_suppressed = triage_map
            .get(&fp)
            .map(|(s, _, _)| s == "suppressed" || s == "false_positive")
            .unwrap_or(false)
            || suppression_rules
                .iter()
                .any(|rule| match rule.suppress_by.as_str() {
                    "fingerprint" => fp == rule.match_value,
                    "rule" => d.id == rule.match_value,
                    "rule_in_file" => format!("{}:{}", d.id, d.path) == rule.match_value,
                    "file" => d.path == rule.match_value,
                    _ => false,
                });
        if is_suppressed {
            *suppressed_per_rule.entry(d.id.clone()).or_insert(0) += 1;
        }
    }

    let mut noisy: Vec<NoisyRule> = by_rule
        .iter()
        .filter_map(|(rule_id, &count)| {
            if count < 3 {
                return None;
            }
            let suppressed = suppressed_per_rule.get(rule_id).copied().unwrap_or(0);
            let rate = suppressed as f64 / count as f64;
            if rate >= 0.5 {
                Some(NoisyRule {
                    rule_id: rule_id.clone(),
                    finding_count: count,
                    suppression_rate: rate,
                })
            } else {
                None
            }
        })
        .collect();

    noisy.sort_by(|a, b| b.finding_count.cmp(&a.finding_count));
    noisy
}

/// Generate actionable insights from overview data.
fn generate_insights(
    summary: &crate::server::models::FindingSummary,
    new_since_last: usize,
    fixed_since_last: usize,
    triage_coverage: f64,
    noisy_rules: &[NoisyRule],
) -> Vec<Insight> {
    let mut insights = Vec::new();

    // Untriaged high findings
    let high_count = summary.by_severity.get("HIGH").copied().unwrap_or(0);
    if high_count > 0 {
        insights.push(Insight {
            kind: "untriaged_high".into(),
            message: format!(
                "{high_count} High severity finding{} to review",
                if high_count == 1 { "" } else { "s" }
            ),
            severity: "warning".into(),
            action_url: Some("/findings?severity=HIGH&status=open".into()),
        });
    }

    // New findings since last scan
    if new_since_last > 0 {
        insights.push(Insight {
            kind: "new_findings".into(),
            message: format!(
                "{new_since_last} new finding{} since last scan",
                if new_since_last == 1 { "" } else { "s" }
            ),
            severity: "warning".into(),
            action_url: Some("/findings".into()),
        });
    }

    // Fixed findings since last scan
    if fixed_since_last > 0 {
        insights.push(Insight {
            kind: "fixed_findings".into(),
            message: format!(
                "{fixed_since_last} finding{} fixed since last scan",
                if fixed_since_last == 1 { "" } else { "s" }
            ),
            severity: "success".into(),
            action_url: None,
        });
    }

    // Noisy rules
    for rule in noisy_rules.iter().take(3) {
        insights.push(Insight {
            kind: "noisy_rule".into(),
            message: format!(
                "Rule {} has {:.0}% suppression rate ({} findings)",
                rule.rule_id,
                rule.suppression_rate * 100.0,
                rule.finding_count
            ),
            severity: "info".into(),
            action_url: Some("/rules".into()),
        });
    }

    // Low triage coverage
    if triage_coverage < 0.1 && summary.total > 20 {
        insights.push(Insight {
            kind: "low_triage".into(),
            message: format!(
                "Only {:.0}% of findings have been triaged",
                triage_coverage * 100.0
            ),
            severity: "info".into(),
            action_url: Some("/triage".into()),
        });
    }

    insights
}

/// Check if the latest scan completed within the last 5 minutes.
fn is_fresh_scan(scan: Option<&ScanSummary>) -> bool {
    let Some(scan) = scan else { return false };
    let Some(ref started_at) = scan.started_at else {
        return false;
    };
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(started_at) {
        let elapsed = chrono::Utc::now() - ts.with_timezone(&chrono::Utc);
        return elapsed.num_seconds() < 300;
    }
    false
}
