use super::dominators;
use super::{AnalysisContext, CfgFinding, Confidence};
use crate::cfg::StmtKind;
use crate::patterns::Severity;

/// Enrich all findings with a numeric score for ranking.
pub fn score_findings(findings: &mut [CfgFinding], ctx: &AnalysisContext) {
    for f in findings.iter_mut() {
        let mut score = 0.0;

        // Base severity
        score += severity_base(f.severity);

        // Distance from entry (fewer hops = more exposed = higher risk)
        let finding_node = f.evidence.first().copied();
        if let Some(node) = finding_node
            && let Some(dist) = dominators::shortest_distance(ctx.cfg, ctx.entry, node)
        {
            score += 20.0 / (1.0 + dist as f64);
        }

        // Branch complexity on path (more branches = more likely to miss a case)
        let branches = count_branches_on_evidence(&f.evidence, ctx);
        score += (branches as f64).min(10.0);

        // Taint-confirmed unguarded sinks get a boost (already HIGH, but
        // reinforce that they sort above structural-only findings).
        if f.rule_id == "cfg-unguarded-sink" && f.severity == Severity::High {
            score += 10.0;
        }
        // Auth-gap in a confirmed web handler gets a moderate boost.
        if f.rule_id == "cfg-auth-gap" {
            score += 5.0;
        }

        // Confidence multiplier
        score *= confidence_multiplier(f.confidence);

        f.score = Some(score);
    }
}

fn severity_base(severity: Severity) -> f64 {
    match severity {
        Severity::High => 80.0,
        Severity::Medium => 50.0,
        Severity::Low => 20.0,
    }
}

fn confidence_multiplier(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::High => 1.0,
        Confidence::Medium => 0.8,
        Confidence::Low => 0.6,
    }
}

fn count_branches_on_evidence(
    evidence: &[petgraph::graph::NodeIndex],
    ctx: &AnalysisContext,
) -> usize {
    evidence
        .iter()
        .filter(|&&idx| ctx.cfg[idx].kind == StmtKind::If)
        .count()
}
