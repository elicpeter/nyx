use super::dominators;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence};
use crate::cfg::StmtKind;
use crate::labels::DataLabel;
use crate::patterns::Severity;

pub struct UnreachableCode;

impl CfgAnalysis for UnreachableCode {
    fn name(&self) -> &'static str {
        "unreachable-code"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let reachable = dominators::reachable_set(ctx.cfg, ctx.entry);
        let mut findings = Vec::new();

        for idx in ctx.cfg.node_indices() {
            if reachable.contains(&idx) {
                continue;
            }

            let info = &ctx.cfg[idx];

            // Skip synthetic Entry/Exit nodes
            if matches!(info.kind, StmtKind::Entry | StmtKind::Exit) {
                continue;
            }

            let (rule_id, title, severity) = match info.label {
                Some(DataLabel::Sanitizer(_)) => (
                    "cfg-unreachable-sanitizer",
                    "Unreachable sanitizer",
                    Severity::Medium,
                ),
                Some(DataLabel::Sink(_)) => {
                    ("cfg-unreachable-sink", "Unreachable sink", Severity::Medium)
                }
                Some(DataLabel::Source(_)) => (
                    "cfg-unreachable-source",
                    "Unreachable source",
                    Severity::Low,
                ),
                _ => {
                    // Check if it's a guard/auth call
                    if super::is_guard_call(info, ctx.lang) || super::is_auth_call(info, ctx.lang) {
                        (
                            "cfg-unreachable-guard",
                            "Unreachable guard/auth check",
                            Severity::Medium,
                        )
                    } else {
                        // Plain unreachable code — low severity
                        continue;
                    }
                }
            };

            let callee_desc = info.callee.as_deref().unwrap_or("(unknown)");

            findings.push(CfgFinding {
                rule_id: rule_id.to_string(),
                title: title.to_string(),
                severity,
                confidence: Confidence::High,
                span: info.span,
                message: format!("{title}: `{callee_desc}` is unreachable and will never execute"),
                evidence: vec![idx],
                score: None,
            });
        }

        findings
    }
}
