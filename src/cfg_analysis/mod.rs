pub mod auth;
pub mod dominators;
pub mod error_handling;
pub mod guards;
pub mod resources;
pub mod rules;
pub mod scoring;
#[cfg(test)]
mod tests;
pub mod unreachable;

use crate::cfg::{FuncSummaries, NodeInfo, StmtKind};
use crate::labels::{DataLabel, LangAnalysisRules};
use crate::patterns::Severity;
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use crate::taint;
use petgraph::graph::NodeIndex;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct CfgFinding {
    pub rule_id: String,
    #[allow(dead_code)]
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub span: (usize, usize),
    #[allow(dead_code)]
    pub message: String,
    pub evidence: Vec<NodeIndex>,
    pub score: Option<f64>,
}

pub struct AnalysisContext<'a> {
    pub cfg: &'a crate::cfg::Cfg,
    pub entry: NodeIndex,
    pub lang: Lang,
    #[allow(dead_code)]
    pub file_path: &'a str,
    #[allow(dead_code)]
    pub source_bytes: &'a [u8],
    pub func_summaries: &'a FuncSummaries,
    #[allow(dead_code)]
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub taint_findings: &'a [taint::Finding],
    pub analysis_rules: Option<&'a LangAnalysisRules>,
    /// Whether full taint analysis was active for this file (global summaries
    /// existed and taint engine ran).  When false, structural findings without
    /// taint confirmation should be treated with lower confidence.
    pub taint_active: bool,
}

pub trait CfgAnalysis {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding>;
}

/// Run all registered analyses and return merged findings.
pub fn run_all(ctx: &AnalysisContext) -> Vec<CfgFinding> {
    let analyses: Vec<Box<dyn CfgAnalysis>> = vec![
        Box::new(unreachable::UnreachableCode),
        Box::new(guards::UnguardedSink),
        Box::new(auth::AuthGap),
        Box::new(error_handling::IncompleteErrorHandling),
        Box::new(resources::ResourceMisuse),
    ];
    let mut findings: Vec<CfgFinding> = analyses.iter().flat_map(|a| a.run(ctx)).collect();

    // ── Dedup: suppress cfg-unguarded-sink when taint already covers the span ──
    // Collect spans where taint findings exist (sink byte offset).
    let taint_spans: HashSet<(usize, usize)> = ctx
        .taint_findings
        .iter()
        .map(|f| ctx.cfg[f.sink].span)
        .collect();

    findings.retain(|f| {
        // If both taint and cfg-unguarded-sink fire on the same span,
        // suppress the structural CFG finding (taint is the primary signal).
        if f.rule_id == "cfg-unguarded-sink" && taint_spans.contains(&f.span) {
            return false;
        }
        true
    });

    // ── Dedup: suppress cfg-unguarded-sink when cfg-unreachable-sink covers the span ──
    let unreachable_spans: HashSet<(usize, usize)> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unreachable-sink")
        .map(|f| f.span)
        .collect();

    findings.retain(|f| {
        if f.rule_id == "cfg-unguarded-sink" && unreachable_spans.contains(&f.span) {
            return false;
        }
        true
    });

    scoring::score_findings(&mut findings, ctx);
    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings
}

/// Helper: check whether a node is a guard call (validate, sanitize, check, etc.).
pub(crate) fn is_guard_call(
    info: &NodeInfo,
    lang: Lang,
    analysis_rules: Option<&LangAnalysisRules>,
) -> bool {
    if info.kind != StmtKind::Call {
        return false;
    }
    if let Some(callee) = &info.callee {
        // Check config sanitizer rules
        if let Some(extras) = analysis_rules {
            let callee_lower = callee.to_ascii_lowercase();
            for rule in &extras.extra_labels {
                if !matches!(rule.label, DataLabel::Sanitizer(_)) {
                    continue;
                }
                for m in &rule.matchers {
                    let ml = m.to_ascii_lowercase();
                    if ml.ends_with('_') {
                        if callee_lower.starts_with(&ml) {
                            return true;
                        }
                    } else if callee_lower.ends_with(&ml) {
                        return true;
                    }
                }
            }
        }

        // Check built-in guard rules
        let guard_rules = rules::guard_rules(lang);
        let callee_lower = callee.to_ascii_lowercase();
        for rule in guard_rules {
            for &m in rule.matchers {
                let ml = m.to_ascii_lowercase();
                if ml.ends_with('_') {
                    if callee_lower.starts_with(&ml) {
                        return true;
                    }
                } else if callee_lower.ends_with(&ml) {
                    return true;
                }
            }
        }
    }
    false
}

/// Helper: check whether a node is an auth check call.
pub(crate) fn is_auth_call(info: &NodeInfo, lang: Lang) -> bool {
    if info.kind != StmtKind::Call {
        return false;
    }
    if let Some(callee) = &info.callee {
        let auth_rules = rules::auth_rules(lang);
        let callee_lower = callee.to_ascii_lowercase();
        for rule in auth_rules {
            for &m in rule.matchers {
                let ml = m.to_ascii_lowercase();
                if ml.ends_with('_') {
                    if callee_lower.starts_with(&ml) {
                        return true;
                    }
                } else if callee_lower.ends_with(&ml) {
                    return true;
                }
            }
        }
    }
    false
}

/// Helper: check if a function name looks like an entry point (HTTP handler, main, etc.).
pub(crate) fn is_entry_point_func(func_name: &str, lang: Lang) -> bool {
    let ep_rules = rules::entry_point_rules(lang);
    let name_lower = func_name.to_ascii_lowercase();
    for rule in ep_rules {
        for &m in rule.matchers {
            let ml = m.to_ascii_lowercase();
            if ml.ends_with('*') {
                let prefix = &ml[..ml.len() - 1];
                if name_lower.starts_with(prefix) {
                    return true;
                }
            } else if name_lower == ml {
                return true;
            }
        }
    }
    false
}

/// Helper: check if a node is a sink.
pub(crate) fn is_sink(info: &NodeInfo) -> bool {
    matches!(info.label, Some(DataLabel::Sink(_)))
}
