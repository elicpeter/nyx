use super::domain::{AuthLevel, ProductState, ResourceLifecycle};
use super::engine::DataflowResult;
use super::symbol::SymbolInterner;
use super::transfer::{TransferEvent, TransferEventKind};
use crate::cfg::{Cfg, StmtKind};
use crate::labels::{Cap, DataLabel};
use crate::patterns::Severity;
use crate::symbol::Lang;
use petgraph::visit::IntoNodeReferences;

/// Normalize a callee description for display.
fn sanitize_desc(s: &str) -> String {
    crate::fmt::normalize_snippet(s)
}

/// A finding produced by state analysis.
#[derive(Debug, Clone)]
pub struct StateFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub span: (usize, usize),
    pub message: String,
}

/// Extract findings from converged dataflow state + transfer events.
pub fn extract_findings(
    result: &DataflowResult<ProductState, TransferEvent>,
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    func_summaries: &crate::cfg::FuncSummaries,
) -> Vec<StateFinding> {
    let mut findings = Vec::new();

    // ── 1. Use-after-close from transfer events ──────────────────────────
    for event in &result.events {
        let info = &cfg[event.node];
        let var_name = interner.resolve(event.var);
        match event.kind {
            TransferEventKind::UseAfterClose => {
                findings.push(StateFinding {
                    rule_id: "state-use-after-close".into(),
                    severity: Severity::High,
                    span: info.span,
                    message: format!(
                        "variable `{var_name}` used after close"
                    ),
                });
            }
            TransferEventKind::DoubleClose => {
                findings.push(StateFinding {
                    rule_id: "state-double-close".into(),
                    severity: Severity::Medium,
                    span: info.span,
                    message: format!(
                        "variable `{var_name}` closed twice"
                    ),
                });
            }
        }
    }

    // ── 2. Resource leaks at Exit and function-Return nodes ──────────────
    for (idx, info) in cfg.node_references() {
        // Check both the file-level Exit node and the *synthesised* function
        // exit node (a Return node).  Skip early-return nodes — they flow
        // into the synthesised exit and carry only path-specific state.
        // The synthesised exit is the one Return node that does NOT have an
        // outgoing edge to another Return in the same function.
        let is_exit = info.kind == StmtKind::Exit;
        let is_func_exit = info.kind == StmtKind::Return && info.enclosing_func.is_some();
        if !is_exit && !is_func_exit {
            continue;
        }
        if is_func_exit {
            use petgraph::Direction;
            let is_early_return = cfg
                .neighbors_directed(idx, Direction::Outgoing)
                .any(|succ| {
                    let s = &cfg[succ];
                    s.kind == StmtKind::Return
                        && s.enclosing_func == info.enclosing_func
                });
            if is_early_return {
                continue;
            }
        }
        let Some(state) = result.states.get(&idx) else {
            continue;
        };

        for (&sym, &lifecycle) in &state.resource.vars {
            if !lifecycle.contains(ResourceLifecycle::OPEN) {
                continue;
            }
            let var_name = interner.resolve(sym);

            if !lifecycle.contains(ResourceLifecycle::CLOSED)
                && !lifecycle.contains(ResourceLifecycle::MOVED)
            {
                // Definite leak: open on all paths, never closed
                // Find the acquire span by scanning backwards for this variable's define
                let acquire_span = find_acquire_span(cfg, sym, interner);
                findings.push(StateFinding {
                    rule_id: "state-resource-leak".into(),
                    severity: Severity::Medium,
                    span: acquire_span.unwrap_or(info.span),
                    message: format!(
                        "resource `{var_name}` is never closed"
                    ),
                });
            } else if lifecycle.contains(ResourceLifecycle::CLOSED) {
                // May-leak: open on some paths, closed on others
                let acquire_span = find_acquire_span(cfg, sym, interner);
                findings.push(StateFinding {
                    rule_id: "state-resource-leak-possible".into(),
                    severity: Severity::Low,
                    span: acquire_span.unwrap_or(info.span),
                    message: format!(
                        "resource `{var_name}` may not be closed on all paths"
                    ),
                });
            }
        }
    }

    // ── 3. Auth-required sinks ───────────────────────────────────────────
    // Check if any function is a web entrypoint
    let has_web_entrypoint = cfg.node_references().any(|(_, info)| {
        if let Some(ref func_name) = info.enclosing_func {
            is_web_entrypoint_simple(func_name, lang, func_summaries, cfg)
        } else {
            false
        }
    });

    if has_web_entrypoint {
        for (idx, info) in cfg.node_references() {
            if !is_privileged_sink(info) {
                continue;
            }
            let Some(state) = result.states.get(&idx) else {
                continue;
            };
            if state.auth.auth_level == AuthLevel::Unauthed {
                let callee_desc = sanitize_desc(
                    info.callee.as_deref().unwrap_or("(sensitive op)"),
                );
                findings.push(StateFinding {
                    rule_id: "state-unauthed-access".into(),
                    severity: Severity::High,
                    span: info.span,
                    message: format!(
                        "sensitive operation `{callee_desc}` reached without authentication"
                    ),
                });
            }
        }
    }

    // Dedup
    findings.sort_by(|a, b| {
        a.span
            .cmp(&b.span)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    findings.dedup_by(|a, b| a.span == b.span && a.rule_id == b.rule_id);

    findings
}

/// Find the span where a variable was acquired (defined via Call node).
fn find_acquire_span(
    cfg: &Cfg,
    sym: super::symbol::SymbolId,
    interner: &SymbolInterner,
) -> Option<(usize, usize)> {
    let var_name = interner.resolve(sym);
    for (_idx, info) in cfg.node_references() {
        if info.kind == StmtKind::Call
            && let Some(ref def) = info.defines
            && def == var_name
        {
            return Some(info.span);
        }
    }
    None
}

/// Check if a node is a privileged sink (shell execution or file I/O).
fn is_privileged_sink(info: &crate::cfg::NodeInfo) -> bool {
    match info.label {
        Some(DataLabel::Sink(caps)) => caps.intersects(Cap::SHELL_ESCAPE | Cap::FILE_IO),
        _ => false,
    }
}

/// Simplified web entrypoint check (avoids AnalysisContext dependency).
fn is_web_entrypoint_simple(
    func_name: &str,
    lang: Lang,
    func_summaries: &crate::cfg::FuncSummaries,
    _cfg: &Cfg,
) -> bool {
    let name_lower = func_name.to_ascii_lowercase();

    // Skip bare "main" — it's typically a CLI entry
    if name_lower == "main" {
        return false;
    }

    let is_handler_name = name_lower.starts_with("handle_")
        || name_lower.starts_with("route_")
        || name_lower.starts_with("api_")
        || name_lower.starts_with("serve_")
        || name_lower.starts_with("process_")
        || name_lower == "handler";

    if !is_handler_name {
        return false;
    }

    // Check for web-like parameters
    let web_params: &[&str] = match lang {
        Lang::Rust => &["request", "req", "json", "query", "form", "payload", "body"],
        Lang::JavaScript | Lang::TypeScript => &["req", "request", "ctx", "res", "response"],
        Lang::Python => &["request", "req"],
        Lang::Go => &["w", "writer", "r", "req", "request"],
        Lang::Java => &["request", "req"],
        _ => &["request", "req"],
    };

    let has_web_params = func_summaries.values().any(|s| {
        s.param_names
            .iter()
            .any(|p| web_params.contains(&p.to_ascii_lowercase().as_str()))
    });

    // Strong handler names are enough even without web params
    let strong_name = name_lower.starts_with("handle_")
        || name_lower.starts_with("route_")
        || name_lower.starts_with("api_");

    has_web_params || strong_name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{EdgeKind, NodeInfo};
    use crate::state::domain::ProductState;
    use crate::state::engine;
    use crate::state::symbol::SymbolInterner;
    use crate::state::transfer::DefaultTransfer;
    use crate::cfg_analysis::rules;
    use petgraph::Graph;
    use std::collections::HashMap;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            span: (0, 0),
            label: None,
            defines: None,
            uses: vec![],
            callee: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
        }
    }

    #[test]
    fn detects_resource_leak() {
        // Entry → fopen(f) → Exit (no close)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            span: (10, 20),
            defines: Some("f".into()),
            callee: Some("fopen".into()),
            ..make_node(StmtKind::Call)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
        };

        let result = engine::run_forward(&cfg, entry, &transfer, ProductState::initial());
        let findings = extract_findings(&result, &cfg, &interner, Lang::C, &HashMap::new());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "state-resource-leak");
        assert!(findings[0].message.contains("f"));
    }

    #[test]
    fn clean_open_close_no_findings() {
        // Entry → fopen(f) → fclose(f) → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            defines: Some("f".into()),
            callee: Some("fopen".into()),
            ..make_node(StmtKind::Call)
        });
        let close_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            uses: vec!["f".into()],
            callee: Some("fclose".into()),
            ..make_node(StmtKind::Call)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, close_node, EdgeKind::Seq);
        cfg.add_edge(close_node, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
        };

        let result = engine::run_forward(&cfg, entry, &transfer, ProductState::initial());
        let findings = extract_findings(&result, &cfg, &interner, Lang::C, &HashMap::new());

        assert!(findings.is_empty());
    }
}
