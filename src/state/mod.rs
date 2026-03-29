pub mod domain;
pub mod engine;
pub mod facts;
pub mod lattice;
pub mod symbol;
pub mod transfer;

use crate::cfg::{Cfg, FuncSummaries};
use crate::cfg_analysis::rules;
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use domain::ProductState;
use engine::MAX_TRACKED_VARS;
use facts::StateFinding;
use petgraph::graph::NodeIndex;
use symbol::SymbolInterner;
use transfer::DefaultTransfer;

/// Run state-model dataflow analysis on a single function's CFG.
///
/// Returns findings for use-after-close, double-close, resource leaks,
/// and unauthenticated access to sensitive sinks.
#[allow(clippy::too_many_arguments)]
pub fn run_state_analysis(
    cfg: &Cfg,
    entry: NodeIndex,
    lang: Lang,
    _source_bytes: &[u8],
    func_summaries: &FuncSummaries,
    _global_summaries: Option<&GlobalSummaries>,
    enable_auth: bool,
    resource_method_summaries: &[transfer::ResourceMethodSummary],
) -> Vec<StateFinding> {
    let _span = tracing::debug_span!("run_state_analysis").entered();

    let interner = SymbolInterner::from_cfg_scoped(cfg);

    if interner.len() > MAX_TRACKED_VARS {
        tracing::warn!(
            symbols = interner.len(),
            max = MAX_TRACKED_VARS,
            "state analysis: too many variables, capping tracking"
        );
    }

    let resource_pairs = rules::resource_pairs(lang);
    let transfer = DefaultTransfer {
        lang,
        resource_pairs,
        interner: &interner,
        resource_method_summaries,
    };

    let initial = ProductState::initial();
    let result = engine::run_forward(cfg, entry, &transfer, initial);

    facts::extract_findings(&result, cfg, &interner, lang, func_summaries, enable_auth)
}

/// Build resource method summaries by pre-scanning all method bodies for known
/// resource acquire/release operations. Only creates summaries for methods whose
/// bodies actually contain matching operations — never infers from names alone.
pub fn build_resource_method_summaries(
    bodies: &[crate::cfg::BodyCfg],
    lang: Lang,
) -> Vec<transfer::ResourceMethodSummary> {
    use petgraph::visit::IntoNodeReferences;

    let resource_pairs = rules::resource_pairs(lang);
    let mut summaries = Vec::new();

    for body in bodies {
        let method_name = match &body.meta.name {
            Some(name) => name.clone(),
            None => continue,
        };
        let class_group = match body.meta.parent_body_id {
            Some(pid) => pid,
            None => continue, // top-level functions are not class methods
        };

        for (_, info) in body.graph.node_references() {
            // Check both Call and Seq (Assignment) nodes — resource operations
            // can appear as RHS of assignments (e.g., `this.fd = fs.openSync(...)`).
            if !matches!(
                info.kind,
                crate::cfg::StmtKind::Call | crate::cfg::StmtKind::Seq
            ) {
                continue;
            }
            let callee = match &info.call.callee {
                Some(c) => c.to_ascii_lowercase(),
                None => continue,
            };
            for pair in resource_pairs {
                if pair
                    .acquire
                    .iter()
                    .any(|a| transfer::callee_matches_pub(&callee, a))
                {
                    summaries.push(transfer::ResourceMethodSummary {
                        method_name: method_name.clone(),
                        effect: transfer::ResourceEffect::Acquire,
                        class_group,
                        original_span: info.ast.span,
                    });
                }
                if pair
                    .release
                    .iter()
                    .any(|r| transfer::callee_matches_pub(&callee, r))
                {
                    summaries.push(transfer::ResourceMethodSummary {
                        method_name: method_name.clone(),
                        effect: transfer::ResourceEffect::Release,
                        class_group,
                        original_span: info.ast.span,
                    });
                }
            }
        }
    }
    summaries
}
