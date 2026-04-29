#![doc = include_str!(concat!(env!("OUT_DIR"), "/state.md"))]

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
use domain::{AuthLevel, ProductState};
use engine::MAX_TRACKED_VARS;
use facts::StateFinding;
use petgraph::graph::NodeIndex;
use symbol::SymbolInterner;
use transfer::DefaultTransfer;

/// Classify decorator/annotation/attribute names against the language's auth
/// rules and return the resulting `AuthLevel`.  Any admin-like match produces
/// `Admin`; any generic auth match produces `Authed`; otherwise `Unauthed`.
pub fn classify_auth_decorators(lang: Lang, decorators: &[String]) -> AuthLevel {
    if decorators.is_empty() {
        return AuthLevel::Unauthed;
    }
    let auth_rules = rules::auth_rules(lang);
    let mut level = AuthLevel::Unauthed;
    for dec in decorators {
        let d = dec.to_ascii_lowercase();
        // Admin patterns, match the same static list used by the call-site
        // transfer so decorators and runtime checks agree on privilege.
        if d.contains("admin") || d.contains("hasrole") || d.contains("superuser") {
            return AuthLevel::Admin;
        }
        let matches = auth_rules.iter().any(|rule| {
            rule.matchers.iter().any(|m| {
                let ml = m.to_ascii_lowercase();
                d == ml || d.ends_with(&ml)
            })
        });
        if matches && level < AuthLevel::Authed {
            level = AuthLevel::Authed;
        }
    }
    level
}

/// Run state-model dataflow analysis on a single function's CFG.
///
/// Returns findings for use-after-close, double-close, resource leaks,
/// and unauthenticated access to sensitive sinks.
///
/// `path_safe_suppressed_sink_spans` lists CFG sink spans whose tainted
/// inputs were proved path-safe by the SSA taint engine.  When a
/// privileged sink at one of those spans is reached without
/// authentication, `state-unauthed-access` is suppressed: the taint
/// engine has already proved the user-controlled input cannot escape
/// into a privileged location, so the auth concern is structurally
/// reduced.
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
    auth_decorators: &[String],
    path_safe_suppressed_sink_spans: &std::collections::HashSet<(usize, usize)>,
    // Optional `var_name → PtrProxyHint` map derived from the body's
    // PointsToFacts.  When present, the proxy-acquire transfer suppresses
    // SymbolId attribution on field-aliased receivers (`m := c.mu;
    // m.Lock()`) and routes them through `chain_proxies` instead.  Pass
    // `None` to disable, strict-additive.
    ptr_proxy_hints: Option<&std::collections::HashMap<String, crate::pointer::PtrProxyHint>>,
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
        ptr_proxy_hints,
    };

    // Seed initial auth level from decorator-based authorization markers.
    // Functions tagged with an auth decorator/annotation/attribute start in
    // `Authed` (or `Admin`) instead of `Unauthed`, so the privileged-sink
    // check in `extract_findings` suppresses findings framework-level auth
    // already enforces.
    let mut initial = ProductState::initial();
    initial.auth.auth_level = classify_auth_decorators(lang, auth_decorators);
    let result = engine::run_forward(cfg, entry, &transfer, initial);

    facts::extract_findings(
        &result,
        cfg,
        &interner,
        lang,
        func_summaries,
        enable_auth,
        path_safe_suppressed_sink_spans,
    )
}

/// Build resource method summaries by pre-scanning all method bodies for known
/// resource acquire/release operations. Only creates summaries for methods whose
/// bodies actually contain matching operations, never infers from names alone.
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
            // Check both Call and Seq (Assignment) nodes, resource operations
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
