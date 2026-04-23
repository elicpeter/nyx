pub mod checks;
pub mod config;
pub mod extract;
pub mod model;
pub mod sql_semantics;

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence, SpanEvidence};
use crate::patterns::FindingCategory;
use crate::ssa::type_facts::TypeKind;
use crate::utils::Config;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::Tree;

fn byte_offset_to_point(tree: &Tree, byte: usize) -> tree_sitter::Point {
    tree.root_node()
        .descendant_for_byte_range(byte, byte)
        .map(|node| node.start_position())
        .unwrap_or(tree_sitter::Point { row: 0, column: 0 })
}

/// Per-file snapshot of SSA-derived variable types, keyed by
/// source-level variable name.  Built at `run_auth_analysis` call sites
/// by merging type facts across all bodies in the file; a variable name
/// with conflicting types in different bodies is dropped (absence is
/// safe — the sink gate just falls back to name-based classification).
pub type VarTypes = HashMap<String, TypeKind>;

pub fn run_auth_analysis(
    tree: &Tree,
    source: &[u8],
    lang: &str,
    file_path: &Path,
    cfg: &Config,
    var_types: Option<&VarTypes>,
) -> Vec<Diag> {
    let rules = config::build_auth_rules(cfg, lang);
    if !rules.enabled {
        return Vec::new();
    }

    let mut model = extract::extract_authorization_model(
        lang,
        cfg.framework_ctx.as_ref(),
        tree,
        source,
        file_path,
        &rules,
    );

    // Refine `SensitiveOperation::sink_class` using SSA-derived
    // variable types.  Runs only when the caller supplied `var_types`
    // (skipped for slug-lookup / unit-test call sites).
    if let Some(types) = var_types {
        apply_var_types_to_model(&mut model, &rules, types);
    }

    // Lift per-function auth-check summaries and synthesise call-site
    // `AuthCheck`s in callers, so a handler that delegates to a helper
    // which internally validates ownership is recognised as
    // auth-checked.  Single-file scope: only units present in this
    // model are considered; cross-file lifting is future work.
    apply_helper_lifting(&mut model);

    if model.routes.is_empty() && model.units.is_empty() {
        return Vec::new();
    }

    checks::run_checks(&model, &rules)
        .into_iter()
        .map(|finding| auth_finding_to_diag(&finding, tree, file_path))
        .collect()
}

/// Walk every `SensitiveOperation` in the model and, when the call's
/// receiver root variable has a known SSA type, override `sink_class`
/// to the type-implied class.  Strictly additive — only overrides
/// when the type map produces a definite class, otherwise leaves the
/// name/prefix-derived classification intact.
fn apply_var_types_to_model(
    model: &mut model::AuthorizationModel,
    rules: &config::AuthAnalysisRules,
    var_types: &VarTypes,
) {
    for unit in &mut model.units {
        for op in &mut unit.operations {
            let Some(first) = receiver_root(&op.callee) else {
                continue;
            };
            let Some(ty) = var_types.get(first) else {
                continue;
            };
            if let Some(new_class) = sink_class_for_type(ty, &op.callee, rules) {
                op.sink_class = Some(new_class);
            }
        }
    }
}

/// First segment of a callee's receiver chain (`map.insert` → `"map"`,
/// `self.cache.set` → `"self"`).  Returns `None` when the callee has no
/// receiver (e.g. a free function call).
fn receiver_root(callee: &str) -> Option<&str> {
    let (first, rest) = callee.split_once('.')?;
    if rest.is_empty() {
        return None;
    }
    if first.is_empty() { None } else { Some(first) }
}

/// Map an inferred [`TypeKind`] to the [`model::SinkClass`] that should
/// supersede the callee-name classification.  The DB case disambiguates
/// read vs mutation using the callee's verb; non-security types return
/// `None` so the caller leaves the existing class in place.
fn sink_class_for_type(
    ty: &TypeKind,
    callee: &str,
    rules: &config::AuthAnalysisRules,
) -> Option<model::SinkClass> {
    match ty {
        TypeKind::LocalCollection => Some(model::SinkClass::InMemoryLocal),
        TypeKind::HttpClient => Some(model::SinkClass::OutboundNetwork),
        TypeKind::DatabaseConnection => {
            if rules.is_read(callee) && !rules.is_mutation(callee) {
                Some(model::SinkClass::DbCrossTenantRead)
            } else {
                Some(model::SinkClass::DbMutation)
            }
        }
        _ => None,
    }
}

/// Build per-function `AuthCheckSummary` and synthesise `AuthCheck`s
/// at every call site that targets a known helper whose summary names
/// auth-checked params.  Iterated to a small fixpoint
/// so transitive helper chains (`handler → validate → require_member`)
/// are also covered.
///
/// The synthesised AuthCheck inherits the helper-param's check kind
/// and is anchored at the call site's line, with subjects = the
/// caller's value-refs from the corresponding positional argument.
/// `auth_check_covers_subject` then matches them against downstream
/// sensitive operations exactly like a real prior auth check.
fn apply_helper_lifting(model: &mut model::AuthorizationModel) {
    use std::collections::HashSet;

    const MAX_ROUNDS: usize = 4;
    for _ in 0..MAX_ROUNDS {
        let summaries = build_helper_summaries(model);
        if summaries.is_empty() {
            return;
        }
        let mut added = false;
        // For each unit, compute synthetic checks BEFORE mutating, so
        // a helper-call inside one unit doesn't see synthetic checks
        // we add to a sibling in the same round (those land in the
        // next iteration via the rebuilt summaries).
        let synth: Vec<(usize, Vec<model::AuthCheck>)> = model
            .units
            .iter()
            .enumerate()
            .map(|(idx, unit)| (idx, synthesise_checks_for_unit(unit, &summaries)))
            .collect();
        let mut existing_keys_per_unit: Vec<HashSet<((usize, usize), model::AuthCheckKind)>> =
            model
                .units
                .iter()
                .map(|u| {
                    u.auth_checks
                        .iter()
                        .map(|c| (c.span, c.kind))
                        .collect::<HashSet<_>>()
                })
                .collect();
        for (idx, checks) in synth {
            for check in checks {
                let key = (check.span, check.kind);
                if existing_keys_per_unit[idx].insert(key) {
                    model.units[idx].auth_checks.push(check);
                    added = true;
                }
            }
        }
        if !added {
            return;
        }
    }
}

/// Build a `name → AuthCheckSummary` map by walking each unit's auth
/// checks and recording, for every check subject whose value-ref name
/// matches a positional parameter name of the unit, that param index
/// → check kind.  Same key with different kinds collapses to the most
/// specific (Ownership/Membership wins over Other).
fn build_helper_summaries(
    model: &model::AuthorizationModel,
) -> std::collections::HashMap<String, model::AuthCheckSummary> {
    use model::{AuthCheckKind, AuthCheckSummary};
    use std::collections::HashMap;

    let mut summaries: HashMap<String, AuthCheckSummary> = HashMap::new();
    for unit in &model.units {
        let Some(name) = unit.name.as_deref() else {
            continue;
        };
        if name.is_empty() || unit.params.is_empty() {
            continue;
        }
        let mut summary = AuthCheckSummary::default();
        for check in &unit.auth_checks {
            // We only lift checks that actively prove ownership /
            // membership / admin-rights / authorize-helper — login
            // and token-validity checks don't justify foreign-id
            // mutations and we want to keep parity with
            // `has_prior_subject_auth`'s filter.
            if matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            ) {
                continue;
            }
            for subject in &check.subjects {
                let candidate = subject_lift_key(subject);
                let Some(candidate) = candidate else { continue };
                if let Some(idx) = unit.params.iter().position(|p| p == &candidate) {
                    summary
                        .param_auth_kinds
                        .entry(idx)
                        .and_modify(|existing| {
                            *existing = stronger_check_kind(*existing, check.kind);
                        })
                        .or_insert(check.kind);
                }
            }
        }
        if !summary.param_auth_kinds.is_empty() {
            // Deduplicate by last segment of the function name — the
            // lifting site matches the call's last segment too.
            let last = name.rsplit('.').next().unwrap_or(name).to_string();
            summaries
                .entry(last)
                .or_default()
                .param_auth_kinds
                .extend(summary.param_auth_kinds);
        }
    }
    summaries
}

/// Pick the identifier name for a check subject for purposes of
/// matching to the enclosing function's parameters.  We prefer the
/// `base` segment of a member-chain subject (`row.user_id` → `row`)
/// because helpers usually receive the full struct, not the field;
/// fall back to the raw `name` for plain identifiers.
fn subject_lift_key(subject: &model::ValueRef) -> Option<String> {
    if let Some(base) = subject.base.as_deref() {
        let first = base.split('.').next().unwrap_or(base).trim();
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    if subject.name.is_empty() {
        None
    } else {
        Some(
            subject
                .name
                .split('.')
                .next()
                .unwrap_or(&subject.name)
                .to_string(),
        )
    }
}

fn stronger_check_kind(a: model::AuthCheckKind, b: model::AuthCheckKind) -> model::AuthCheckKind {
    use model::AuthCheckKind::*;
    fn rank(k: model::AuthCheckKind) -> u8 {
        match k {
            Ownership => 5,
            Membership => 4,
            AdminGuard => 3,
            Other => 2,
            LoginGuard => 1,
            TokenExpiry | TokenRecipient => 0,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

/// For one unit, synthesise an `AuthCheck` at every call site that
/// targets a helper with a non-trivial summary.  Subjects are taken
/// from `call_site.args_value_refs[K]` for each auth-checked param
/// position K — these are the caller's concrete subjects passed at
/// that arg slot, exactly what `auth_check_covers_subject` needs.
fn synthesise_checks_for_unit(
    unit: &model::AnalysisUnit,
    summaries: &std::collections::HashMap<String, model::AuthCheckSummary>,
) -> Vec<model::AuthCheck> {
    let line_of = |span: (usize, usize)| -> usize {
        // Span is byte offsets; we don't have direct access to a Tree
        // here. Caller assigns line via `line` field on call_site
        // through CallSite metadata absence — fall back to the unit's
        // line since covers_subject uses `check.line <= op.line` and
        // helper calls are typically near the unit start.
        let _ = span;
        unit.line
    };

    let mut out = Vec::new();
    for call in &unit.call_sites {
        let last = call.name.rsplit('.').next().unwrap_or(&call.name);
        let Some(summary) = summaries.get(last) else {
            continue;
        };
        // A call to the unit itself shouldn't lift anything (would
        // produce a tautological self-cover).
        if unit.name.as_deref() == Some(last) {
            continue;
        }
        // Build subjects from the auth-checked param positions.
        let mut subjects: Vec<model::ValueRef> = Vec::new();
        let mut effective_kind = model::AuthCheckKind::Other;
        for (param_idx, kind) in &summary.param_auth_kinds {
            let Some(arg_refs) = call.args_value_refs.get(*param_idx) else {
                continue;
            };
            subjects.extend(arg_refs.iter().cloned());
            effective_kind = stronger_check_kind(effective_kind, *kind);
        }
        if subjects.is_empty() {
            continue;
        }
        let line = call_site_line(unit, call).unwrap_or_else(|| line_of(call.span));
        out.push(model::AuthCheck {
            kind: effective_kind,
            callee: format!("(lifted {})", call.name),
            subjects,
            span: call.span,
            line,
            args: call.args.clone(),
            condition_text: None,
        });
    }
    out
}

/// Approximate the call site's line.  We don't have tree access here,
/// so we walk the unit's existing operations / call_sites to find one
/// whose span starts at the same byte offset and reuse its line; if
/// nothing matches we conservatively report the unit's start line so
/// the synthetic check still satisfies `check.line <= op.line` for
/// operations declared after it.  In practice, helper calls always
/// resolve via the operations match because handlers register their
/// own call_site too.
fn call_site_line(unit: &model::AnalysisUnit, call: &model::CallSite) -> Option<usize> {
    for op in &unit.operations {
        if op.span.0 == call.span.0 {
            return Some(op.line);
        }
    }
    None
}

fn auth_finding_to_diag(finding: &checks::AuthFinding, tree: &Tree, file_path: &Path) -> Diag {
    let point = byte_offset_to_point(tree, finding.span.0);
    Diag {
        path: file_path.to_string_lossy().into_owned(),
        line: point.row + 1,
        col: point.column + 1,
        severity: finding.severity,
        id: finding.rule_id.clone(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: Some(finding.message.clone()),
        labels: vec![],
        confidence: Some(Confidence::Medium),
        evidence: Some(Evidence {
            source: None,
            sink: Some(SpanEvidence {
                path: file_path.to_string_lossy().into_owned(),
                line: (point.row + 1) as u32,
                col: (point.column + 1) as u32,
                kind: "sink".into(),
                snippet: None,
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![],
            ..Default::default()
        }),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{VarTypes, apply_var_types_to_model, receiver_root, sink_class_for_type};
    use crate::auth_analysis::config::build_auth_rules;
    use crate::auth_analysis::model::{
        AnalysisUnit, AnalysisUnitKind, AuthorizationModel, OperationKind, SensitiveOperation,
        SinkClass,
    };
    use crate::ssa::type_facts::TypeKind;
    use crate::utils::config::Config;
    use std::collections::{HashMap, HashSet};

    fn sample_op(callee: &str, initial: Option<SinkClass>) -> SensitiveOperation {
        SensitiveOperation {
            kind: OperationKind::Mutation,
            sink_class: initial,
            callee: callee.to_string(),
            subjects: Vec::new(),
            span: (0, 0),
            line: 1,
            text: callee.to_string(),
        }
    }

    fn sample_unit(op: SensitiveOperation) -> AnalysisUnit {
        AnalysisUnit {
            kind: AnalysisUnitKind::Function,
            name: Some("handle".into()),
            span: (0, 0),
            params: Vec::new(),
            context_inputs: Vec::new(),
            call_sites: Vec::new(),
            auth_checks: Vec::new(),
            operations: vec![op],
            value_refs: Vec::new(),
            condition_texts: Vec::new(),
            line: 1,
            row_field_vars: HashMap::new(),
            self_actor_vars: HashSet::new(),
            authorized_sql_vars: HashSet::new(),
        }
    }

    #[test]
    fn receiver_root_returns_first_segment_only_for_chain_calls() {
        assert_eq!(receiver_root("map.insert"), Some("map"));
        assert_eq!(receiver_root("self.cache.insert"), Some("self"));
        // Free function call (no receiver) → None.
        assert_eq!(receiver_root("HashMap"), None);
        assert_eq!(receiver_root("free_fn"), None);
        // Empty chain segments → None.
        assert_eq!(receiver_root("."), None);
        assert_eq!(receiver_root(""), None);
    }

    #[test]
    fn sink_class_for_type_maps_security_typekinds() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        // LocalCollection always → InMemoryLocal.
        assert_eq!(
            sink_class_for_type(&TypeKind::LocalCollection, "whatever.insert", &rules),
            Some(SinkClass::InMemoryLocal)
        );
        // HttpClient → OutboundNetwork.
        assert_eq!(
            sink_class_for_type(&TypeKind::HttpClient, "client.send", &rules),
            Some(SinkClass::OutboundNetwork)
        );
        // DatabaseConnection: mutation verb → DbMutation.
        assert_eq!(
            sink_class_for_type(&TypeKind::DatabaseConnection, "conn.insert", &rules),
            Some(SinkClass::DbMutation)
        );
        // DatabaseConnection: read-only verb → DbCrossTenantRead.
        assert_eq!(
            sink_class_for_type(&TypeKind::DatabaseConnection, "conn.get", &rules),
            Some(SinkClass::DbCrossTenantRead)
        );
        // DatabaseConnection: unrecognized verb (`execute`) → DbMutation
        // (conservative default — treat as write-shaped).
        assert_eq!(
            sink_class_for_type(&TypeKind::DatabaseConnection, "conn.execute", &rules),
            Some(SinkClass::DbMutation)
        );
        // Non-security types → None (don't override).
        assert_eq!(
            sink_class_for_type(&TypeKind::String, "s.len", &rules),
            None
        );
        assert_eq!(
            sink_class_for_type(&TypeKind::Unknown, "x.frobnicate", &rules),
            None
        );
    }

    #[test]
    fn apply_var_types_overrides_sink_class_for_known_receiver() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut model = AuthorizationModel::default();
        // Initial sink class from B1 name-based classification (e.g.
        // `results.insert` → DbMutation because `insert` matches the
        // mutation list and `results` doesn't match any non-sink prefix).
        model.units.push(sample_unit(sample_op(
            "results.insert",
            Some(SinkClass::DbMutation),
        )));

        let mut var_types: VarTypes = HashMap::new();
        var_types.insert("results".into(), TypeKind::LocalCollection);

        apply_var_types_to_model(&mut model, &rules, &var_types);

        // B2 overrode to InMemoryLocal based on the SSA type.
        assert_eq!(
            model.units[0].operations[0].sink_class,
            Some(SinkClass::InMemoryLocal)
        );
    }

    #[test]
    fn apply_var_types_leaves_classification_untouched_when_receiver_unknown() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut model = AuthorizationModel::default();
        model.units.push(sample_unit(sample_op(
            "db.insert",
            Some(SinkClass::DbMutation),
        )));
        let var_types: VarTypes = HashMap::new();
        apply_var_types_to_model(&mut model, &rules, &var_types);
        // Unchanged — no entry in var_types for `db`.
        assert_eq!(
            model.units[0].operations[0].sink_class,
            Some(SinkClass::DbMutation)
        );
    }
}
