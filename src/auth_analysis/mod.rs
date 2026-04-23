pub mod checks;
pub mod config;
pub mod extract;
pub mod model;

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

/// Phase B2: per-file snapshot of SSA-derived variable types, keyed by
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

    // Phase B2: refine `SensitiveOperation::sink_class` using
    // SSA-derived variable types.  Runs only when the caller supplied
    // `var_types` (skipped for slug-lookup / unit-test call sites).
    if let Some(types) = var_types {
        apply_var_types_to_model(&mut model, &rules, types);
    }

    if model.routes.is_empty() && model.units.is_empty() {
        return Vec::new();
    }

    checks::run_checks(&model, &rules)
        .into_iter()
        .map(|finding| auth_finding_to_diag(&finding, tree, file_path))
        .collect()
}

/// Phase B2: walk every `SensitiveOperation` in the model and, when the
/// call's receiver root variable has a known SSA type, override
/// `sink_class` to the type-implied class.  Strictly additive — only
/// overrides when the type map produces a definite class, otherwise
/// leaves the name/prefix-derived classification from B1 intact.
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
