pub mod checks;
pub mod config;
pub mod extract;
pub mod model;

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence, SpanEvidence};
use crate::patterns::FindingCategory;
use crate::utils::Config;
use std::path::Path;
use tree_sitter::Tree;

fn byte_offset_to_point(tree: &Tree, byte: usize) -> tree_sitter::Point {
    tree.root_node()
        .descendant_for_byte_range(byte, byte)
        .map(|node| node.start_position())
        .unwrap_or(tree_sitter::Point { row: 0, column: 0 })
}

pub fn run_auth_analysis(
    tree: &Tree,
    source: &[u8],
    lang: &str,
    file_path: &Path,
    cfg: &Config,
) -> Vec<Diag> {
    let rules = config::build_auth_rules(cfg, lang);
    if !rules.enabled {
        return Vec::new();
    }

    let model = extract::extract_authorization_model(
        lang,
        cfg.framework_ctx.as_ref(),
        tree,
        source,
        file_path,
        &rules,
    );

    if model.routes.is_empty() && model.units.is_empty() {
        return Vec::new();
    }

    checks::run_checks(&model, &rules)
        .into_iter()
        .map(|finding| auth_finding_to_diag(&finding, tree, file_path))
        .collect()
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
    }
}
