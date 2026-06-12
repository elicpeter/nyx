//! Cross-file caller-scope IPA for graphene-django mutations.
//!
//! Distilled from saleor `graphql/order/mutations/order_cancel.py` +
//! `graphql/order/mutations/utils.py`: a permissioned graphene mutation
//! (`class Meta: permissions = (...)`) implements its action in a
//! `perform_mutation` classmethod that delegates the id-targeted ORM
//! write to a private helper in a DIFFERENT file.
//!
//! The `GrapheneExtractor` (`src/auth_analysis/extract/graphene.rs`) marks
//! `perform_mutation` an authorized RouteHandler, so the existing Phase 2
//! cross-file caller-scope IPA (`caller_scope.rs`) lifts the mutation's
//! route-level auth onto the helper.
//!
//! Recall guard: `helpers/export_ops.py` is reached only from the PUBLIC
//! `PublicExport` mutation (no `Meta.permissions`), so it has no
//! authorized caller edge, the lift is refused, and
//! `missing_ownership_check` must still fire.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("auth_analysis_graphene_cross_file")
}

#[test]
fn graphene_permissioned_mutation_lifts_route_auth_onto_cross_file_helper() {
    let diags = scan_fixture_dir(&fixture_dir(), AnalysisMode::Full);

    // Safe side: helper reached only from the permissioned mutation must
    // be clean of both auth findings.
    let safe_hits: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.path.ends_with("order_ops.py")
                && (d.id == "py.auth.missing_ownership_check"
                    || d.id == "py.auth.token_override_without_validation")
        })
        .collect();
    assert!(
        safe_hits.is_empty(),
        "graphene Meta.permissions must lift route auth onto helpers/order_ops.py, \
         but found: {safe_hits:#?}"
    );

    // Recall side: helper reached only from the PUBLIC mutation (no
    // Meta.permissions) must still fire.
    let vuln_hits = diags
        .iter()
        .filter(|d| {
            d.path.ends_with("export_ops.py") && d.id == "py.auth.missing_ownership_check"
        })
        .count();
    assert!(
        vuln_hits >= 1,
        "recall guard: helpers/export_ops.py (reached only from a public, \
         unpermissioned mutation) must still fire missing_ownership_check.\n\
         All findings: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>()
    );
}
