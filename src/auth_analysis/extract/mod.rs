use super::config::AuthAnalysisRules;
use super::model::AuthorizationModel;
use crate::utils::project::FrameworkContext;
use std::path::Path;
use tree_sitter::Tree;

pub mod actix_web;
pub mod axum;
pub mod common;
pub mod django;
pub mod echo;
pub mod express;
pub mod fastify;
pub mod flask;
pub mod gin;
pub mod koa;
pub mod rails;
pub mod rocket;
pub mod sinatra;
pub mod spring;

pub trait AuthExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool;
    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
    ) -> AuthorizationModel;
}

pub fn extract_authorization_model(
    lang: &str,
    framework_ctx: Option<&FrameworkContext>,
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
) -> AuthorizationModel {
    let extractors: [&dyn AuthExtractor; 13] = [
        &express::ExpressExtractor,
        &koa::KoaExtractor,
        &fastify::FastifyExtractor,
        &gin::GinExtractor,
        &echo::EchoExtractor,
        &flask::FlaskExtractor,
        &django::DjangoExtractor,
        &spring::SpringExtractor,
        &rails::RailsExtractor,
        &sinatra::SinatraExtractor,
        &axum::AxumExtractor,
        &actix_web::ActixWebExtractor,
        &rocket::RocketExtractor,
    ];
    let mut model = AuthorizationModel::default();

    for extractor in extractors {
        if extractor.supports(lang, framework_ctx) {
            model.extend(extractor.extract(tree, bytes, path, rules));
        }
    }

    // **Dedup units by span across extractors.**  Multiple extractors
    // (e.g. Flask + Django on a Python file) each call
    // `collect_top_level_units`, producing one unit per top-level
    // function.  When one extractor also recognises a route on that
    // function and promotes its copy to `RouteHandler` (with injected
    // middleware auth checks), the *other* extractor's untouched
    // `Function` copy still runs through `check_ownership_gaps` and
    // emits the FP from a unit that never saw the middleware-derived
    // auth check.
    //
    // This step keeps a single canonical unit per source span,
    // preferring `RouteHandler` over `Function`, merging auth_checks
    // and folding operation lists conservatively.  Route registrations
    // are remapped to the surviving unit index.
    deduplicate_units_by_span(&mut model);

    model
}

fn deduplicate_units_by_span(model: &mut AuthorizationModel) {
    use crate::auth_analysis::model::{AnalysisUnit, AnalysisUnitKind};
    use std::collections::HashMap;

    // First pass: choose a winner for each span, prefer the
    // first-seen `RouteHandler` over any `Function` copy.
    let mut winner_by_span: HashMap<(usize, usize), usize> = HashMap::new();
    for (idx, unit) in model.units.iter().enumerate() {
        let key = unit.span;
        match winner_by_span.get(&key) {
            None => {
                winner_by_span.insert(key, idx);
            }
            Some(&existing) => {
                let prev_kind = model.units[existing].kind;
                if prev_kind != AnalysisUnitKind::RouteHandler
                    && unit.kind == AnalysisUnitKind::RouteHandler
                {
                    winner_by_span.insert(key, idx);
                }
            }
        }
    }

    // Second pass: drain auth_checks from losers so we can append them
    // to the winners after the layout collapses.
    let mut moved_checks: Vec<Vec<crate::auth_analysis::model::AuthCheck>> =
        Vec::with_capacity(model.units.len());
    for old_idx in 0..model.units.len() {
        let span = model.units[old_idx].span;
        let winner = *winner_by_span.get(&span).unwrap_or(&old_idx);
        if winner == old_idx {
            moved_checks.push(Vec::new());
        } else {
            moved_checks.push(std::mem::take(&mut model.units[old_idx].auth_checks));
        }
    }

    // Third pass: emit surviving units (clone the winners) and build
    // the old-idx → new-idx remap.
    let mut new_idx_for_old: HashMap<usize, usize> = HashMap::new();
    let mut surviving: Vec<AnalysisUnit> = Vec::with_capacity(winner_by_span.len());
    for old_idx in 0..model.units.len() {
        let span = model.units[old_idx].span;
        let winner = *winner_by_span.get(&span).unwrap_or(&old_idx);
        if winner == old_idx {
            new_idx_for_old.insert(old_idx, surviving.len());
            surviving.push(model.units[old_idx].clone());
        }
    }

    // Fourth pass: drain loser auth_checks into their winners, deduping
    // by (span, callee).  Operations are not merged: both extractor
    // passes recompute the same operation list from the AST, so the
    // winner already carries the canonical set.
    for (old_idx, checks) in moved_checks.iter_mut().enumerate() {
        let span = model.units[old_idx].span;
        let winner = *winner_by_span.get(&span).unwrap_or(&old_idx);
        if winner == old_idx {
            continue;
        }
        let Some(&new_winner_idx) = new_idx_for_old.get(&winner) else {
            continue;
        };
        for check in checks.drain(..) {
            let already_present = surviving[new_winner_idx]
                .auth_checks
                .iter()
                .any(|existing| existing.span == check.span && existing.callee == check.callee);
            if !already_present {
                surviving[new_winner_idx].auth_checks.push(check);
            }
        }
    }

    model.units = surviving;
    for route in &mut model.routes {
        if let Some(&new_idx) = new_idx_for_old.get(&route.unit_idx) {
            route.unit_idx = new_idx;
        }
    }
}
