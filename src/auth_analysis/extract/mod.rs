use super::config::AuthAnalysisRules;
use super::model::AuthorizationModel;
use crate::utils::project::FrameworkContext;
use std::path::Path;
use tree_sitter::Tree;

pub mod express;

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
    let extractors: [&dyn AuthExtractor; 1] = [&express::ExpressExtractor];
    let mut model = AuthorizationModel::default();

    for extractor in extractors {
        if extractor.supports(lang, framework_ctx) {
            model.extend(extractor.extract(tree, bytes, path, rules));
        }
    }

    model
}
