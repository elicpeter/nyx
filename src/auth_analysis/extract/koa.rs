use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_site_from_node, collect_top_level_units, is_handler_reference,
    named_children, string_literal_value, text,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{AuthorizationModel, Framework, HttpMethod, RouteRegistration};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct KoaExtractor;

impl AuthExtractor for KoaExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        matches!(lang, "javascript" | "typescript")
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Koa))
    }

    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
    ) -> AuthorizationModel {
        let root = tree.root_node();
        let mut model = AuthorizationModel::default();

        collect_top_level_units(root, bytes, rules, &mut model);
        collect_routes(root, root, bytes, path, rules, &mut model);

        model
    }
}

fn collect_routes(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if node.kind() == "call_expression" {
        maybe_collect_route(root, node, bytes, path, rules, model);
    }

    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        collect_routes(root, child, bytes, path, rules, model);
    }
}

fn maybe_collect_route(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let Some((object_name, method)) = parse_route_target(function, bytes) else {
        return;
    };
    if !matches!(object_name.as_str(), "koaRouter" | "router" | "app" | "koa") {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let named_args = named_children(arguments);
    let Some(path_node) = named_args.first().copied() else {
        return;
    };
    let Some(route_path) = string_literal_value(path_node, bytes) else {
        return;
    };

    let Some((handler_idx, handler_expr)) = named_args
        .iter()
        .enumerate()
        .rev()
        .find(|(_, arg)| is_handler_reference(**arg))
    else {
        return;
    };

    let Some(handler) = attach_route_handler(
        root,
        *handler_expr,
        format!("{:?} {}", method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_nodes: Vec<Node<'_>> = named_args[1..handler_idx].to_vec();
    let middleware_calls = middleware_nodes
        .iter()
        .map(|middleware| call_site_from_node(*middleware, bytes))
        .collect::<Vec<_>>();
    let middleware = middleware_calls
        .iter()
        .map(|call| call.name.clone())
        .collect::<Vec<_>>();

    model.routes.push(RouteRegistration {
        framework: Framework::Koa,
        method,
        path: route_path,
        middleware,
        handler_span: handler.span,
        handler_params: handler.params,
        file: path.to_path_buf(),
        line: handler.line,
        unit_idx: handler.unit_idx,
        middleware_calls,
    });
}

fn parse_route_target(node: Node<'_>, bytes: &[u8]) -> Option<(String, HttpMethod)> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    let method_name = text(property, bytes);
    let method = match method_name.as_str() {
        "get" => HttpMethod::Get,
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "delete" => HttpMethod::Delete,
        "patch" => HttpMethod::Patch,
        "all" => HttpMethod::All,
        "use" => HttpMethod::Use,
        _ => return None,
    };
    Some((text(object, bytes), method))
}
