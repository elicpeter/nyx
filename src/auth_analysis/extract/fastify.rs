use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_sites_from_value, is_handler_reference, named_children,
    object_property_value, string_literal_value, text,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::extract::common::collect_top_level_units;
use crate::auth_analysis::model::{
    AuthorizationModel, CallSite, Framework, HttpMethod, RouteRegistration,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct FastifyExtractor;

impl AuthExtractor for FastifyExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        matches!(lang, "javascript" | "typescript")
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Fastify))
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
        maybe_collect_shorthand_route(root, node, bytes, path, rules, model);
        maybe_collect_route_object(root, node, bytes, path, rules, model);
    }

    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        collect_routes(root, child, bytes, path, rules, model);
    }
}

fn maybe_collect_shorthand_route(
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
    let Some((object_name, method)) = parse_fastify_target(function, bytes) else {
        return;
    };
    if !matches!(object_name.as_str(), "fastify" | "app" | "server") {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = named_children(arguments);
    let Some(path_node) = args.first().copied() else {
        return;
    };
    let Some(route_path) = string_literal_value(path_node, bytes) else {
        return;
    };

    let options = args.get(1).copied().filter(|node| node.kind() == "object");
    let handler_expr = args
        .last()
        .copied()
        .filter(|node| is_handler_reference(*node))
        .or_else(|| options.and_then(|opts| object_property_value(opts, bytes, &["handler"])));
    let Some(handler_expr) = handler_expr else {
        return;
    };

    let Some(handler) = attach_route_handler(
        root,
        handler_expr,
        format!("{:?} {}", method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_calls = options
        .map(|opts| collect_fastify_hooks(opts, bytes))
        .unwrap_or_default();
    let middleware = middleware_calls
        .iter()
        .map(|call| call.name.clone())
        .collect::<Vec<_>>();

    model.routes.push(RouteRegistration {
        framework: Framework::Fastify,
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

fn maybe_collect_route_object(
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
    if !is_fastify_route_call(function, bytes) {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let Some(route_object) = named_children(arguments).first().copied() else {
        return;
    };
    if route_object.kind() != "object" {
        return;
    }

    let Some(method_text) = object_property_value(route_object, bytes, &["method"])
        .and_then(|value| string_literal_value(value, bytes))
    else {
        return;
    };
    let Some(method) = http_method_from_text(&method_text) else {
        return;
    };
    let Some(route_path) = object_property_value(route_object, bytes, &["url", "path"])
        .and_then(|value| string_literal_value(value, bytes))
    else {
        return;
    };
    let Some(handler_expr) = object_property_value(route_object, bytes, &["handler"]) else {
        return;
    };
    let Some(handler) = attach_route_handler(
        root,
        handler_expr,
        format!("{:?} {}", method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_calls = collect_fastify_hooks(route_object, bytes);
    let middleware = middleware_calls
        .iter()
        .map(|call| call.name.clone())
        .collect::<Vec<_>>();

    model.routes.push(RouteRegistration {
        framework: Framework::Fastify,
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

fn collect_fastify_hooks(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let mut hooks = Vec::new();
    for field in ["preHandler", "preValidation", "onRequest"] {
        if let Some(value) = object_property_value(node, bytes, &[field]) {
            hooks.extend(call_sites_from_value(value, bytes));
        }
    }
    hooks
}

fn is_fastify_route_call(node: Node<'_>, bytes: &[u8]) -> bool {
    if node.kind() != "member_expression" {
        return false;
    }
    let Some(object) = node.child_by_field_name("object") else {
        return false;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return false;
    };
    matches!(text(object, bytes).as_str(), "fastify" | "app" | "server")
        && text(property, bytes) == "route"
}

fn parse_fastify_target(node: Node<'_>, bytes: &[u8]) -> Option<(String, HttpMethod)> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    let object_name = text(object, bytes);
    let method = http_method_from_text(&text(property, bytes))?;
    Some((object_name, method))
}

fn http_method_from_text(text: &str) -> Option<HttpMethod> {
    match text.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        "all" => Some(HttpMethod::All),
        "use" => Some(HttpMethod::Use),
        _ => None,
    }
}
