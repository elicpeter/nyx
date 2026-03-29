use super::AuthExtractor;
use super::common::{
    attach_route_handler, auth_check_from_call_site, call_site_from_node, named_children,
    string_literal_value, text,
};
use crate::auth_analysis::config::{AuthAnalysisRules, matches_name};
use crate::auth_analysis::extract::common::{
    collect_top_level_units, decorated_definition_child,
};
use crate::auth_analysis::model::{
    AuthorizationModel, CallSite, Framework, HttpMethod, RouteRegistration,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct FlaskExtractor;

impl AuthExtractor for FlaskExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "python"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Flask))
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

#[derive(Clone)]
struct FlaskRouteSpec {
    method: HttpMethod,
    path: String,
}

fn collect_routes(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if node.kind() == "decorated_definition" {
        maybe_collect_flask_route(root, node, bytes, path, rules, model);
    }

    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        collect_routes(root, child, bytes, path, rules, model);
    }
}

fn maybe_collect_flask_route(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(definition) = decorated_definition_child(node) else {
        return;
    };
    if definition.kind() != "function_definition" {
        return;
    }

    let mut route_specs = Vec::new();
    let mut middleware_calls = Vec::new();
    for decorator in decorator_expressions(node) {
        if let Some(mut specs) = parse_flask_route_decorator(decorator, bytes) {
            route_specs.append(&mut specs);
        } else {
            middleware_calls.extend(expand_decorator_calls(decorator, bytes));
        }
    }

    if route_specs.is_empty() {
        return;
    }

    let middleware_names: Vec<String> = middleware_calls
        .iter()
        .map(|call| call.name.clone())
        .collect();

    for spec in route_specs {
        let Some(handler) = attach_route_handler(
            root,
            node,
            format!("{:?} {}", spec.method, spec.path),
            bytes,
            rules,
            model,
        ) else {
            continue;
        };
        inject_middleware_auth(model, handler.unit_idx, handler.line, &middleware_calls, rules);

        model.routes.push(RouteRegistration {
            framework: Framework::Flask,
            method: spec.method,
            path: spec.path,
            middleware: middleware_names.clone(),
            handler_span: handler.span,
            handler_params: handler.params,
            file: path.to_path_buf(),
            line: handler.line,
            unit_idx: handler.unit_idx,
            middleware_calls: middleware_calls.clone(),
        });
    }
}

fn parse_flask_route_decorator(
    decorator_expr: Node<'_>,
    bytes: &[u8],
) -> Option<Vec<FlaskRouteSpec>> {
    let function = if decorator_expr.kind() == "call" {
        decorator_expr.child_by_field_name("function")?
    } else {
        return None;
    };

    let callee = text(function, bytes);
    let method_name = callee.rsplit('.').next().unwrap_or(&callee);
    let arguments = decorator_expr.child_by_field_name("arguments")?;
    let args = named_children(arguments);

    let route_path = args
        .iter()
        .find_map(|arg| string_literal_value(*arg, bytes))
        .or_else(|| keyword_argument_string(arguments, bytes, "rule"))?;

    let methods = match method_name.to_ascii_lowercase().as_str() {
        "get" => vec![HttpMethod::Get],
        "post" => vec![HttpMethod::Post],
        "put" => vec![HttpMethod::Put],
        "delete" => vec![HttpMethod::Delete],
        "patch" => vec![HttpMethod::Patch],
        "route" => parse_methods_keyword(arguments, bytes).unwrap_or_else(|| vec![HttpMethod::Get]),
        _ => return None,
    };

    Some(
        methods
            .into_iter()
            .map(|method| FlaskRouteSpec {
                method,
                path: route_path.clone(),
            })
            .collect(),
    )
}

fn parse_methods_keyword(arguments: Node<'_>, bytes: &[u8]) -> Option<Vec<HttpMethod>> {
    let value = keyword_argument_value(arguments, bytes, "methods")?;
    let mut methods = Vec::new();
    for child in named_children(value) {
        if let Some(method) = string_literal_value(child, bytes).and_then(|text| http_method(&text)) {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        None
    } else {
        Some(methods)
    }
}

fn keyword_argument_string(arguments: Node<'_>, bytes: &[u8], name: &str) -> Option<String> {
    let value = keyword_argument_value(arguments, bytes, name)?;
    string_literal_value(value, bytes)
}

fn keyword_argument_value<'tree>(
    arguments: Node<'tree>,
    bytes: &[u8],
    name: &str,
) -> Option<Node<'tree>> {
    for arg in named_children(arguments) {
        if arg.kind() != "keyword_argument" {
            continue;
        }
        let key = arg.child_by_field_name("name")?;
        if text(key, bytes) == name {
            return arg.child_by_field_name("value");
        }
    }
    None
}

fn http_method(value: &str) -> Option<HttpMethod> {
    match value.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        _ => None,
    }
}

fn decorator_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| named_children(decorator).into_iter().next())
        .collect()
}

fn expand_decorator_calls(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    if node.kind() == "call" {
        let call = call_site_from_node(node, bytes);
        if matches_name(&call.name, "method_decorator")
            && let Some(arguments) = node.child_by_field_name("arguments")
            && let Some(first) = named_children(arguments).first().copied()
        {
            return vec![call_site_from_node(first, bytes)];
        }
        return vec![call];
    }

    vec![call_site_from_node(node, bytes)]
}

fn inject_middleware_auth(
    model: &mut AuthorizationModel,
    unit_idx: usize,
    line: usize,
    middleware_calls: &[CallSite],
    rules: &AuthAnalysisRules,
) {
    let Some(unit) = model.units.get_mut(unit_idx) else {
        return;
    };
    for call in middleware_calls {
        if let Some(check) = auth_check_from_call_site(call, line, rules) {
            unit.auth_checks.push(check);
        }
    }
}
