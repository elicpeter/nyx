use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_name, call_site_from_node, call_sites_from_value,
    collect_top_level_units, function_definition_node, named_children, resolve_handler_node,
    string_literal_value, text,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{
    AuthCheck, AuthCheckKind, AuthorizationModel, CallSite, Framework, HttpMethod,
    RouteRegistration, ValueRef, ValueSourceKind,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct AxumExtractor;

impl AuthExtractor for AxumExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "rust"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Axum))
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

    for child in named_children(node) {
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
    if call_name(node, bytes).rsplit('.').next() != Some("route") {
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
    let Some(route_spec) = args.get(1).copied() else {
        return;
    };
    let Some(spec) = parse_method_router(route_spec, bytes) else {
        return;
    };
    let Some(handler_node) = resolve_handler_node(root, spec.handler_expr, bytes) else {
        return;
    };
    let Some(handler) = attach_route_handler(
        root,
        spec.handler_expr,
        format!("{:?} {}", spec.method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let mut middleware_calls = inherited_layer_calls(node, bytes);
    middleware_calls.extend(spec.middleware_calls.clone());
    let guard_calls =
        guard_calls_for_handler(handler_node, &route_path, bytes, GuardFramework::Axum);
    middleware_calls.extend(guard_calls.clone());
    dedup_call_sites(&mut middleware_calls);

    if let Some(unit) = model.units.get_mut(handler.unit_idx) {
        let aliases = rust_param_aliases(handler_node, &route_path, bytes, GuardFramework::Axum);
        apply_aliases(unit, &aliases);
        inject_guard_checks(unit, &guard_calls, rules);
    }

    model.routes.push(RouteRegistration {
        framework: Framework::Axum,
        method: spec.method,
        path: route_path,
        middleware: middleware_calls
            .iter()
            .map(|call| call.name.clone())
            .collect(),
        handler_span: handler.span,
        handler_params: handler.params,
        file: path.to_path_buf(),
        line: handler.line,
        unit_idx: handler.unit_idx,
        middleware_calls,
    });
}

struct MethodRouterSpec<'tree> {
    method: HttpMethod,
    handler_expr: Node<'tree>,
    middleware_calls: Vec<CallSite>,
}

fn parse_method_router<'tree>(node: Node<'tree>, bytes: &[u8]) -> Option<MethodRouterSpec<'tree>> {
    let last = call_name(node, bytes).rsplit('.').next()?.to_string();
    if let Some(method) = axum_http_method(&last) {
        let args = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        let handler_expr = *args.last()?;
        return Some(MethodRouterSpec {
            method,
            handler_expr,
            middleware_calls: Vec::new(),
        });
    }

    if node.kind() != "call_expression" {
        return None;
    }

    let Some(function) = node.child_by_field_name("function") else {
        return None;
    };
    let Some(receiver) = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("argument"))
    else {
        return None;
    };
    let mut spec = parse_method_router(receiver, bytes)?;
    match last.as_str() {
        "layer" | "route_layer" => {
            if let Some(arguments) = node.child_by_field_name("arguments") {
                for arg in named_children(arguments) {
                    spec.middleware_calls
                        .extend(expanded_guard_call_sites(arg, bytes));
                }
            }
            Some(spec)
        }
        _ => None,
    }
}

fn axum_http_method(name: &str) -> Option<HttpMethod> {
    match name {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        "any" => Some(HttpMethod::All),
        _ => None,
    }
}

fn inherited_layer_calls(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let Some(function) = node.child_by_field_name("function") else {
        return Vec::new();
    };
    let Some(receiver) = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("argument"))
    else {
        return Vec::new();
    };
    collect_layer_calls(receiver, bytes)
}

fn collect_layer_calls(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    if node.kind() != "call_expression" {
        return Vec::new();
    }

    let mut calls = Vec::new();
    let name = call_name(node, bytes);
    if matches!(name.rsplit('.').next(), Some("layer" | "route_layer"))
        && let Some(arguments) = node.child_by_field_name("arguments")
    {
        for arg in named_children(arguments) {
            calls.extend(expanded_guard_call_sites(arg, bytes));
        }
    }

    if let Some(function) = node.child_by_field_name("function")
        && let Some(receiver) = function
            .child_by_field_name("object")
            .or_else(|| function.child_by_field_name("argument"))
    {
        calls.extend(collect_layer_calls(receiver, bytes));
    }

    calls
}

#[derive(Clone, Copy)]
pub(crate) enum GuardFramework {
    Axum,
    ActixWeb,
    Rocket,
}

pub(crate) fn rust_param_aliases(
    handler_node: Node<'_>,
    route_path: &str,
    bytes: &[u8],
    framework: GuardFramework,
) -> HashMap<String, ValueSourceKind> {
    let mut aliases = HashMap::new();
    let Some(parameters) = function_definition_node(handler_node).child_by_field_name("parameters")
    else {
        return aliases;
    };

    let path_names = route_placeholder_names(route_path);
    let query_names = route_query_placeholder_names(route_path);

    for param in named_children(parameters) {
        let param_text = text(param, bytes);
        if param.kind() == "self_parameter" || param_text.trim().is_empty() {
            continue;
        }
        let binding = rust_binding_name(&param_text);
        let type_text = rust_param_type_text(param, bytes, &param_text);
        if binding.is_empty() || type_text.is_empty() {
            continue;
        }

        let kind = match framework {
            GuardFramework::Axum => classify_axum_param(&binding, &type_text),
            GuardFramework::ActixWeb => classify_actix_param(&binding, &type_text),
            GuardFramework::Rocket => {
                classify_rocket_param(&binding, &type_text, &path_names, &query_names)
            }
        };
        if let Some(kind) = kind {
            aliases.insert(binding, kind);
        }
    }

    aliases
}

pub(crate) fn guard_calls_for_handler(
    handler_node: Node<'_>,
    route_path: &str,
    bytes: &[u8],
    framework: GuardFramework,
) -> Vec<CallSite> {
    let mut calls = Vec::new();
    let Some(parameters) = function_definition_node(handler_node).child_by_field_name("parameters")
    else {
        return calls;
    };
    let span = (handler_node.start_byte(), handler_node.end_byte());
    let path_names = route_placeholder_names(route_path);
    let query_names = route_query_placeholder_names(route_path);

    for param in named_children(parameters) {
        let param_text = text(param, bytes);
        if param.kind() == "self_parameter" || param_text.trim().is_empty() {
            continue;
        }
        let type_text = rust_param_type_text(param, bytes, &param_text);
        let Some(kind) = (match framework {
            GuardFramework::Axum => classify_guard_type(&type_text),
            GuardFramework::ActixWeb => classify_guard_type(&type_text),
            GuardFramework::Rocket => classify_rocket_guard_type(
                &type_text,
                &rust_binding_name(&param_text),
                &path_names,
                &query_names,
            ),
        }) else {
            continue;
        };

        let name = type_last_segment(&type_text);
        if !name.is_empty() {
            calls.push(CallSite {
                name,
                args: Vec::new(),
                span,
            });
            if matches!(kind, AuthCheckKind::AdminGuard) {
                calls.push(CallSite {
                    name: "require_admin".to_string(),
                    args: Vec::new(),
                    span,
                });
            }
        }
    }

    dedup_call_sites(&mut calls);
    calls
}

fn classify_axum_param(binding: &str, type_text: &str) -> Option<ValueSourceKind> {
    if wrapper_type_matches(type_text, &["Path"]) {
        Some(ValueSourceKind::RequestParam)
    } else if wrapper_type_matches(type_text, &["Query"]) {
        Some(ValueSourceKind::RequestQuery)
    } else if wrapper_type_matches(type_text, &["Json", "Form"]) {
        Some(ValueSourceKind::RequestBody)
    } else if wrapper_type_matches(type_text, &["State", "Extension"]) || binding == "session" {
        Some(ValueSourceKind::Session)
    } else {
        None
    }
}

fn classify_actix_param(binding: &str, type_text: &str) -> Option<ValueSourceKind> {
    if wrapper_type_matches(type_text, &["Path"]) {
        Some(ValueSourceKind::RequestParam)
    } else if wrapper_type_matches(type_text, &["Query"]) {
        Some(ValueSourceKind::RequestQuery)
    } else if wrapper_type_matches(type_text, &["Json", "Form"]) {
        Some(ValueSourceKind::RequestBody)
    } else if wrapper_type_matches(type_text, &["Session", "Identity", "ReqData"])
        || binding == "session"
    {
        Some(ValueSourceKind::Session)
    } else {
        None
    }
}

fn classify_rocket_param(
    binding: &str,
    type_text: &str,
    path_names: &[String],
    query_names: &[String],
) -> Option<ValueSourceKind> {
    if wrapper_type_matches(type_text, &["Json", "Form"]) {
        Some(ValueSourceKind::RequestBody)
    } else if wrapper_type_matches(type_text, &["State", "Session"]) || binding == "session" {
        Some(ValueSourceKind::Session)
    } else if query_names.iter().any(|name| name == binding) {
        Some(ValueSourceKind::RequestQuery)
    } else if path_names.iter().any(|name| name == binding) {
        Some(ValueSourceKind::RequestParam)
    } else {
        None
    }
}

fn classify_guard_type(type_text: &str) -> Option<AuthCheckKind> {
    let lower = type_text.to_ascii_lowercase();
    if is_extractor_wrapper(&lower) {
        return None;
    }
    if lower.contains("admin") {
        Some(AuthCheckKind::AdminGuard)
    } else if lower.contains("user")
        || lower.contains("auth")
        || lower.contains("session")
        || lower.contains("identity")
    {
        Some(AuthCheckKind::LoginGuard)
    } else {
        None
    }
}

fn classify_rocket_guard_type(
    type_text: &str,
    binding: &str,
    path_names: &[String],
    query_names: &[String],
) -> Option<AuthCheckKind> {
    if path_names.iter().any(|name| name == binding)
        || query_names.iter().any(|name| name == binding)
    {
        return None;
    }
    classify_guard_type(type_text)
}

fn is_extractor_wrapper(lower: &str) -> bool {
    lower.contains("path<")
        || lower.contains("query<")
        || lower.contains("json<")
        || lower.contains("form<")
        || lower.contains("state<")
        || lower.contains("extension<")
        || lower.contains("web::")
}

fn wrapper_type_matches(type_text: &str, wrappers: &[&str]) -> bool {
    let normalized = type_text.replace(' ', "");
    wrappers.iter().any(|wrapper| {
        normalized.contains(&format!("{wrapper}<")) || normalized.contains(&format!("::{wrapper}<"))
    })
}

fn rust_binding_name(param_text: &str) -> String {
    let before_colon = param_text.split(':').next().unwrap_or(param_text).trim();
    let tokens: Vec<&str> = before_colon
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty() && *token != "mut")
        .collect();
    tokens.last().copied().unwrap_or_default().to_string()
}

fn rust_param_type_text(param: Node<'_>, bytes: &[u8], param_text: &str) -> String {
    param
        .child_by_field_name("type")
        .map(|node| text(node, bytes))
        .or_else(|| {
            param_text
                .split_once(':')
                .map(|(_, ty)| ty.trim().to_string())
        })
        .unwrap_or_default()
}

fn route_placeholder_names(route_path: &str) -> Vec<String> {
    route_path
        .split(['/', '<', '>', ':', '{', '}'])
        .filter(|segment| !segment.is_empty())
        .filter(|segment| !segment.contains('?'))
        .filter(|segment| {
            route_path.contains(&format!("<{segment}>"))
                || route_path.contains(&format!(":{segment}"))
                || route_path.contains(&format!("{{{segment}}}"))
        })
        .map(|segment| segment.to_string())
        .collect()
}

fn route_query_placeholder_names(route_path: &str) -> Vec<String> {
    let Some((_, query)) = route_path.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|segment| {
            if let Some(name) = segment.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
                Some(name.to_string())
            } else {
                segment
                    .split('=')
                    .next()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(|name| name.to_string())
            }
        })
        .collect()
}

fn type_last_segment(type_text: &str) -> String {
    type_text
        .trim_start_matches('&')
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'))
        .find(|segment| !segment.is_empty())
        .and_then(|segment| segment.rsplit("::").next())
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn expanded_guard_call_sites(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let mut calls = call_sites_from_value(node, bytes);
    if node.kind() == "call_expression" {
        let name = call_name(node, bytes);
        if matches!(
            name.rsplit('.').next(),
            Some("from_fn" | "from_fn_with_state" | "wrap_fn" | "fn_guard")
        ) && let Some(arguments) = node.child_by_field_name("arguments")
        {
            for arg in named_children(arguments) {
                let inner = call_site_from_node(arg, bytes);
                if !inner.name.is_empty() {
                    calls.push(inner);
                }
            }
        }
    }
    dedup_call_sites(&mut calls);
    calls
}

pub(crate) fn dedup_call_sites(calls: &mut Vec<CallSite>) {
    let mut deduped = Vec::new();
    for call in calls.drain(..) {
        if !deduped.iter().any(|existing: &CallSite| {
            existing.name == call.name && existing.span == call.span && existing.args == call.args
        }) {
            deduped.push(call);
        }
    }
    *calls = deduped;
}

pub(crate) fn apply_aliases(
    unit: &mut crate::auth_analysis::model::AnalysisUnit,
    aliases: &HashMap<String, ValueSourceKind>,
) {
    for value in &mut unit.value_refs {
        apply_alias_to_value(value, aliases);
    }
    for check in &mut unit.auth_checks {
        for subject in &mut check.subjects {
            apply_alias_to_value(subject, aliases);
        }
    }
    for op in &mut unit.operations {
        for subject in &mut op.subjects {
            apply_alias_to_value(subject, aliases);
        }
    }
    unit.context_inputs = unit
        .value_refs
        .iter()
        .filter(|value| {
            matches!(
                value.source_kind,
                ValueSourceKind::RequestParam
                    | ValueSourceKind::RequestBody
                    | ValueSourceKind::RequestQuery
                    | ValueSourceKind::Session
            )
        })
        .cloned()
        .collect();
}

fn apply_alias_to_value(value: &mut ValueRef, aliases: &HashMap<String, ValueSourceKind>) {
    let root = value
        .base
        .as_deref()
        .and_then(first_identifier)
        .or_else(|| first_identifier(&value.name));
    let Some(root) = root else {
        return;
    };
    let Some(kind) = aliases.get(root) else {
        return;
    };

    if value.source_kind == ValueSourceKind::ArrayIndex && *kind != ValueSourceKind::Session {
        return;
    }

    value.source_kind = *kind;
}

fn first_identifier(input: &str) -> Option<&str> {
    let mut end = input.len();
    for (idx, ch) in input.char_indices() {
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            end = idx;
            break;
        }
    }
    if end == 0 { None } else { Some(&input[..end]) }
}

pub(crate) fn inject_guard_checks(
    unit: &mut crate::auth_analysis::model::AnalysisUnit,
    guard_calls: &[CallSite],
    rules: &AuthAnalysisRules,
) {
    let line = unit.line;
    for call in guard_calls {
        let kind = if rules.is_admin_guard(&call.name, &call.args) {
            AuthCheckKind::AdminGuard
        } else if rules.is_login_guard(&call.name) {
            AuthCheckKind::LoginGuard
        } else {
            continue;
        };
        unit.auth_checks.push(AuthCheck {
            kind,
            callee: call.name.clone(),
            subjects: Vec::new(),
            span: call.span,
            line,
            args: call.args.clone(),
            condition_text: None,
        });
    }
}
