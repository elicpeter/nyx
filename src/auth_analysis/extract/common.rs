use crate::auth_analysis::config::{AuthAnalysisRules, matches_name, strip_quotes};
use crate::auth_analysis::model::{
    AnalysisUnit, AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel, CallSite,
    OperationKind, SensitiveOperation, ValueRef, ValueSourceKind,
};
use tree_sitter::Node;

pub fn collect_top_level_units(
    root: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    for idx in 0..root.named_child_count() {
        let Some(child) = root.named_child(idx as u32) else {
            continue;
        };
        collect_top_level_from_node(child, bytes, rules, model);
    }
}

fn collect_top_level_from_node(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    match node.kind() {
        "function_declaration" => {
            model.units.push(build_function_unit(
                node,
                AnalysisUnitKind::Function,
                function_name(node, bytes),
                bytes,
                rules,
            ));
        }
        "lexical_declaration" | "variable_declaration" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if child.kind() == "variable_declarator" {
                    if let Some(unit) = function_unit_from_var_declarator(child, bytes, rules) {
                        model.units.push(unit);
                    }
                }
            }
        }
        "export_statement" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if child.is_named() {
                    collect_top_level_from_node(child, bytes, rules, model);
                }
            }
        }
        _ => {}
    }
}

fn function_unit_from_var_declarator(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
) -> Option<AnalysisUnit> {
    let value = node.child_by_field_name("value")?;
    if !is_function_like(value) {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| text(n, bytes))
        .filter(|s| !s.is_empty());
    Some(build_function_unit(
        value,
        AnalysisUnitKind::Function,
        name,
        bytes,
        rules,
    ))
}

pub struct ResolvedHandler {
    pub unit_idx: usize,
    pub span: (usize, usize),
    pub params: Vec<String>,
    pub line: usize,
}

pub fn attach_route_handler(
    root: Node<'_>,
    handler_expr: Node<'_>,
    route_name: String,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) -> Option<ResolvedHandler> {
    let handler_node = resolve_handler_node(root, handler_expr, bytes)?;
    let unit_idx = model.units.len();
    let unit = build_function_unit(
        handler_node,
        AnalysisUnitKind::RouteHandler,
        Some(route_name),
        bytes,
        rules,
    );
    let params = unit.params.clone();
    let line = handler_node.start_position().row + 1;
    let span = span(handler_node);
    model.units.push(unit);
    Some(ResolvedHandler {
        unit_idx,
        span,
        params,
        line,
    })
}

pub fn resolve_handler_node<'tree>(
    root: Node<'tree>,
    handler_expr: Node<'tree>,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    if is_function_like(handler_expr) {
        return Some(handler_expr);
    }

    if !is_handler_reference(handler_expr) {
        return None;
    }

    let candidate = callee_name(handler_expr, bytes);
    let name = candidate.rsplit('.').next().unwrap_or(&candidate);
    if name.is_empty() {
        return None;
    }
    find_top_level_function_node(root, name, bytes)
}

fn find_top_level_function_node<'tree>(
    root: Node<'tree>,
    name: &str,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    for idx in 0..root.named_child_count() {
        let Some(child) = root.named_child(idx as u32) else {
            continue;
        };
        if let Some(found) = find_top_level_function_node_in_child(child, name, bytes) {
            return Some(found);
        }
    }
    None
}

fn find_top_level_function_node_in_child<'tree>(
    node: Node<'tree>,
    name: &str,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    match node.kind() {
        "function_declaration" => {
            if function_name(node, bytes).as_deref() == Some(name) {
                Some(node)
            } else {
                None
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if child.kind() != "variable_declarator" {
                    continue;
                }
                let Some(var_name) = child.child_by_field_name("name") else {
                    continue;
                };
                if text(var_name, bytes) != name {
                    continue;
                }
                let Some(value) = child.child_by_field_name("value") else {
                    continue;
                };
                if is_function_like(value) {
                    return Some(value);
                }
            }
            None
        }
        "export_statement" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if !child.is_named() {
                    continue;
                }
                if let Some(found) = find_top_level_function_node_in_child(child, name, bytes) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

pub fn build_function_unit(
    node: Node<'_>,
    kind: AnalysisUnitKind,
    name: Option<String>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
) -> AnalysisUnit {
    let params = function_params(node, bytes);
    let line = node.start_position().row + 1;
    let mut state = UnitState::default();
    collect_unit_state(node, bytes, rules, &mut state);
    dedup_value_refs(&mut state.value_refs);
    let context_inputs: Vec<ValueRef> = state
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

    AnalysisUnit {
        kind,
        name,
        span: span(node),
        params,
        context_inputs,
        call_sites: state.call_sites,
        auth_checks: state.auth_checks,
        operations: state.operations,
        value_refs: state.value_refs,
        condition_texts: state.condition_texts,
        line,
    }
}

#[derive(Default)]
struct UnitState {
    call_sites: Vec<CallSite>,
    auth_checks: Vec<AuthCheck>,
    operations: Vec<SensitiveOperation>,
    value_refs: Vec<ValueRef>,
    condition_texts: Vec<String>,
}

fn collect_unit_state(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    match node.kind() {
        "call_expression" => collect_call(node, bytes, rules, state),
        "if_statement" | "while_statement" | "do_statement" => {
            if let Some(condition) = node.child_by_field_name("condition") {
                collect_condition(condition, bytes, rules, state);
            }
        }
        "conditional_expression" => collect_condition(node, bytes, rules, state),
        _ => {}
    }

    for value in extract_value_refs(node, bytes) {
        state.value_refs.push(value);
    }

    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        collect_unit_state(child, bytes, rules, state);
    }
}

fn collect_call(node: Node<'_>, bytes: &[u8], rules: &AuthAnalysisRules, state: &mut UnitState) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let callee = callee_name(function, bytes);
    if callee.is_empty() {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = named_children(arguments);
    let subjects: Vec<ValueRef> = args
        .iter()
        .flat_map(|arg| extract_value_refs(*arg, bytes))
        .collect();
    let line = node.start_position().row + 1;
    let string_args: Vec<String> = args.iter().map(|arg| text(*arg, bytes)).collect();
    state.call_sites.push(CallSite {
        name: callee.clone(),
        args: string_args.clone(),
        span: span(node),
    });

    if rules.is_authorization_check(&callee) {
        state.auth_checks.push(AuthCheck {
            kind: classify_auth_check(&callee, rules),
            callee: callee.clone(),
            subjects: subjects.clone(),
            span: span(node),
            line,
            args: string_args,
            condition_text: None,
        });
    }

    let op_kind = if rules.is_token_lookup(&callee) {
        Some(OperationKind::TokenLookup)
    } else if rules.is_mutation(&callee) {
        Some(OperationKind::Mutation)
    } else if rules.is_read(&callee) {
        Some(OperationKind::Read)
    } else {
        None
    };

    if let Some(kind) = op_kind {
        state.operations.push(SensitiveOperation {
            kind,
            callee,
            subjects,
            span: span(node),
            line,
            text: text(node, bytes),
        });
    }
}

fn collect_condition(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    let condition_text = text(node, bytes);
    if condition_text.is_empty() {
        return;
    }
    state.condition_texts.push(condition_text.clone());

    let subjects = extract_value_refs(node, bytes);
    let line = node.start_position().row + 1;

    if rules.has_expiry_field(&condition_text) {
        state.auth_checks.push(AuthCheck {
            kind: AuthCheckKind::TokenExpiry,
            callee: "(condition)".into(),
            subjects: subjects.clone(),
            span: span(node),
            line,
            args: Vec::new(),
            condition_text: Some(condition_text.clone()),
        });
    }

    if rules.has_recipient_field(&condition_text) {
        state.auth_checks.push(AuthCheck {
            kind: AuthCheckKind::TokenRecipient,
            callee: "(condition)".into(),
            subjects,
            span: span(node),
            line,
            args: Vec::new(),
            condition_text: Some(condition_text),
        });
    }
}

fn classify_auth_check(callee: &str, rules: &AuthAnalysisRules) -> AuthCheckKind {
    if rules.is_admin_guard(callee, &[]) || matches_name(callee, "isAdmin") {
        AuthCheckKind::AdminGuard
    } else if rules.is_login_guard(callee) {
        AuthCheckKind::LoginGuard
    } else if matches_name(callee, "checkMembership")
        || matches_name(callee, "hasWorkspaceMembership")
        || matches_name(callee, "isMember")
        || matches_name(callee, "requireMembership")
    {
        AuthCheckKind::Membership
    } else if matches_name(callee, "checkOwnership")
        || matches_name(callee, "isOwner")
        || matches_name(callee, "requireOwnership")
    {
        AuthCheckKind::Ownership
    } else {
        AuthCheckKind::Other
    }
}

fn function_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .map(|name| text(name, bytes))
        .filter(|name| !name.is_empty())
}

fn function_params(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let Some(params_node) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut params = Vec::new();
    collect_param_names(params_node, bytes, &mut params);
    params
}

fn collect_param_names(node: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "identifier" | "property_identifier" | "shorthand_property_identifier_pattern" => {
            let name = text(node, bytes);
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
        _ => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                collect_param_names(child, bytes, out);
            }
        }
    }
}

pub fn is_function_like(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "function_expression" | "arrow_function"
    )
}

pub fn is_handler_reference(node: Node<'_>) -> bool {
    is_function_like(node) || matches!(node.kind(), "identifier" | "member_expression")
}

pub fn call_site_from_node(node: Node<'_>, bytes: &[u8]) -> CallSite {
    if node.kind() == "call_expression" {
        let name = node
            .child_by_field_name("function")
            .map(|callee| callee_name(callee, bytes))
            .unwrap_or_else(|| text(node, bytes));
        let args = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default()
            .into_iter()
            .map(|arg| text(arg, bytes))
            .collect();
        CallSite {
            name,
            args,
            span: span(node),
        }
    } else {
        CallSite {
            name: text(node, bytes),
            args: Vec::new(),
            span: span(node),
        }
    }
}

pub fn call_sites_from_value(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    if node.kind() == "array" {
        named_children(node)
            .into_iter()
            .map(|child| call_site_from_node(child, bytes))
            .filter(|call| !call.name.is_empty())
            .collect()
    } else {
        let call = call_site_from_node(node, bytes);
        if call.name.is_empty() {
            Vec::new()
        } else {
            vec![call]
        }
    }
}

pub fn extract_value_refs(node: Node<'_>, bytes: &[u8]) -> Vec<ValueRef> {
    match node.kind() {
        "member_expression" => member_value_ref(node, bytes).into_iter().collect(),
        "subscript_expression" => subscript_value_ref(node, bytes).into_iter().collect(),
        "identifier" => vec![ValueRef {
            source_kind: ValueSourceKind::Identifier,
            name: text(node, bytes),
            base: None,
            field: None,
            index: None,
            span: span(node),
        }],
        _ => {
            let mut refs = Vec::new();
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                refs.extend(extract_value_refs(child, bytes));
            }
            refs
        }
    }
}

fn member_value_ref(node: Node<'_>, bytes: &[u8]) -> Option<ValueRef> {
    let chain = member_chain(node, bytes);
    if chain.is_empty() {
        return None;
    }
    let name = chain.join(".");
    let field = chain.last().cloned();
    let base = if chain.len() > 1 {
        Some(chain[..chain.len() - 1].join("."))
    } else {
        None
    };
    let source_kind = classify_member_chain(&chain);

    Some(ValueRef {
        source_kind,
        name,
        base,
        field,
        index: None,
        span: span(node),
    })
}

fn classify_member_chain(chain: &[String]) -> ValueSourceKind {
    if matches_request_param(chain) {
        ValueSourceKind::RequestParam
    } else if matches_request_body(chain) {
        ValueSourceKind::RequestBody
    } else if matches_request_query(chain) {
        ValueSourceKind::RequestQuery
    } else if matches_session_context(chain) {
        ValueSourceKind::Session
    } else if chain
        .first()
        .is_some_and(|segment| matches!(segment.as_str(), "invitation" | "token" | "invite"))
    {
        ValueSourceKind::TokenField
    } else {
        ValueSourceKind::MemberField
    }
}

fn matches_request_param(chain: &[String]) -> bool {
    (chain.len() >= 3 && matches!(chain[0].as_str(), "req" | "request") && chain[1] == "params")
        || (chain.len() >= 3 && chain[0] == "ctx" && chain[1] == "params")
}

fn matches_request_body(chain: &[String]) -> bool {
    (chain.len() >= 3 && matches!(chain[0].as_str(), "req" | "request") && chain[1] == "body")
        || (chain.len() >= 4 && chain[0] == "ctx" && chain[1] == "request" && chain[2] == "body")
        || (chain.len() >= 3 && chain[0] == "ctx" && chain[1] == "body")
}

fn matches_request_query(chain: &[String]) -> bool {
    (chain.len() >= 3 && matches!(chain[0].as_str(), "req" | "request") && chain[1] == "query")
        || (chain.len() >= 3 && chain[0] == "ctx" && chain[1] == "query")
        || (chain.len() >= 4 && chain[0] == "ctx" && chain[1] == "request" && chain[2] == "query")
}

fn matches_session_context(chain: &[String]) -> bool {
    (chain.len() >= 3
        && matches!(chain[0].as_str(), "req" | "request")
        && matches!(chain[1].as_str(), "session" | "user" | "currentUser"))
        || (chain.len() >= 3
            && chain[0] == "ctx"
            && matches!(chain[1].as_str(), "session" | "state"))
}

fn subscript_value_ref(node: Node<'_>, bytes: &[u8]) -> Option<ValueRef> {
    let object = node.child_by_field_name("object")?;
    let index = node.child_by_field_name("index")?;
    let base = text(object, bytes);
    let index_text = text(index, bytes);
    Some(ValueRef {
        source_kind: ValueSourceKind::ArrayIndex,
        name: format!("{base}[{index_text}]"),
        base: Some(base),
        field: None,
        index: Some(index_text),
        span: span(node),
    })
}

pub fn member_chain(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    if node.kind() != "member_expression" {
        let value = text(node, bytes);
        return if value.is_empty() {
            Vec::new()
        } else {
            vec![value]
        };
    }

    let mut chain = Vec::new();
    if let Some(object) = node.child_by_field_name("object") {
        chain.extend(member_chain(object, bytes));
    }
    if let Some(property) = node.child_by_field_name("property") {
        let property_text = text(property, bytes);
        if !property_text.is_empty() {
            chain.push(property_text);
        }
    }
    chain
}

pub fn callee_name(node: Node<'_>, bytes: &[u8]) -> String {
    match node.kind() {
        "identifier" | "property_identifier" => text(node, bytes),
        "member_expression" => member_chain(node, bytes).join("."),
        _ => text(node, bytes),
    }
}

pub fn string_literal_value(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "string" | "template_string" => Some(strip_quotes(&text(node, bytes))),
        _ => None,
    }
}

pub fn object_property_value<'tree>(
    node: Node<'tree>,
    bytes: &[u8],
    names: &[&str],
) -> Option<Node<'tree>> {
    if node.kind() != "object" {
        return None;
    }

    for child in named_children(node) {
        match child.kind() {
            "pair" => {
                let Some(key) = child.child_by_field_name("key") else {
                    continue;
                };
                let key_name = strip_quotes(&text(key, bytes));
                if names.iter().any(|name| *name == key_name) {
                    return child.child_by_field_name("value");
                }
            }
            "shorthand_property_identifier" | "identifier" => {
                let key_name = text(child, bytes);
                if names.iter().any(|name| *name == key_name) {
                    return Some(child);
                }
            }
            _ => {}
        }
    }

    None
}

pub fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut children = Vec::new();
    for idx in 0..node.named_child_count() {
        if let Some(child) = node.named_child(idx as u32) {
            children.push(child);
        }
    }
    children
}

pub fn text(node: Node<'_>, bytes: &[u8]) -> String {
    node.utf8_text(bytes).unwrap_or("").to_string()
}

pub fn span(node: Node<'_>) -> (usize, usize) {
    (node.start_byte(), node.end_byte())
}

fn dedup_value_refs(values: &mut Vec<ValueRef>) {
    let mut deduped = Vec::new();
    for value in values.drain(..) {
        if !deduped
            .iter()
            .any(|existing: &ValueRef| existing.name == value.name && existing.span == value.span)
        {
            deduped.push(value);
        }
    }
    *values = deduped;
}
