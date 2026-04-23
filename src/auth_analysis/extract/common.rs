use crate::auth_analysis::config::{AuthAnalysisRules, canonical_name, matches_name, strip_quotes};
use crate::auth_analysis::model::{
    AnalysisUnit, AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel, CallSite,
    Framework, HttpMethod, OperationKind, RouteRegistration, SensitiveOperation, ValueRef,
    ValueSourceKind,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
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
        "function_declaration"
        | "function_definition"
        | "method_declaration"
        | "function_item"
        | "method"
        | "singleton_method" => {
            model.units.push(build_function_unit(
                node,
                AnalysisUnitKind::Function,
                function_name(node, bytes),
                bytes,
                rules,
            ));
        }
        "decorated_definition"
            if decorated_definition_child(node)
                .is_some_and(|definition| definition.kind() == "function_definition") =>
        {
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
                if child.kind() == "variable_declarator"
                    && let Some(unit) = function_unit_from_var_declarator(child, bytes, rules)
                {
                    model.units.push(unit);
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
        "program" | "source_file" | "module" | "class" | "class_declaration" | "class_body"
        | "body_statement" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                collect_top_level_from_node(child, bytes, rules, model);
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

pub fn visit_named_nodes(node: Node<'_>, visit: &mut impl FnMut(Node<'_>)) {
    visit(node);
    for child in named_children(node) {
        visit_named_nodes(child, visit);
    }
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

pub fn push_route_registration(
    model: &mut AuthorizationModel,
    framework: Framework,
    method: HttpMethod,
    path: String,
    file: &Path,
    handler: ResolvedHandler,
    middleware_calls: Vec<CallSite>,
) {
    model.routes.push(RouteRegistration {
        framework,
        method,
        path,
        middleware: middleware_names(&middleware_calls),
        handler_span: handler.span,
        handler_params: handler.params,
        file: file.to_path_buf(),
        line: handler.line,
        unit_idx: handler.unit_idx,
        middleware_calls,
    });
}

pub fn middleware_names(middleware_calls: &[CallSite]) -> Vec<String> {
    middleware_calls
        .iter()
        .map(|call| call.name.clone())
        .collect()
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
        "function_declaration" | "function_definition" | "method_declaration" => {
            if function_name(node, bytes).as_deref() == Some(name) {
                Some(node)
            } else {
                None
            }
        }
        "function_item" => {
            if function_name(node, bytes).as_deref() == Some(name) {
                Some(node)
            } else {
                None
            }
        }
        "decorated_definition" => {
            let definition = decorated_definition_child(node)?;
            if definition.kind() == "function_definition"
                && function_name(node, bytes).as_deref() == Some(name)
            {
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
                if child.is_named()
                    && let Some(found) = find_top_level_function_node_in_child(child, name, bytes)
                {
                    return Some(found);
                }
            }
            None
        }
        "program" | "source_file" | "class_declaration" | "class_body" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
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
    let definition = function_definition_node(node);
    let params = function_params(definition, bytes);
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
        row_field_vars: state.row_field_vars,
        self_actor_vars: state.self_actor_vars,
    }
}

#[derive(Default)]
struct UnitState {
    call_sites: Vec<CallSite>,
    auth_checks: Vec<AuthCheck>,
    operations: Vec<SensitiveOperation>,
    value_refs: Vec<ValueRef>,
    condition_texts: Vec<String>,
    /// Local variable names bound to a known non-sink collection
    /// (e.g. `HashMap::new()`, `Vec::with_capacity(_)`, `vec![]`,
    /// or via an explicit type annotation).  Consulted by
    /// `collect_call` so method calls on these bindings
    /// (`map.insert(…)`, `set.remove(…)`) aren't classified as
    /// auth-relevant Read/Mutation operations.
    non_sink_vars: HashSet<String>,
    /// Map from local variable name to the row binding it was read
    /// from (`let owner_id = existing.get("user_id")` → `owner_id →
    /// existing`). Powers A2's row-level ownership-equality check so
    /// downstream uses of fields from the same row are implicitly
    /// covered by a check on the row's owner column.
    row_field_vars: HashMap<String, String>,
    /// Per row-binding metadata from the `let ROW = CALL(...)` site:
    /// the declaration line and the set of `ValueRef`s appearing in
    /// the call's arguments. When an A2 AuthCheck fires against
    /// `ROW`, we back-date the check to this line and merge these
    /// argument value-refs into its subjects so the original fetch
    /// (e.g. `db.query_one(..., &[doc_id])`) is also covered.
    row_population_data: HashMap<String, (usize, Vec<ValueRef>)>,
    /// A3: local variables bound to the authenticated actor.
    /// Populated from `let V = require_auth(..).await?` (or any call
    /// matching `rules.is_login_guard` / `rules.is_authorization_check`)
    /// and from typed route-handler parameters whose type names the
    /// authenticated user (`CurrentUser`, `AuthUser`, …). Copied onto
    /// `AnalysisUnit.self_actor_vars` so `checks.rs` can recognize
    /// `V.id` as actor context rather than a foreign scoped id.
    self_actor_vars: HashSet<String>,
}

fn collect_unit_state(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    match node.kind() {
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            collect_call(node, bytes, rules, state)
        }
        "if_statement" | "elif_clause" | "while_statement" | "do_statement" | "if" | "unless"
        | "if_modifier" | "unless_modifier" | "while_modifier" | "until_modifier"
        | "while_expression" => {
            if let Some(condition) = node.child_by_field_name("condition") {
                collect_condition(condition, bytes, rules, state);
            }
        }
        "if_expression" => {
            if let Some(condition) = node.child_by_field_name("condition") {
                collect_condition(condition, bytes, rules, state);
            }
            detect_ownership_equality_check(node, bytes, state);
        }
        "conditional_expression" => collect_condition(node, bytes, rules, state),
        "let_declaration" => {
            collect_non_sink_binding(node, bytes, rules, state);
            collect_row_field_binding(node, bytes, state);
            collect_row_population(node, bytes, state);
            collect_self_actor_binding(node, bytes, rules, state);
        }
        "parameter" => {
            collect_typed_extractor_self_actor(node, bytes, state);
        }
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
    let callee = call_name(node, bytes);
    if callee.is_empty() {
        return;
    }

    let args = node
        .child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default();
    let mut subjects: Vec<ValueRef> = call_receiver_subjects(node, bytes);
    subjects.extend(
        args.iter()
            .flat_map(|arg| extract_value_refs(*arg, bytes))
            .collect::<Vec<_>>(),
    );
    let line = node.start_position().row + 1;
    let string_args: Vec<String> = args.iter().map(|arg| text(*arg, bytes)).collect();
    let node_text = text(node, bytes);
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

    let op_kind = if rules.is_token_lookup_call(&callee, &node_text) {
        Some(OperationKind::TokenLookup)
    } else if rules.callee_has_non_sink_receiver(&callee, &state.non_sink_vars) {
        // Call targets a local non-sink collection (HashMap, HashSet,
        // Vec, …) — method calls like `map.insert` / `set.remove` are
        // pure in-memory bookkeeping, not authorization-relevant.
        None
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
            text: node_text,
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

/// Detect `let` bindings that produce a known non-sink collection
/// (e.g. `HashMap::new()`, `Vec::with_capacity(_)`, `vec![]`, or an
/// explicit type annotation like `: HashMap<_, _>`).  Registered
/// variable names are consulted by `collect_call` so later method
/// calls on those bindings (`map.insert(..)`, `set.remove(..)`)
/// aren't treated as auth-relevant Read/Mutation operations.
///
/// Rust-oriented in practice; JS/TS/Python/etc. use different
/// declaration node kinds and are unaffected.
fn collect_non_sink_binding(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }

    if let Some(ty_node) = node.child_by_field_name("type") {
        let ty_text = text(ty_node, bytes);
        if rules.is_non_sink_receiver_type(&ty_text) {
            state.non_sink_vars.insert(var_name);
            return;
        }
    }

    if let Some(value) = node.child_by_field_name("value")
        && value_is_non_sink_constructor(value, bytes, rules)
    {
        state.non_sink_vars.insert(var_name);
    }
}

fn first_identifier_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if matches!(node.kind(), "identifier" | "shorthand_property_identifier_pattern") {
        let value = text(node, bytes);
        if !value.is_empty() {
            return Some(value);
        }
    }
    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        if let Some(found) = first_identifier_name(child, bytes) {
            return Some(found);
        }
    }
    None
}

fn value_is_non_sink_constructor(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
) -> bool {
    match node.kind() {
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let callee = call_name(node, bytes);
            rules.is_non_sink_constructor_callee(&callee)
        }
        "macro_invocation" => {
            let name = node
                .child_by_field_name("macro")
                .map(|m| text(m, bytes))
                .unwrap_or_default();
            let last = name.rsplit("::").next().unwrap_or(&name);
            matches!(last, "vec" | "smallvec")
        }
        "try_expression" | "await_expression" | "reference_expression" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if value_is_non_sink_constructor(child, bytes, rules) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Track `let V = ROW.method(..)` or `let V = ROW.field` so later
/// row-level ownership-equality checks on `V` (or on another var read
/// from the same `ROW`) can be attributed back to `ROW`. See
/// `detect_ownership_equality_check` for the consumer.
fn collect_row_field_binding(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let Some(row_name) = extract_row_receiver_name(value, bytes) else {
        return;
    };
    state.row_field_vars.insert(var_name, row_name);
}

/// Record the line and argument value-refs of a `let ROW = CALL(..)`.
/// When A2 synthesises an `AuthCheck` on `ROW` later, we back-date the
/// check to this line and merge the args into its subjects so the
/// original fetch (e.g. `db.query_one(.., &[doc_id])`) is also covered.
fn collect_row_population(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let call_node = unwrap_try_like(value);
    if !matches!(
        call_node.kind(),
        "call_expression" | "call" | "method_invocation" | "method_call_expression"
    ) {
        return;
    }
    let args = call_node
        .child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default();
    let mut arg_refs: Vec<ValueRef> = Vec::new();
    for arg in args {
        arg_refs.extend(extract_value_refs(arg, bytes));
    }
    let line = node.start_position().row + 1;
    state
        .row_population_data
        .insert(var_name, (line, arg_refs));
}

/// A3: record `let V = CALL(..)` (or `.await?` / `?` / reference
/// chains wrapping such a call) where `CALL` matches a configured
/// login-guard or authorization-check name. `V` is then treated as the
/// authenticated actor — `V.id`-shaped subjects are actor context and
/// shouldn't be flagged as foreign scoped IDs.
fn collect_self_actor_binding(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    if value_is_self_actor_call(value, bytes, rules) {
        state.self_actor_vars.insert(var_name);
    }
}

/// Does `node` (possibly wrapped in `?`/`.await`/`&`) resolve to a
/// call whose callee matches `is_login_guard` or
/// `is_authorization_check`? Used to detect `let user =
/// auth::require_auth(..).await?`-style bindings.
fn value_is_self_actor_call(node: Node<'_>, bytes: &[u8], rules: &AuthAnalysisRules) -> bool {
    match node.kind() {
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let callee = call_name(node, bytes);
            !callee.is_empty()
                && (rules.is_login_guard(&callee) || rules.is_authorization_check(&callee))
        }
        "try_expression" | "await_expression" | "reference_expression"
        | "parenthesized_expression" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if value_is_self_actor_call(child, bytes, rules) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// A3: typed route-handler parameters whose declared type names the
/// authenticated user (e.g. `user: CurrentUser`, `admin: AdminUser`)
/// count as self-actor bindings. Recognized type last-segments:
/// `CurrentUser`, `SessionUser`, `AuthUser`, `AdminUser`,
/// `AuthenticatedUser`, `RequireAuth`, `RequireLogin`, `Authenticated`.
fn collect_typed_extractor_self_actor(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    let Some(ty_node) = node.child_by_field_name("type") else {
        return;
    };
    let ty_text = text(ty_node, bytes);
    if is_self_actor_type_text(&ty_text) {
        state.self_actor_vars.insert(var_name);
    }
}

fn is_self_actor_type_text(ty: &str) -> bool {
    let trimmed = ty
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    let after_colons = trimmed.rsplit("::").next().unwrap_or(trimmed);
    let base = after_colons.split('<').next().unwrap_or(after_colons).trim();
    matches!(
        base,
        "CurrentUser"
            | "SessionUser"
            | "AuthUser"
            | "AdminUser"
            | "AuthenticatedUser"
            | "RequireAuth"
            | "RequireLogin"
            | "Authenticated"
    )
}

/// Extract a single-segment receiver name for a value node of the shape
/// `ROW.method(..)` or `ROW.field`. Returns `None` when the receiver
/// isn't a simple identifier (e.g. deeper chains like `ctx.db.get(..)`).
fn extract_row_receiver_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let node = unwrap_try_like(node);
    match node.kind() {
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let function = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("method"));
            let function = function?;
            single_ident_receiver(function, bytes)
                .or_else(|| single_ident_from_call_receiver(node, bytes))
        }
        "field_expression" | "member_expression" | "attribute" | "selector_expression"
        | "field_access" => single_ident_receiver(node, bytes),
        _ => None,
    }
}

fn single_ident_receiver(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let object = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| node.child_by_field_name("receiver"))?;
    single_ident_text(object, bytes)
}

fn single_ident_from_call_receiver(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let receiver = node
        .child_by_field_name("receiver")
        .or_else(|| node.child_by_field_name("object"))?;
    single_ident_text(receiver, bytes)
}

fn single_ident_text(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier" | "field_identifier"
    ) {
        let value = text(node, bytes);
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    } else {
        None
    }
}

/// Strip `?` / `.await` / `&` / `&mut` wrappers from a value node,
/// returning the underlying call/field expression when present.
fn unwrap_try_like(node: Node<'_>) -> Node<'_> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "try_expression" | "await_expression" | "reference_expression"
            | "parenthesized_expression" => {
                let Some(inner) = cur
                    .child_by_field_name("expression")
                    .or_else(|| cur.named_child(0))
                else {
                    return cur;
                };
                cur = inner;
            }
            _ => return cur,
        }
    }
}

/// Detect the `if OWNER != SELF { return ... }` (or `==` with `else`
/// early-exit) row-level ownership-equality pattern and emit a
/// synthetic `AuthCheck { kind: Ownership }`.  The AuthCheck is
/// back-dated to the row's `let` line — and populated with the row's
/// original fetch arguments as subjects — so the row-fetching call
/// (e.g. `db.query_one(.., &[doc_id])`) is also covered.
fn detect_ownership_equality_check(if_node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    let Some(condition_raw) = if_node.child_by_field_name("condition") else {
        return;
    };
    let Some(consequence) = if_node.child_by_field_name("consequence") else {
        return;
    };
    let alternative = if_node.child_by_field_name("alternative");
    let condition = unwrap_parens_local(condition_raw);
    if condition.kind() != "binary_expression" {
        return;
    }
    let Some(operator) = binary_operator_text(condition, bytes) else {
        return;
    };
    let is_ne = matches!(operator.as_str(), "!=" | "ne");
    let is_eq = matches!(operator.as_str(), "==" | "eq");
    if !is_ne && !is_eq {
        return;
    }
    let Some((left, right)) = binary_operands(condition) else {
        return;
    };

    let fail_branch = if is_ne {
        consequence
    } else if let Some(alt) = alternative {
        resolve_else_block(alt)
    } else {
        return;
    };

    if !branch_has_early_exit(fail_branch) {
        return;
    }

    let left_refs = extract_value_refs(left, bytes);
    let right_refs = extract_value_refs(right, bytes);

    let (owner_ref, _self_ref) = match (
        pick_owner_field_ref(&left_refs),
        pick_self_actor_ref(&right_refs),
    ) {
        (Some(o), Some(s)) => (o, s),
        _ => match (
            pick_owner_field_ref(&right_refs),
            pick_self_actor_ref(&left_refs),
        ) {
            (Some(o), Some(s)) => (o, s),
            _ => return,
        },
    };

    let row_binding = state.row_field_vars.get(&owner_ref.name).cloned();
    let if_line = if_node.start_position().row + 1;
    let if_span = span(if_node);
    let condition_text = text(condition, bytes);

    let (check_line, mut subjects) = match row_binding
        .as_ref()
        .and_then(|row| state.row_population_data.get(row).map(|v| (row, v)))
    {
        Some((row, (row_line, arg_refs))) => {
            let mut subjects = arg_refs.clone();
            subjects.push(ValueRef {
                source_kind: ValueSourceKind::Identifier,
                name: row.clone(),
                base: None,
                field: None,
                index: None,
                span: if_span,
            });
            (*row_line, subjects)
        }
        None => match row_binding.as_ref() {
            Some(row) => (
                if_line,
                vec![ValueRef {
                    source_kind: ValueSourceKind::Identifier,
                    name: row.clone(),
                    base: None,
                    field: None,
                    index: None,
                    span: if_span,
                }],
            ),
            None => (if_line, Vec::new()),
        },
    };
    subjects.push(owner_ref);

    state.auth_checks.push(AuthCheck {
        kind: AuthCheckKind::Ownership,
        callee: "(row ownership equality)".into(),
        subjects,
        span: if_span,
        line: check_line,
        args: Vec::new(),
        condition_text: Some(condition_text),
    });
}

fn unwrap_parens_local(node: Node<'_>) -> Node<'_> {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return unwrap_parens_local(inner);
        }
    }
    node
}

fn binary_operator_text(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if let Some(op) = node.child_by_field_name("operator") {
        let value = text(op, bytes);
        if !value.is_empty() {
            return Some(value);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            let value = text(child, bytes);
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn binary_operands<'tree>(node: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    if let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        return Some((left, right));
    }
    let children = named_children(node);
    match children.as_slice() {
        [left, right] => Some((*left, *right)),
        _ => None,
    }
}

fn resolve_else_block(alt: Node<'_>) -> Node<'_> {
    // Rust wraps the else branch in an `else_clause` with the block
    // as a named child. Other grammars differ, so we walk defensively.
    if alt.kind() == "else_clause" {
        if let Some(block) = named_children(alt).into_iter().next() {
            return block;
        }
    }
    alt
}

fn branch_has_early_exit(branch: Node<'_>) -> bool {
    named_children(branch)
        .into_iter()
        .any(node_is_early_exit)
}

fn node_is_early_exit(node: Node<'_>) -> bool {
    match node.kind() {
        "return_expression" | "return_statement" => true,
        "expression_statement" => named_children(node).into_iter().any(node_is_early_exit),
        _ => false,
    }
}

pub(super) fn is_owner_field_subject(subject: &ValueRef) -> bool {
    let raw = match subject.source_kind {
        ValueSourceKind::ArrayIndex => subject.base.as_deref().unwrap_or(&subject.name),
        _ => subject
            .field
            .as_deref()
            .or(subject.base.as_deref())
            .unwrap_or(&subject.name),
    };
    let key = canonical_name(raw);
    matches!(
        key.as_str(),
        "userid"
            | "ownerid"
            | "authorid"
            | "createdby"
            | "uploaderid"
            | "updatedby"
            | "submittedby"
            | "assignedto"
            | "creatorid"
            | "postedby"
    )
}

pub(super) fn is_self_actor_subject(subject: &ValueRef) -> bool {
    // `req.user.id`, `session.user.id`, `ctx.session.user.id`, etc.
    if subject.source_kind == ValueSourceKind::Session
        && subject
            .base
            .as_deref()
            .is_some_and(is_self_session_base_local)
    {
        return true;
    }
    // Plain member chains that name the caller directly: `user.id`,
    // `current_user.id`, `actor.id`. A3 widens this set via
    // `self_actor_vars`.
    let Some(field) = subject.field.as_deref() else {
        return false;
    };
    if !field.eq_ignore_ascii_case("id") {
        return false;
    }
    let Some(base) = subject.base.as_deref() else {
        return false;
    };
    let last = base.rsplit('.').next().unwrap_or(base);
    matches!(
        last,
        "user" | "current_user" | "currentUser" | "actor" | "current_actor"
    )
}

fn is_self_session_base_local(base: &str) -> bool {
    matches!(
        base,
        "req.session.user"
            | "request.session.user"
            | "session.user"
            | "req.session.currentUser"
            | "request.session.currentUser"
            | "session.currentUser"
            | "req.user"
            | "request.user"
            | "req.currentUser"
            | "request.currentUser"
            | "ctx.session.user"
            | "ctx.session.currentUser"
            | "ctx.state.user"
            | "ctx.state.currentUser"
    )
}

fn pick_owner_field_ref(refs: &[ValueRef]) -> Option<ValueRef> {
    refs.iter().find(|v| is_owner_field_subject(v)).cloned()
}

fn pick_self_actor_ref(refs: &[ValueRef]) -> Option<ValueRef> {
    refs.iter().find(|v| is_self_actor_subject(v)).cloned()
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
        || matches_name(callee, "check_membership")
        || matches_name(callee, "has_membership")
        || matches_name(callee, "has_membership?")
        || matches_name(callee, "require_membership")
        || matches_name(callee, "ensure_membership")
        || matches_name(callee, "member_of?")
        || matches_name(callee, "member?")
    {
        AuthCheckKind::Membership
    } else if matches_name(callee, "checkOwnership")
        || matches_name(callee, "isOwner")
        || matches_name(callee, "requireOwnership")
        || matches_name(callee, "check_ownership")
        || matches_name(callee, "has_ownership")
        || matches_name(callee, "require_ownership")
        || matches_name(callee, "ensure_ownership")
        || matches_name(callee, "is_owner")
        || matches_name(callee, "owner?")
        || matches_name(callee, "owns?")
    {
        AuthCheckKind::Ownership
    } else {
        AuthCheckKind::Other
    }
}

pub fn function_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    function_definition_node(node)
        .child_by_field_name("name")
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
        "default_parameter" | "typed_parameter" | "typed_default_parameter" => {
            if let Some(name) = node.child_by_field_name("name") {
                collect_param_names(name, bytes, out);
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
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "function_definition"
            | "method_declaration"
            | "function_item"
            | "closure_expression"
            | "func_literal"
            | "decorated_definition"
            | "method"
            | "singleton_method"
            | "block"
            | "do_block"
    )
}

pub fn is_handler_reference(node: Node<'_>) -> bool {
    is_function_like(node)
        || matches!(
            node.kind(),
            "identifier"
                | "member_expression"
                | "attribute"
                | "selector_expression"
                | "field_expression"
                | "scoped_identifier"
                | "field_access"
                | "constant"
                | "scope_resolution"
        )
}

pub fn call_site_from_node(node: Node<'_>, bytes: &[u8]) -> CallSite {
    if matches!(
        node.kind(),
        "call_expression" | "call" | "method_invocation" | "method_call_expression"
    ) {
        let name = call_name(node, bytes);
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
    if matches!(node.kind(), "array" | "list" | "tuple") {
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

pub fn auth_check_from_call_site(
    call: &CallSite,
    line: usize,
    rules: &AuthAnalysisRules,
) -> Option<AuthCheck> {
    let kind = if rules.is_admin_guard(&call.name, &call.args) {
        AuthCheckKind::AdminGuard
    } else if rules.is_login_guard(&call.name) {
        AuthCheckKind::LoginGuard
    } else if rules.is_authorization_check(&call.name) {
        classify_auth_check(&call.name, rules)
    } else {
        return None;
    };

    Some(AuthCheck {
        kind,
        callee: call.name.clone(),
        subjects: Vec::new(),
        span: call.span,
        line,
        args: call.args.clone(),
        condition_text: None,
    })
}

pub fn extract_value_refs(node: Node<'_>, bytes: &[u8]) -> Vec<ValueRef> {
    match node.kind() {
        "member_expression"
        | "attribute"
        | "selector_expression"
        | "field_expression"
        | "field_access" => member_value_ref(node, bytes).into_iter().collect(),
        "subscript_expression" | "subscript" | "element_reference" | "index_expression" => {
            subscript_value_ref(node, bytes).into_iter().collect()
        }
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            call_value_ref(node, bytes)
                .map(|value| vec![value])
                .unwrap_or_else(|| {
                    let mut refs = Vec::new();
                    for idx in 0..node.named_child_count() {
                        let Some(child) = node.named_child(idx as u32) else {
                            continue;
                        };
                        refs.extend(extract_value_refs(child, bytes));
                    }
                    refs
                })
        }
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

fn call_value_ref(node: Node<'_>, bytes: &[u8]) -> Option<ValueRef> {
    let callee = call_name(node, bytes);
    let args = node
        .child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default();
    let chain = member_chain(node, bytes);

    if let Some(value) = accessor_call_value_ref(node, &callee, &chain, &args, bytes) {
        return Some(value);
    }

    if !args.is_empty() {
        return None;
    }
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

    Some(ValueRef {
        source_kind: classify_member_chain(&chain),
        name,
        base,
        field,
        index: None,
        span: span(node),
    })
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
    } else if chain.first().is_some_and(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "invitation" | "token" | "invite"
        )
    }) {
        ValueSourceKind::TokenField
    } else {
        ValueSourceKind::MemberField
    }
}

fn matches_request_param(chain: &[String]) -> bool {
    let lower = lower_segments(chain);
    (lower.first().is_some_and(|segment| segment == "params"))
        || (lower.len() >= 2 && lower[0] == "self" && lower[1] == "params")
        || (lower.len() >= 3
            && matches!(lower[0].as_str(), "req" | "request")
            && lower[1] == "params")
        || (lower.len() >= 3 && lower[0] == "ctx" && lower[1] == "params")
}

fn matches_request_body(chain: &[String]) -> bool {
    let lower = lower_segments(chain);
    (lower.len() >= 3 && matches!(lower[0].as_str(), "req" | "request") && lower[1] == "body")
        || (lower.len() >= 3
            && matches!(lower[0].as_str(), "req" | "request")
            && matches!(
                lower[1].as_str(),
                "form" | "json" | "values" | "post" | "data"
            ))
        || (lower.len() >= 4 && lower[0] == "ctx" && lower[1] == "request" && lower[2] == "body")
        || (lower.len() >= 3 && lower[0] == "ctx" && lower[1] == "body")
}

fn matches_request_query(chain: &[String]) -> bool {
    let lower = lower_segments(chain);
    (lower.len() >= 3 && matches!(lower[0].as_str(), "req" | "request") && lower[1] == "query")
        || (lower.len() >= 3
            && matches!(lower[0].as_str(), "req" | "request")
            && matches!(lower[1].as_str(), "args" | "get"))
        || (lower.len() >= 3 && lower[0] == "ctx" && lower[1] == "query")
        || (lower.len() >= 4 && lower[0] == "ctx" && lower[1] == "request" && lower[2] == "query")
}

fn matches_session_context(chain: &[String]) -> bool {
    let lower = lower_segments(chain);
    (lower.first().is_some_and(|segment| {
        matches!(
            segment.as_str(),
            "session"
                | "current_user"
                | "current_account"
                | "current_member"
                | "securitycontext"
                | "principal"
                | "authentication"
        )
    })) || (lower.len() >= 2
        && matches!(lower[0].as_str(), "req" | "request")
        && matches!(lower[1].as_str(), "session" | "user" | "currentuser"))
        || (lower.len() >= 3
            && lower[0] == "self"
            && matches!(lower[1].as_str(), "request" | "session" | "current_user")
            && matches!(lower[2].as_str(), "session" | "user" | "currentuser"))
        || (lower.len() >= 3
            && lower[0] == "ctx"
            && matches!(lower[1].as_str(), "session" | "state"))
}

fn subscript_value_ref(node: Node<'_>, bytes: &[u8]) -> Option<ValueRef> {
    let object = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("operand"));
    let index = node
        .child_by_field_name("index")
        .or_else(|| node.child_by_field_name("subscript"));
    let (object, index) = if let (Some(object), Some(index)) = (object, index) {
        (object, index)
    } else {
        let children = named_children(node);
        match children.as_slice() {
            [object, index, ..] => (*object, *index),
            _ => return None,
        }
    };
    let base_chain = member_chain(object, bytes);
    let base = if base_chain.is_empty() {
        text(object, bytes)
    } else {
        base_chain.join(".")
    };
    let index_text = text(index, bytes);
    let field = Some(strip_quotes(&index_text));
    let source_kind = if base_chain.is_empty() {
        ValueSourceKind::ArrayIndex
    } else {
        match classify_member_chain(&base_chain) {
            ValueSourceKind::MemberField => ValueSourceKind::ArrayIndex,
            other => other,
        }
    };

    Some(ValueRef {
        source_kind,
        name: if source_kind == ValueSourceKind::ArrayIndex {
            format!("{base}[{index_text}]")
        } else {
            format!("{base}.{}", strip_quotes(&index_text))
        },
        base: Some(base),
        field,
        index: Some(index_text),
        span: span(node),
    })
}

pub fn member_chain(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    if node.kind() == "call" {
        let mut chain = if let Some(receiver) = node.child_by_field_name("receiver") {
            member_chain(receiver, bytes)
        } else {
            Vec::new()
        };
        let method = node
            .child_by_field_name("method")
            .or_else(|| node.child_by_field_name("name"))
            .map(|method| text(method, bytes))
            .unwrap_or_default();
        if !method.is_empty() {
            chain.push(method);
        }
        return chain;
    }

    if node.kind() == "method_invocation" || node.kind() == "method_call_expression" {
        let mut chain = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("receiver"))
            .map(|object| member_chain(object, bytes))
            .unwrap_or_default();
        let method = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("method"))
            .map(|method| text(method, bytes))
            .unwrap_or_default();
        if !method.is_empty() {
            chain.push(method);
        }
        return chain;
    }

    if node.kind() == "scope_resolution" {
        let mut chain = Vec::new();
        if let Some(scope) = node.child_by_field_name("scope") {
            chain.extend(member_chain(scope, bytes));
        }
        if let Some(name) = node.child_by_field_name("name") {
            let value = text(name, bytes);
            if !value.is_empty() {
                chain.push(value);
            }
        }
        return chain;
    }

    if node.kind() == "scoped_identifier" {
        let mut chain = Vec::new();
        if let Some(path) = node.child_by_field_name("path") {
            chain.extend(member_chain(path, bytes));
        }
        if let Some(name) = node.child_by_field_name("name") {
            let value = text(name, bytes);
            if !value.is_empty() {
                chain.push(value);
            }
        }
        return chain;
    }

    if !matches!(
        node.kind(),
        "member_expression"
            | "attribute"
            | "selector_expression"
            | "field_expression"
            | "field_access"
    ) {
        let value = text(node, bytes);
        return if value.is_empty() {
            Vec::new()
        } else {
            vec![value]
        };
    }

    let mut chain = Vec::new();
    if let Some(object) = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| node.child_by_field_name("argument"))
    {
        chain.extend(member_chain(object, bytes));
    }
    if let Some(property) = node
        .child_by_field_name("property")
        .or_else(|| node.child_by_field_name("attribute"))
        .or_else(|| node.child_by_field_name("field"))
        .or_else(|| node.child_by_field_name("name"))
    {
        let property_text = text(property, bytes);
        if !property_text.is_empty() {
            chain.push(property_text);
        }
    }
    chain
}

pub fn callee_name(node: Node<'_>, bytes: &[u8]) -> String {
    match node.kind() {
        "identifier" | "property_identifier" | "constant" | "field_identifier" => text(node, bytes),
        "member_expression"
        | "attribute"
        | "selector_expression"
        | "field_expression"
        | "scoped_identifier"
        | "field_access"
        | "scope_resolution"
        | "call"
        | "method_invocation"
        | "method_call_expression" => member_chain(node, bytes).join("."),
        _ => text(node, bytes),
    }
}

pub fn call_name(node: Node<'_>, bytes: &[u8]) -> String {
    if !matches!(
        node.kind(),
        "call_expression" | "call" | "method_invocation" | "method_call_expression"
    ) {
        return callee_name(node, bytes);
    }

    if let Some(function) = node.child_by_field_name("function") {
        return callee_name(function, bytes);
    }

    let method = node
        .child_by_field_name("method")
        .or_else(|| node.child_by_field_name("name"))
        .map(|child| text(child, bytes))
        .unwrap_or_default();
    let receiver = node
        .child_by_field_name("receiver")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("scope"))
        .or_else(|| node.child_by_field_name("argument"))
        .map(|child| member_chain(child, bytes).join("."))
        .filter(|value| !value.is_empty());

    match (receiver, method.is_empty()) {
        (Some(receiver), false) => format!("{receiver}.{method}"),
        (_, false) => method,
        _ => text(node, bytes),
    }
}

pub fn member_target(node: Node<'_>, bytes: &[u8]) -> Option<(String, String)> {
    let object = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("receiver"))
        .or_else(|| node.child_by_field_name("argument"))?;
    let property = node
        .child_by_field_name("property")
        .or_else(|| node.child_by_field_name("field"))
        .or_else(|| node.child_by_field_name("attribute"))
        .or_else(|| node.child_by_field_name("name"))?;
    Some((text(object, bytes), text(property, bytes)))
}

pub fn http_method_from_name(name: &str) -> Option<HttpMethod> {
    match name.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        "all" | "any" => Some(HttpMethod::All),
        "use" => Some(HttpMethod::Use),
        _ => None,
    }
}

pub fn join_route_paths(prefix: &str, route: &str) -> String {
    match (prefix.trim_end_matches('/'), route.trim_start_matches('/')) {
        ("", "") => "/".to_string(),
        ("", route) => format!("/{route}"),
        (prefix, "") => prefix.to_string(),
        (prefix, route) => format!("{prefix}/{route}"),
    }
}

fn call_receiver_subjects(node: Node<'_>, bytes: &[u8]) -> Vec<ValueRef> {
    let mut subjects = Vec::new();
    if let Some(receiver) = node
        .child_by_field_name("receiver")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("argument"))
        .or_else(|| {
            node.child_by_field_name("function").and_then(|function| {
                function
                    .child_by_field_name("object")
                    .or_else(|| function.child_by_field_name("operand"))
                    .or_else(|| function.child_by_field_name("argument"))
            })
        })
    {
        subjects.extend(extract_value_refs(receiver, bytes));
    }
    subjects
}

pub fn string_literal_value(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "string"
        | "template_string"
        | "string_literal"
        | "interpreted_string_literal"
        | "raw_string_literal" => Some(strip_quotes(&text(node, bytes))),
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

pub fn decorated_definition_child(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("definition")
}

pub fn function_definition_node(node: Node<'_>) -> Node<'_> {
    decorated_definition_child(node).unwrap_or(node)
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

fn lower_segments(chain: &[String]) -> Vec<String> {
    chain
        .iter()
        .map(|segment| segment.to_ascii_lowercase())
        .collect()
}

fn accessor_call_value_ref(
    node: Node<'_>,
    callee: &str,
    chain: &[String],
    args: &[Node<'_>],
    bytes: &[u8],
) -> Option<ValueRef> {
    let method = callee.rsplit('.').next().unwrap_or(callee);
    let field = args
        .first()
        .and_then(|arg| string_literal_value(*arg, bytes));
    let source_kind = match method {
        "Param" | "PathParam" => Some(ValueSourceKind::RequestParam),
        "Query" | "QueryParam" | "DefaultQuery" | "getParameter" | "getQueryString" => {
            Some(ValueSourceKind::RequestQuery)
        }
        "PostForm" | "FormValue" | "DefaultPostForm" => Some(ValueSourceKind::RequestBody),
        "Get" | "GetString" | "MustGet" | "getAttribute" => Some(ValueSourceKind::Session),
        _ if chain.first().is_some_and(|segment| {
            matches!(
                segment.to_ascii_lowercase().as_str(),
                "invitation" | "token" | "invite"
            )
        }) && method.starts_with("get")
            && method.len() > 3 =>
        {
            Some(ValueSourceKind::TokenField)
        }
        _ => None,
    }?;

    let normalized_field = field
        .or_else(|| {
            if source_kind == ValueSourceKind::TokenField && method.starts_with("get") {
                Some(method[3..].to_string())
            } else {
                None
            }
        })
        .map(|field| {
            let mut chars = field.chars();
            let Some(first) = chars.next() else {
                return field;
            };
            format!("{}{}", first.to_ascii_lowercase(), chars.as_str())
        })
        .filter(|field| !field.is_empty());

    let base = match source_kind {
        ValueSourceKind::Session => Some("session".to_string()),
        _ if chain.len() > 1 => Some(chain[..chain.len() - 1].join(".")),
        _ => chain.first().cloned(),
    };

    let name = if let Some(field) = normalized_field.as_deref() {
        match base.as_deref() {
            Some(base) if !base.is_empty() => format!("{base}.{field}"),
            _ => field.to_string(),
        }
    } else {
        callee.to_string()
    };

    Some(ValueRef {
        source_kind,
        name,
        base,
        field: normalized_field,
        index: None,
        span: span(node),
    })
}

#[cfg(test)]
mod tests {
    use super::{is_owner_field_subject, is_self_actor_subject, is_self_actor_type_text};
    use crate::auth_analysis::model::{ValueRef, ValueSourceKind};

    #[test]
    fn is_self_actor_type_text_matches_known_wrappers() {
        assert!(is_self_actor_type_text("CurrentUser"));
        assert!(is_self_actor_type_text("SessionUser"));
        assert!(is_self_actor_type_text("AuthUser"));
        assert!(is_self_actor_type_text("AdminUser"));
        assert!(is_self_actor_type_text("AuthenticatedUser"));
        assert!(is_self_actor_type_text("RequireAuth"));
        assert!(is_self_actor_type_text("RequireLogin"));
        assert!(is_self_actor_type_text("Authenticated"));
        // Qualified paths resolve to last segment.
        assert!(is_self_actor_type_text("crate::auth::CurrentUser"));
        assert!(is_self_actor_type_text("&CurrentUser"));
        assert!(is_self_actor_type_text("&mut AuthUser"));
        // Generic wrappers: match on the base segment.
        assert!(is_self_actor_type_text("CurrentUser<Admin>"));
        // Non-matches.
        assert!(!is_self_actor_type_text("Db"));
        assert!(!is_self_actor_type_text("Path<(i64,)>"));
        assert!(!is_self_actor_type_text("User"));
        assert!(!is_self_actor_type_text("Json<Body>"));
    }

    fn ident(name: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::Identifier,
            name: name.to_string(),
            base: None,
            field: None,
            index: None,
            span: (0, 0),
        }
    }

    fn member(base: &str, field: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::MemberField,
            name: format!("{base}.{field}"),
            base: Some(base.to_string()),
            field: Some(field.to_string()),
            index: None,
            span: (0, 0),
        }
    }

    fn session(base: &str, field: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::Session,
            name: format!("{base}.{field}"),
            base: Some(base.to_string()),
            field: Some(field.to_string()),
            index: None,
            span: (0, 0),
        }
    }

    #[test]
    fn is_owner_field_subject_matches_known_column_names() {
        assert!(is_owner_field_subject(&ident("owner_id")));
        assert!(is_owner_field_subject(&ident("user_id")));
        assert!(is_owner_field_subject(&ident("author_id")));
        assert!(is_owner_field_subject(&ident("created_by")));
        assert!(is_owner_field_subject(&member("row", "owner_id")));
        assert!(!is_owner_field_subject(&ident("group_id")));
        assert!(!is_owner_field_subject(&ident("doc_id")));
        assert!(!is_owner_field_subject(&ident("user")));
    }

    #[test]
    fn is_self_actor_subject_matches_known_self_shapes() {
        assert!(is_self_actor_subject(&member("user", "id")));
        assert!(is_self_actor_subject(&member("current_user", "id")));
        assert!(is_self_actor_subject(&session("req.user", "id")));
        assert!(is_self_actor_subject(&session("ctx.session.user", "id")));
        // Wrong field.
        assert!(!is_self_actor_subject(&member("user", "workspace_id")));
        // Unknown base.
        assert!(!is_self_actor_subject(&member("target", "id")));
        // Plain identifier, no base.
        assert!(!is_self_actor_subject(&ident("user_id")));
    }
}
