use crate::auth_analysis::config::{AuthAnalysisRules, canonical_name, matches_name, strip_quotes};
use crate::auth_analysis::model::{
    AnalysisUnit, AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel, CallSite,
    Framework, HttpMethod, OperationKind, RouteRegistration, SensitiveOperation, SinkClass,
    ValueRef, ValueSourceKind,
};
use crate::labels::bare_method_name;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tree_sitter::Node;

pub fn collect_top_level_units(
    root: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let file_meta = FileMeta::scan(root, bytes);
    for idx in 0..root.named_child_count() {
        let Some(child) = root.named_child(idx as u32) else {
            continue;
        };
        collect_top_level_from_node(child, bytes, rules, model, &file_meta);
    }
}

fn collect_top_level_from_node(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
    file_meta: &FileMeta,
) {
    match node.kind() {
        "function_declaration"
        | "function_definition"
        | "method_declaration"
        | "function_item"
        | "method"
        | "singleton_method" => {
            model.units.push(build_function_unit_with_meta(
                node,
                AnalysisUnitKind::Function,
                function_name(node, bytes),
                bytes,
                rules,
                Some(file_meta),
            ));
        }
        "decorated_definition"
            if decorated_definition_child(node)
                .is_some_and(|definition| definition.kind() == "function_definition") =>
        {
            model.units.push(build_function_unit_with_meta(
                node,
                AnalysisUnitKind::Function,
                function_name(node, bytes),
                bytes,
                rules,
                Some(file_meta),
            ));
        }
        "lexical_declaration" | "variable_declaration" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if child.kind() == "variable_declarator"
                    && let Some(unit) =
                        function_unit_from_var_declarator(child, bytes, rules, Some(file_meta))
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
                    collect_top_level_from_node(child, bytes, rules, model, file_meta);
                }
            }
        }
        "program" | "source_file" | "module" | "class" | "class_declaration" | "class_body"
        | "body_statement" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                collect_top_level_from_node(child, bytes, rules, model, file_meta);
            }
        }
        _ => {}
    }
}

fn function_unit_from_var_declarator(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    file_meta: Option<&FileMeta>,
) -> Option<AnalysisUnit> {
    let value = node.child_by_field_name("value")?;
    if !is_function_like(value) {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| text(n, bytes))
        .filter(|s| !s.is_empty());
    Some(build_function_unit_with_meta(
        value,
        AnalysisUnitKind::Function,
        name,
        bytes,
        rules,
        file_meta,
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
    // `attach_route_handler` is called by route-aware extractors (express,
    // koa, fastify, axum, …) which already hold the file root.  Build
    // the FileMeta once here so the JS/TS TRPC pre-scan only walks the
    // top-level decl set per file (instead of per route).
    let file_meta = FileMeta::scan(root, bytes);
    let unit = build_function_unit_with_meta(
        handler_node,
        AnalysisUnitKind::RouteHandler,
        Some(route_name),
        bytes,
        rules,
        Some(&file_meta),
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

/// Per-file metadata gathered once at the top of
/// [`collect_top_level_units`] / [`attach_route_handler`] and passed
/// down through unit construction.  Currently carries the set of TS
/// type-alias names whose body references a TRPC-marker type; future
/// fields can be added without changing the per-unit signature.
#[derive(Default, Debug, Clone)]
pub struct FileMeta {
    pub trpc_alias_names: HashSet<String>,
}

impl FileMeta {
    pub fn scan(root: Node<'_>, bytes: &[u8]) -> Self {
        let mut trpc_alias_names = HashSet::new();
        scan_trpc_aliases_visit(root, bytes, &mut trpc_alias_names);
        Self { trpc_alias_names }
    }
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
    build_function_unit_with_meta(node, kind, name, bytes, rules, None)
}

/// Internal variant of [`build_function_unit`] that accepts a
/// pre-computed file-level [`FileMeta`].  When `file_meta` is
/// `Some`, its `trpc_alias_names` set is copied into `UnitState`
/// once per unit so the per-parameter pre-pass doesn't re-scan the
/// source-file root.  Pre-built `FileMeta` is required to keep
/// `tests/hostile_input_tests::many_small_functions_do_not_explode`
/// inside its 15s budget on N×N files.
pub fn build_function_unit_with_meta(
    node: Node<'_>,
    kind: AnalysisUnitKind,
    name: Option<String>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    file_meta: Option<&FileMeta>,
) -> AnalysisUnit {
    let definition = function_definition_node(node);
    let params = function_params(definition, bytes);
    let line = node.start_position().row + 1;
    let mut state = UnitState::default();
    // Seed Go's method-receiver name (`func (c *Cache) ...` → `c`) into
    // `non_sink_vars` so calls of the form `c.foo(..)` /
    // `c.field.foo(..)` route through the in-memory-local sink class
    // and skip the verb-name fallback.  These are intra-struct
    // dispatches; without type tracking, the auth analyser cannot tell
    // a `*Cache` field-call from a `*sql.DB` call by name alone, so we
    // err on the safe side per the deferred memo
    // (`project_realrepo_hugo.md`).  Only Go's `method_declaration`
    // exposes a `receiver` field — Rust/Java instance methods route
    // through `self`/`this` keywords and are unaffected.
    if let Some(receiver_name) = method_receiver_name(definition, bytes) {
        state.non_sink_vars.insert(receiver_name);
    }
    if let Some(meta) = file_meta {
        state.trpc_alias_names = meta.trpc_alias_names.clone();
    }
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
        var_alias_chain: state.var_alias_chain,
        row_population_data: state.row_population_data,
        self_actor_vars: state.self_actor_vars,
        self_actor_id_vars: state.self_actor_id_vars,
        authorized_sql_vars: state.authorized_sql_vars,
        const_bound_vars: state.const_bound_vars,
        typed_bounded_vars: HashSet::new(),
        typed_bounded_dto_fields: std::collections::HashMap::new(),
        self_scoped_session_bases: state.self_scoped_session_bases,
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
    /// Full chain text for `let X = BASE.FIELD` shapes (or
    /// transitively through method calls / try / await wrappers when
    /// the value resolves to a member access). Stored alongside
    /// `row_field_vars` so the row-population reverse-walk can match
    /// plain-identifier sink subjects against population args by
    /// their original chain text. See
    /// [`crate::auth_analysis::model::AnalysisUnit::var_alias_chain`].
    var_alias_chain: HashMap<String, String>,
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
    /// Transitive copies of the authenticated actor's id field
    /// (`let X = V.id` / `let X = (V.id as ..).into()` /
    /// `let X = V.user_id` / `V.uid`).  Populated by
    /// `collect_self_actor_id_binding`.  Copied onto
    /// `AnalysisUnit.self_actor_id_vars` so subjects whose name appears
    /// here count as actor context — closes the FP where a route
    /// handler does `let uid = user.id; query_all(.., &[uid])` and the
    /// engine sees `uid` only as a plain scoped id.
    self_actor_id_vars: HashSet<String>,
    /// B3: local variables bound (directly or transitively) to a
    /// SQL query whose literal text is auth-gated.  Populated by
    /// `collect_sql_authorized_binding` and the `for ROW in X` /
    /// `let Y = ROW.method(..)` propagation paths inside
    /// `collect_row_field_binding` and `collect_for_row_binding`.
    authorized_sql_vars: HashSet<String>,
    /// Local variables whose declaration binds them to a string,
    /// numeric, or boolean literal — `id := "id"` / `let id = "1"` /
    /// `String id = "id";`.  These cannot be user-controlled and so
    /// must not be treated as scoped-identifier subjects by
    /// `is_relevant_target_subject`.  Closes the gin/context_test.go
    /// FP where `id := "id"; c.AddParam(id, value)` triggered
    /// `go.auth.missing_ownership_check` because the local `id`
    /// matched `is_id_like` but had no actor-context exemption.
    const_bound_vars: HashSet<String>,
    /// Dynamic per-unit session-base set lifted into the
    /// `AnalysisUnit` of the same name.  Populated by
    /// [`collect_trpc_ctx_param`] when a TS parameter's type
    /// references a TRPC-shaped Options alias.  See the field doc on
    /// [`crate::auth_analysis::model::AnalysisUnit::self_scoped_session_bases`].
    self_scoped_session_bases: HashSet<String>,
    /// File-level set of TS type-alias names whose body references a
    /// TRPC-marker type (`TrpcSessionUser` etc.).  Populated once per
    /// unit at the top of [`build_function_unit`] by walking up to
    /// the source-file root and scanning every
    /// `type_alias_declaration` / `interface_declaration`.  Read by
    /// [`collect_trpc_ctx_param`] to decide whether a parameter's
    /// type annotation (often just an alias name like `GetOptions`)
    /// resolves to a TRPC handler signature.  Empty for non-TS
    /// languages — the scanner only matches TS-grammar node kinds.
    trpc_alias_names: HashSet<String>,
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
            collect_member_alias_binding(node, bytes, state);
            collect_row_population(node, bytes, state);
            collect_self_actor_binding(node, bytes, rules, state);
            collect_self_actor_id_binding(node, bytes, state);
            collect_sql_authorized_binding(node, bytes, rules, state);
            propagate_sql_authorized_through_field_read(node, bytes, state);
            collect_const_string_binding(node, bytes, state);
        }
        // JS/TS `variable_declarator` inside `lexical_declaration`
        // (`const X = ...`, `let X = ...`) — exposes `name` + `value`
        // fields. Run the same self-actor / self-actor-id binding
        // recognition as the Rust `let_declaration` arm above so the
        // session-self-actor copy chain (`const session = await
        // getServerSession(...)`; `const userId = session.user.id`)
        // populates `self_actor_vars` / `self_actor_id_vars`.
        "variable_declarator" => {
            collect_self_actor_binding(node, bytes, rules, state);
            collect_self_actor_id_binding(node, bytes, state);
            collect_const_string_binding(node, bytes, state);
        }
        // Go `id := "id"` / Python `id = "id"` / Java `String id = "id";` /
        // Ruby `id = "id"` — language-specific binding nodes that the
        // let_declaration arm above doesn't catch.  Const-only — never
        // marks self_actor / row_field / sql vars (those need richer
        // right-hand-side analysis already provided by the
        // let_declaration arm).
        "short_var_declaration"
        | "const_declaration"
        | "var_declaration"
        | "var_spec"
        | "lexical_declaration"
        | "local_variable_declaration"
        | "assignment"
        | "assignment_expression"
        | "augmented_assignment"
        | "expression_statement" => {
            collect_const_string_binding(node, bytes, state);
            // Ruby `@issue = Issue.find(params[:id])` is the canonical
            // controller idiom: instance-variable assignment whose RHS
            // is a row-fetch call.  The let_declaration arm above
            // doesn't fire for this kind, so register the row
            // population separately.  `collect_row_population` reads
            // either `pattern`/`value` or `left`/`right`, so it works
            // unchanged for Ruby `assignment` once the LHS recognises
            // `instance_variable`.
            if matches!(node.kind(), "assignment" | "assignment_expression") {
                collect_row_population(node, bytes, state);
            }
        }
        "for_expression" => {
            collect_for_row_binding(node, bytes, state);
        }
        "parameter" => {
            collect_typed_extractor_self_actor(node, bytes, state);
        }
        // TS `required_parameter` / `optional_parameter` — the analogous
        // arm to Rust's `parameter`.  Recognise TRPC-shaped Options
        // params (`{ ctx, input }: GetOptions`) and add the destructured
        // ctx-base to `self_scoped_session_bases` so downstream
        // `ctx.user.id` accesses count as actor context.
        "required_parameter" | "optional_parameter" => {
            collect_trpc_ctx_param(node, bytes, state);
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
    let args_value_refs: Vec<Vec<ValueRef>> = args
        .iter()
        .map(|arg| extract_value_refs(*arg, bytes))
        .collect();
    let node_text = text(node, bytes);
    state.call_sites.push(CallSite {
        name: callee.clone(),
        args: string_args.clone(),
        span: span(node),
        args_value_refs,
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

    // Split classification into OperationKind (what verb?) and
    // SinkClass (what resource?).  The sink class drives the
    // ownership gate; OperationKind is kept for partial-batch / stale-
    // session checks that care about read-vs-mutation semantics.
    let (op_kind, sink_class) = if rules.is_token_lookup_call(&callee, &node_text) {
        (Some(OperationKind::TokenLookup), None)
    } else if let Some(class) = rules.classify_sink_class(&callee, &state.non_sink_vars) {
        let op = match class {
            SinkClass::DbCrossTenantRead => OperationKind::Read,
            // InMemoryLocal: keep the verb for telemetry but the
            // ownership gate ignores this class.
            SinkClass::InMemoryLocal => {
                if rules.is_mutation(&callee) {
                    OperationKind::Mutation
                } else {
                    OperationKind::Read
                }
            }
            // Publish / outbound / cache / DB mutation — treat as
            // write-shaped by default unless the callee name is a
            // read verb (e.g. `cache.get(tenant_id)`).
            _ => {
                if rules.is_read(&callee) && !rules.is_mutation(&callee) {
                    OperationKind::Read
                } else {
                    OperationKind::Mutation
                }
            }
        };
        (Some(op), Some(class))
    } else {
        (None, None)
    };

    if let Some(kind) = op_kind {
        state.operations.push(SensitiveOperation {
            kind,
            sink_class,
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
    if matches!(
        node.kind(),
        "identifier"
            | "shorthand_property_identifier_pattern"
            // Ruby `@foo` instance vars and `@@foo` class vars:
            // Rails controllers populate the row via `@issue =
            // Issue.find(...)`, so the row var is the *full* `@issue`
            // text — chain_root in checks.rs strips on `.` only, so an
            // auth check on `@issue.visible?` resolves to root `@issue`,
            // matching the row var.
            | "instance_variable"
            | "class_variable"
            // Ruby globals `$foo` are unusual but match the same
            // handler-state idiom — kept symmetric with @-vars.
            | "global_variable"
    ) {
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

fn value_is_non_sink_constructor(node: Node<'_>, bytes: &[u8], rules: &AuthAnalysisRules) -> bool {
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

/// Track `let X = BASE.FIELD` (or `BASE.FIELD?` / `(BASE.FIELD).await`)
/// so a downstream sink whose subject is the bare identifier `X` can be
/// matched against row-population args that recorded the original
/// chain text.  Distinct from `collect_row_field_binding`, which only
/// records the receiver name (loses the field).
///
/// Only fires when the value resolves to a member-access node and the
/// resulting chain has at least two segments (`req.community_id`,
/// `data.user.id`, …) — single-ident receivers are uninteresting and a
/// chain of length one would just duplicate the binding's own name.
///
/// Defensive: never overwrites an existing entry — first writer wins.
/// Re-binding the same local name (rare in idiomatic Rust) is treated
/// as a separate variable scope; the rest of the analysis already
/// works on the first binding seen during a top-down walk.
fn collect_member_alias_binding(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
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
    let target = unwrap_try_like(value);
    if !matches!(
        target.kind(),
        "member_expression"
            | "attribute"
            | "selector_expression"
            | "field_expression"
            | "field_access"
    ) {
        return;
    }
    let chain = member_chain(target, bytes);
    if chain.len() < 2 {
        return;
    }
    let chain_text = chain.join(".");
    state.var_alias_chain.entry(var_name).or_insert(chain_text);
}

/// Record the line and argument value-refs of a `let ROW = CALL(..)`.
/// When A2 synthesises an `AuthCheck` on `ROW` later, we back-date the
/// check to this line and merge the args into its subjects so the
/// original fetch (e.g. `db.query_one(.., &[doc_id])`) is also covered.
///
/// The recorded line is the **call**'s start line, not the
/// `let_declaration`'s.  These differ for multi-line bindings such as
///
/// ```ignore
/// let orig =                         // let_declaration starts here
///     CommentView::read(&mut pool, comment_id, ..).await?;  // call starts here
/// ```
///
/// `has_row_fetch_exemption` looks for a row var "declared at this
/// op's line", where `op.line` is the call site.  Recording the
/// let-line caused the multi-line shape to fall through the exemption
/// — surfaced on lemmy's `comment/lock.rs:31`, where every fetch-then-
/// check route handler that wraps the read across two lines was
/// flagged despite a textual auth check on the resulting row.
fn collect_row_population(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    // Most languages expose `pattern`/`value` on let / const / var
    // declarations.  Ruby `assignment` uses `left`/`right` instead, so
    // accept either.  When both fields are missing, the node isn't an
    // RHS-bound binding and we skip.
    let Some(pattern) = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("left"))
    else {
        return;
    };
    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    let Some(value) = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))
    else {
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
    let call_line = call_node.start_position().row + 1;
    state
        .row_population_data
        .insert(var_name, (call_line, arg_refs));
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
    // Rust `let_declaration` exposes `pattern`; JS/TS
    // `variable_declarator` exposes `name`. Try both so the same
    // recognition fires across languages.
    let Some(pattern) = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("name"))
    else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };

    // Destructuring: `const { user } = ctx.session;` /
    // `const { user } = await getServerSession();` /
    // `const { id } = req.user;`.  These bind LOCAL variables that are
    // semantically the actor (or the actor's id), and the existing
    // single-ident path can't see them because `first_identifier_name`
    // either picks the wrong key when several are destructured or
    // misses the session-container RHS shape entirely.
    if pattern.kind() == "object_pattern" {
        collect_destructured_self_actor_binding(pattern, value, bytes, rules, state);
        return;
    }

    let Some(var_name) = first_identifier_name(pattern, bytes) else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    if value_is_self_actor_call(value, bytes, rules) {
        state.self_actor_vars.insert(var_name);
    }
}

/// Pattern is `object_pattern` (JS/TS destructure).  Walk the keys and
/// classify the RHS to decide what each destructured local should
/// register as:
///
/// * `const { user } = ctx.session` / `const { user } = await
///   getServerSession()` — RHS is a session container, so a
///   destructured `user` (or `currentUser`) becomes the unit's
///   self-actor binding.
/// * `const { id } = req.user` / `const { userId } = session.user` —
///   RHS is the canonical authed-user base from
///   `is_self_scoped_session_base_text`, so a destructured `id` /
///   `userId` / `user_id` / `uid` becomes a self-actor-id binding.
/// * `const { user } = await loginGuardCall()` — also accepted
///   because `value_is_self_actor_call` already covers the
///   `let user = require_auth(..)` shape; we lift that recognition
///   into the destructure case so callers can extract the actor in a
///   single statement.
///
/// Each `pair_pattern` entry distinguishes the destructured KEY (the
/// shape of the RHS source) from the bound LOCAL (what we add to the
/// state set).  Shorthand patterns reuse the key as the local.
fn collect_destructured_self_actor_binding(
    pattern: Node<'_>,
    value: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    // Two recognition paths run in sequence:
    //   1. Static classify_destructure_rhs: hard-coded session-container
    //      / self-actor-base / self-actor-call shapes.
    //   2. Dynamic self_scoped_session_bases lookup: if the RHS is a
    //      chain (or bare identifier) `<X>` and `<X>.user` was added to
    //      `self_scoped_session_bases` by an earlier TRPC param scan,
    //      the destructured `user` key is the actor.  Closes the
    //      cal.com `({ ctx, input }: Options) => { const { user } = ctx; }`
    //      shape where ctx is the TRPC-typed param.
    let kind = classify_destructure_rhs(value, bytes, rules);
    let trpc_ctx_path = lookup_trpc_ctx_destructure_match(value, bytes, state);

    if kind == DestructureRhsKind::None && trpc_ctx_path.is_none() {
        return;
    }

    for idx in 0..pattern.named_child_count() {
        let Some(child) = pattern.named_child(idx as u32) else {
            continue;
        };
        let (key, local) = match child.kind() {
            // `{ user }` — key and local are the same identifier.
            "shorthand_property_identifier_pattern" => {
                let name = text(child, bytes);
                (name.clone(), name)
            }
            // `{ user = default }` — left is the shorthand key/local.
            "object_assignment_pattern" => {
                let Some(left) = child.child_by_field_name("left") else {
                    continue;
                };
                let name = if matches!(
                    left.kind(),
                    "identifier" | "shorthand_property_identifier_pattern"
                ) {
                    text(left, bytes)
                } else {
                    first_identifier_name(left, bytes).unwrap_or_default()
                };
                (name.clone(), name)
            }
            // `{ user: localName }` — `key` and `value` fields are
            // distinct (key from RHS source, local in our scope).
            "pair_pattern" => {
                let key_node = child.child_by_field_name("key");
                let local_node = child.child_by_field_name("value");
                let (Some(k), Some(v)) = (key_node, local_node) else {
                    continue;
                };
                let key = text(k, bytes);
                let local = first_identifier_name(v, bytes).unwrap_or_default();
                (key, local)
            }
            _ => continue,
        };
        if kind != DestructureRhsKind::None {
            process_destructure_entry(&key, &local, kind, state);
        }
        // Dynamic-set lift: when the RHS resolves to an `<X>` whose
        // `<X>.user` was added to `self_scoped_session_bases`, the
        // destructured `user` key is the actor.  This closes the
        // chained TRPC shape `({ ctx }: Options) => { const { user }
        // = ctx; }` where the param-level pre-pass marked `ctx.user`
        // earlier in the unit.
        if let Some(rhs_path) = trpc_ctx_path.as_deref()
            && key.eq_ignore_ascii_case("user")
            && !local.is_empty()
        {
            let _ = rhs_path; // path itself is not stored; presence is the signal
            state.self_actor_vars.insert(local);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestructureRhsKind {
    /// RHS is a session container — the destructured `user` field
    /// resolves to the authenticated actor.  Examples: `ctx.session`,
    /// `req.session`, `session`, `await getServerSession()`,
    /// `getSession()`.
    SessionContainer,
    /// RHS is the authed-user base itself (`req.user`, `session.user`,
    /// `ctx.session.user`).  A destructured `id` field is the actor's
    /// own id.
    SelfActorBase,
    /// RHS is not a session/actor source — destructure is irrelevant
    /// for self-actor recognition.
    None,
}

/// When the destructure RHS is `<chain>` (an identifier or member
/// chain), return `Some(chain_text)` if `<chain_text>.user` was added
/// to `state.self_scoped_session_bases` by an earlier
/// `collect_trpc_ctx_param` call.  Used to mark the destructured
/// `user` shorthand as a self-actor binding when extracting it from a
/// TRPC ctx param's local — `({ ctx }: Options) => { const { user }
/// = ctx; }`.
fn lookup_trpc_ctx_destructure_match(
    node: Node<'_>,
    bytes: &[u8],
    state: &UnitState,
) -> Option<String> {
    if state.self_scoped_session_bases.is_empty() {
        return None;
    }
    let chain_text = chain_text_from_value(node, bytes)?;
    if chain_text.is_empty() {
        return None;
    }
    let candidate = format!("{chain_text}.user");
    if state.self_scoped_session_bases.contains(&candidate) {
        Some(chain_text)
    } else {
        None
    }
}

/// Reduce an RHS expression to its dotted chain text, walking through
/// `await`/parens/non-null wrappers.  Returns `None` for shapes that
/// aren't a pure identifier/member-chain (e.g. a call result, a
/// template literal, an object-literal expression).
fn chain_text_from_value(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let t = text(node, bytes);
            if t.is_empty() { None } else { Some(t) }
        }
        "field_expression" | "member_expression" | "field_access" | "scoped_identifier" => {
            let chain = member_chain(node, bytes);
            if chain.is_empty() {
                None
            } else {
                Some(chain.join("."))
            }
        }
        "type_cast_expression"
        | "as_expression"
        | "cast_expression"
        | "parenthesized_expression"
        | "non_null_expression"
        | "await_expression"
        | "try_expression" => {
            let inner = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"));
            if let Some(v) = inner
                && let Some(t) = chain_text_from_value(v, bytes)
            {
                return Some(t);
            }
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if let Some(t) = chain_text_from_value(child, bytes) {
                    return Some(t);
                }
            }
            None
        }
        _ => None,
    }
}

fn classify_destructure_rhs(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
) -> DestructureRhsKind {
    if value_is_self_actor_call(node, bytes, rules) {
        return DestructureRhsKind::SessionContainer;
    }
    if value_is_session_provider_chain(node, bytes) {
        return DestructureRhsKind::SessionContainer;
    }
    if value_is_self_actor_base_chain(node, bytes) {
        return DestructureRhsKind::SelfActorBase;
    }
    DestructureRhsKind::None
}

fn process_destructure_entry(
    key: &str,
    local: &str,
    kind: DestructureRhsKind,
    state: &mut UnitState,
) {
    if key.is_empty() || local.is_empty() {
        return;
    }
    let key_lower = key.to_ascii_lowercase();
    match kind {
        DestructureRhsKind::SessionContainer => {
            if matches!(key_lower.as_str(), "user" | "currentuser" | "current_user") {
                state.self_actor_vars.insert(local.to_string());
            }
        }
        DestructureRhsKind::SelfActorBase => {
            if matches!(key_lower.as_str(), "id" | "userid" | "user_id" | "uid") {
                state.self_actor_id_vars.insert(local.to_string());
            }
        }
        DestructureRhsKind::None => {}
    }
}

/// True when `node` (after walking through `await`/parens/non-null
/// wrappers) is a session-container expression — a chain ending in
/// `.session` / `.state.session` / a bare `session` identifier, or a
/// call to a known session-getter (`getServerSession()`,
/// `getSession()`).  Distinct from `value_is_self_actor_call` which
/// matches login-guard / authorization-check callees configured per
/// language.
fn value_is_session_provider_chain(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "field_expression" | "member_expression" | "field_access" | "scoped_identifier" => {
            let chain = member_chain(node, bytes);
            if chain.is_empty() {
                return false;
            }
            let joined = chain.join(".");
            // Bare session containers — `ctx.session`, `req.session`,
            // `request.session`, plus the Koa `ctx.state` shape.
            matches!(
                joined.as_str(),
                "ctx.session" | "ctx.state" | "req.session" | "request.session" | "session"
            )
        }
        "identifier" => {
            let name = text(node, bytes);
            matches!(name.as_str(), "session")
        }
        // Known session-getter calls.  Conservative list — only
        // recogniser shapes that are unambiguously session-providing
        // in the JS/TS ecosystem (NextAuth's `getServerSession` is the
        // dominant one).  `auth()` and `useSession()` are deliberately
        // omitted because their meaning is ambiguous outside of a
        // server-component context and adding them risks
        // over-suppression in non-NextAuth code.
        "call_expression" | "call" => {
            let callee = call_name(node, bytes);
            let last = bare_method_name(&callee);
            matches!(
                last,
                "getServerSession"
                    | "getSession"
                    | "getServerSideSession"
                    | "unstable_getServerSession"
            )
        }
        "type_cast_expression"
        | "as_expression"
        | "cast_expression"
        | "parenthesized_expression"
        | "non_null_expression"
        | "await_expression"
        | "try_expression" => {
            let inner = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"));
            if let Some(v) = inner
                && value_is_session_provider_chain(v, bytes)
            {
                return true;
            }
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if value_is_session_provider_chain(child, bytes) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// True when `node` is the canonical authed-user base from
/// `is_self_scoped_session_base_text` (e.g. `req.user`, `session.user`,
/// `ctx.session.user`).  Used to recognise `const { id } = req.user`
/// so the destructured `id` becomes a self-actor-id.
fn value_is_self_actor_base_chain(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "field_expression" | "member_expression" | "field_access" | "scoped_identifier" => {
            let chain = member_chain(node, bytes);
            if chain.is_empty() {
                return false;
            }
            let joined = chain.join(".");
            is_self_scoped_session_base_text(&joined)
        }
        "type_cast_expression"
        | "as_expression"
        | "cast_expression"
        | "parenthesized_expression"
        | "non_null_expression"
        | "await_expression"
        | "try_expression" => {
            let inner = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"));
            if let Some(v) = inner
                && value_is_self_actor_base_chain(v, bytes)
            {
                return true;
            }
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if value_is_self_actor_base_chain(child, bytes) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Recognise variable bindings whose right-hand side is a literal
/// constant — string, integer, float, or boolean.  A subject backed
/// by a constant binding cannot be user-controlled and so must not
/// trigger `<lang>.auth.missing_ownership_check` even when the
/// variable name happens to match `is_id_like` (e.g.
/// `id := "id"` in a Go test fixture).
///
/// Walks the binding's RHS through common wrappers
/// (`parenthesized_expression`, `type_cast_expression`,
/// reference/borrow expressions) before checking for a leaf literal
/// kind.  Conservative: any non-literal subexpression on the RHS
/// (a call, identifier, field-access) skips the binding — that var
/// might still hold attacker-controlled data.
///
/// Handles the per-language declaration kinds wired in
/// `collect_unit_state`: Go `short_var_declaration` (`x := "foo"`),
/// JS `lexical_declaration` (`const x = "foo"`), Java
/// `local_variable_declaration`, Rust `let_declaration`, and bare
/// `assignment_expression`.
fn collect_const_string_binding(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    // `assignment` / `assignment_expression`: `x = "foo"` — populate
    // the LHS (`name` / `left`) when the RHS is a literal.
    if matches!(
        node.kind(),
        "assignment" | "assignment_expression" | "augmented_assignment"
    ) {
        let lhs = node
            .child_by_field_name("left")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("target"));
        let rhs = node
            .child_by_field_name("right")
            .or_else(|| node.child_by_field_name("value"));
        if let (Some(lhs), Some(rhs)) = (lhs, rhs)
            && rhs_is_pure_literal(rhs)
        {
            for var in collect_lhs_idents(lhs, bytes) {
                state.const_bound_vars.insert(var);
            }
        }
        return;
    }

    // Go `short_var_declaration` / `var_declaration` /
    // `const_declaration`: `id := "id"` or `var id string = "id"`.
    // Tree-sitter-go uses `left:expression_list` and
    // `right:expression_list`.
    if matches!(
        node.kind(),
        "short_var_declaration" | "var_spec" | "const_spec"
    ) {
        let left = node.child_by_field_name("left").or_else(|| {
            // Some tree-sitter grammars expose name(s) instead of left
            node.child_by_field_name("name")
        });
        let right = node.child_by_field_name("right").or_else(|| {
            node.child_by_field_name("value")
                .or_else(|| node.child_by_field_name("default"))
        });
        if let (Some(left), Some(right)) = (left, right) {
            // expression_list parallel — pair LHS idents with RHS exprs.
            let lhs_idents = collect_lhs_idents(left, bytes);
            let rhs_exprs: Vec<Node<'_>> = if right.kind() == "expression_list" {
                let mut cursor = right.walk();
                right
                    .children(&mut cursor)
                    .filter(|c| !matches!(c.kind(), "," | "(" | ")"))
                    .collect()
            } else {
                vec![right]
            };
            for (idx, var) in lhs_idents.into_iter().enumerate() {
                if let Some(expr) = rhs_exprs.get(idx)
                    && rhs_is_pure_literal(*expr)
                {
                    state.const_bound_vars.insert(var);
                }
            }
        }
        return;
    }

    // `var_declaration` / `const_declaration` (Go top-level wrappers
    // around var_spec/const_spec): recurse into children handled above.
    if matches!(node.kind(), "var_declaration" | "const_declaration") {
        for idx in 0..node.named_child_count() {
            if let Some(child) = node.named_child(idx as u32) {
                collect_const_string_binding(child, bytes, state);
            }
        }
        return;
    }

    // Rust `let_declaration` / Python `expression_statement` wrapping a
    // top-level assignment / JS `lexical_declaration` / Java
    // `local_variable_declaration` — all expose the binding via
    // `pattern`/`name` + `value`.
    let pattern = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("name"));
    let value = node.child_by_field_name("value");
    if let (Some(pattern), Some(value)) = (pattern, value)
        && rhs_is_pure_literal(value)
    {
        for var in collect_lhs_idents(pattern, bytes) {
            state.const_bound_vars.insert(var);
        }
        return;
    }

    // JS `lexical_declaration` / Java `local_variable_declaration` /
    // Python `expression_statement` — the binding child is a wrapper
    // (`variable_declarator`).  Recurse into wrappers; the
    // `variable_declarator` arm in `collect_unit_state` handles them.
    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        if matches!(
            child.kind(),
            "variable_declarator"
                | "init_declarator"
                | "var_spec"
                | "const_spec"
                | "assignment"
                | "assignment_expression"
        ) {
            collect_const_string_binding(child, bytes, state);
        }
    }
}

/// Returns true if `node` (after unwrapping common wrappers) is a
/// pure literal — string, integer, float, boolean, or null.  Returns
/// false for any expression that could carry attacker-controlled data
/// (calls, identifiers, field access, template strings with
/// interpolations).
fn rhs_is_pure_literal(node: Node<'_>) -> bool {
    // Unwrap wrappers that don't change taint provenance.
    let inner = match node.kind() {
        "parenthesized_expression"
        | "type_cast_expression"
        | "as_expression"
        | "cast_expression"
        | "reference_expression" => {
            let value = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"));
            value.unwrap_or(node)
        }
        _ => node,
    };
    matches!(
        inner.kind(),
        "string_literal"
            | "raw_string_literal"
            | "string"
            | "interpreted_string_literal"
            | "rune_literal"
            | "integer_literal"
            | "int_literal"
            | "float_literal"
            | "true"
            | "false"
            | "boolean_literal"
            | "nil"
            | "null"
            | "null_literal"
            | "none"
            | "character_literal"
    ) || (inner.kind() == "template_string" && !template_has_interpolation(inner))
        || (inner.kind() == "template_literal" && !template_has_interpolation(inner))
}

/// Returns true if a template literal/string contains any
/// interpolation segment (which carries dynamic data).  Pure
/// hard-coded template strings without `${...}` are still constants.
fn template_has_interpolation(node: Node<'_>) -> bool {
    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        if matches!(
            child.kind(),
            "template_substitution" | "interpolation" | "string_interpolation"
        ) {
            return true;
        }
    }
    false
}

/// Collect identifier names from an LHS pattern: a bare `identifier`,
/// a `tuple_pattern`, a Go `expression_list`, or a Rust `tuple_pattern`
/// / `let_pattern`.  Returns the bound variable names.  Ignores
/// destructured field accesses (we only track plain locals).
fn collect_lhs_idents(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if node.kind() == "identifier" {
        out.push(text(node, bytes));
        return out;
    }
    // Walk children, picking up identifiers; recurse into list/tuple
    // wrappers commonly seen on LHS of multi-binding declarations.
    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        match child.kind() {
            "identifier" => out.push(text(child, bytes)),
            "tuple_pattern"
            | "expression_list"
            | "pattern_list"
            | "list_pattern"
            | "field_identifier"
            | "shorthand_field_identifier" => {
                out.extend(collect_lhs_idents(child, bytes));
            }
            _ => {}
        }
    }
    out
}

/// Detect `let X = V.id` (or `(V.id as ..).into()`, `V.id.into()`,
/// `V.user_id`, `V.uid`, `V.userId`) where `V` is in `self_actor_vars`.
/// `X` is then a transitive copy of the authenticated actor's id and
/// is recorded in `self_actor_id_vars` so subjects of that name count
/// as actor context, not as foreign scoped IDs.
///
/// Closes a real-repo FP cluster: route handlers idiomatically reduce
/// the authed user to a scalar id and reuse it across many SQL params
/// (`let uid = user.id; query_all(.., &[uid]); query_all(.., &[uid])`).
/// The original `V.id`-shape recognition only covered direct subject
/// expressions; this captures the common copy-and-pass shape.
fn collect_self_actor_id_binding(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    // Rust `let_declaration` exposes `pattern`; JS/TS
    // `variable_declarator` exposes `name`.
    let Some(pattern) = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("name"))
    else {
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
    if value_is_self_actor_id_field(value, bytes, &state.self_actor_vars)
        || value_is_self_scoped_session_id_chain(value, bytes)
    {
        state.self_actor_id_vars.insert(var_name);
    }
}

/// Does `node` resolve to a `V.id` / `V.user_id` / `V.uid` / `V.userId`
/// field access where `V` is in `actor_vars`?  Walks through common
/// wrappers: `try_expression`, `await_expression`, `parenthesized_expression`,
/// `reference_expression`, `type_cast_expression` (`v.id as i64`),
/// and `call_expression` for chained `.into()` / `.to_string()` etc.
fn value_is_self_actor_id_field(
    node: Node<'_>,
    bytes: &[u8],
    actor_vars: &HashSet<String>,
) -> bool {
    match node.kind() {
        "field_expression" | "member_expression" | "field_access" | "scoped_identifier" => {
            let receiver = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("object"));
            let field = node
                .child_by_field_name("field")
                .or_else(|| node.child_by_field_name("property"))
                .or_else(|| node.child_by_field_name("name"));
            let (Some(receiver), Some(field)) = (receiver, field) else {
                return false;
            };
            let receiver_name = text(receiver, bytes);
            let field_name = text(field, bytes);
            actor_vars.contains(&receiver_name) && is_self_actor_id_field_name(&field_name)
        }
        "type_cast_expression"
        | "as_expression"
        | "cast_expression"
        | "parenthesized_expression"
        | "try_expression"
        | "await_expression"
        | "reference_expression" => {
            let value = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"));
            if let Some(v) = value
                && value_is_self_actor_id_field(v, bytes, actor_vars)
            {
                return true;
            }
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if value_is_self_actor_id_field(child, bytes, actor_vars) {
                    return true;
                }
            }
            false
        }
        // `(v.id as i64).into()` / `v.id.to_string()` / `v.id.clone()` —
        // call on a self-actor id field still propagates self-actor-id.
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let receiver = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("object"));
            if let Some(r) = receiver {
                // Function field of a method call is `receiver.method` —
                // walk the receiver subtree for the self-actor id field.
                if value_is_self_actor_id_field(r, bytes, actor_vars) {
                    return true;
                }
                // Also check the receiver of a method-style chain:
                // `(v.id as i64).into()` — `function` is the
                // `field_expression` `(...).into`, whose `value` child
                // is the cast expression.
                if let Some(inner) = r
                    .child_by_field_name("value")
                    .or_else(|| r.child_by_field_name("object"))
                    && value_is_self_actor_id_field(inner, bytes, actor_vars)
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn is_self_actor_id_field_name(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "id" | "user_id" | "userid" | "uid" | "email" | "username" | "handle"
    )
}

/// Recognise `let X = session.user.id` (or
/// `req.session.user.id` / `ctx.session.user.id` / `req.user.id` /
/// `request.user.id`, etc.) — a copy of the authenticated actor's
/// own id field through one of the canonical session-context chains
/// (the same set `is_self_scoped_session_subject` accepts at use
/// time). Walks through wrappers (`await`, `?.`, parens, casts,
/// trivial method chains like `.toString()`).
///
/// Closes a real-repo FP cluster (cal.com Next.js handlers): the
/// idiomatic shape is `if (session?.user?.id) { const userId =
/// session.user.id; await repo.get(userId); }`. The use site sees
/// a plain `userId` subject, so without binding-time recognition the
/// classifier can't tell it's actor context.
fn value_is_self_scoped_session_id_chain(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "field_expression" | "member_expression" | "field_access" | "scoped_identifier" => {
            // Build the dotted chain and reuse the same predicate the
            // subject classifier uses (`matches_session_context` +
            // self-scoped-base check). Doing it via the chain avoids
            // re-implementing the session-context grammar here.
            let chain = member_chain(node, bytes);
            if chain.len() < 2 {
                return false;
            }
            let field = chain.last().expect("len >= 2");
            if !is_self_actor_id_field_name(field) {
                return false;
            }
            let base_chain = &chain[..chain.len() - 1];
            let base = base_chain.join(".");
            classify_member_chain(base_chain) == ValueSourceKind::Session
                && is_self_scoped_session_base_text(&base)
        }
        "type_cast_expression"
        | "as_expression"
        | "cast_expression"
        | "parenthesized_expression"
        | "try_expression"
        | "await_expression"
        | "reference_expression"
        | "non_null_expression" => {
            let value = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"));
            if let Some(v) = value
                && value_is_self_scoped_session_id_chain(v, bytes)
            {
                return true;
            }
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if value_is_self_scoped_session_id_chain(child, bytes) {
                    return true;
                }
            }
            false
        }
        // `(req.user.id as number).toString()` / `session.user.id.toString()`
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let receiver = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("object"));
            if let Some(r) = receiver {
                if value_is_self_scoped_session_id_chain(r, bytes) {
                    return true;
                }
                if let Some(inner) = r
                    .child_by_field_name("value")
                    .or_else(|| r.child_by_field_name("object"))
                    && value_is_self_scoped_session_id_chain(inner, bytes)
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// String-level analogue of `is_self_scoped_session_base` from
/// `checks.rs`. Kept here in the extract layer to avoid a layer
/// dependency; the two lists must stay in sync.
fn is_self_scoped_session_base_text(base: &str) -> bool {
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

/// Does `node` (possibly wrapped in `?`/`.await`/`&`/`match`) resolve
/// to a call whose callee matches `is_login_guard` or
/// `is_authorization_check`? Used to detect `let user =
/// auth::require_auth(..).await?`-style bindings, including the
/// `let user = match require_auth() { Ok(u) => u, Err(_) => return ... }`
/// shape used by Worker / Cloudflare-style handlers that propagate
/// the auth failure response instead of using `?`.
fn value_is_self_actor_call(node: Node<'_>, bytes: &[u8], rules: &AuthAnalysisRules) -> bool {
    match node.kind() {
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let callee = call_name(node, bytes);
            !callee.is_empty()
                && (rules.is_login_guard(&callee) || rules.is_authorization_check(&callee))
        }
        "try_expression"
        | "await_expression"
        | "reference_expression"
        | "parenthesized_expression"
        | "match_expression" => {
            // For `match SCRUTINEE { ... }`, the scrutinee is the
            // call we care about — if `require_auth().await` is being
            // matched, the `Ok(u) => u` arm gives us a self-actor
            // binding even when `?` isn't usable.  Walk all named
            // children — tree-sitter exposes both the scrutinee and
            // the arms.
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

/// B3: detect `let X = …prepare(LIT)…` / `let X = …query(LIT)…`
/// where the SQL literal classifies as authorization-gated.  When
/// matched: insert `X` into `state.authorized_sql_vars` and synthesise
/// a `Membership` `AuthCheck` at the `let`'s line whose subjects
/// include `X` and the value-refs from the SQL call's bind args
/// (e.g. `user.id` in `.bind(user.id)`).  Downstream uses of `X`'s
/// columns are then transitively covered through `row_field_vars`.
fn collect_sql_authorized_binding(
    node: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    state: &mut UnitState,
) {
    if rules.acl_tables.is_empty() && !sql_direct_user_id_enabled() {
        return;
    }
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
    let Some((sql_call, bind_arg_refs)) = find_authorized_sql_call_in_chain(value, bytes, rules)
    else {
        return;
    };

    state.authorized_sql_vars.insert(var_name.clone());

    let mut subjects = bind_arg_refs;
    subjects.push(ValueRef {
        source_kind: ValueSourceKind::Identifier,
        name: var_name,
        base: None,
        field: None,
        index: None,
        span: span(node),
    });
    let line = node.start_position().row + 1;
    state.auth_checks.push(AuthCheck {
        kind: AuthCheckKind::Membership,
        callee: "(sql ACL)".into(),
        subjects,
        span: span(sql_call),
        line,
        args: Vec::new(),
        condition_text: None,
    });
}

/// Always true — the direct-user-id-predicate path in
/// `sql_semantics::classify_sql_query` doesn't depend on the ACL
/// table list, so we still want to walk `let X = …query(LIT)…`
/// chains even when the user hasn't configured any ACL tables.
/// Kept as a function so future tuning can disable this path.
fn sql_direct_user_id_enabled() -> bool {
    true
}

/// Walk down a chain of method calls (`a.b().c().d()`) looking for a
/// call whose method matches a SQL prepare/query verb and whose first
/// argument is a string literal classifying as auth-gated.  Returns
/// the matching call node along with the value-refs collected from
/// the *outer* chain's argument list (the call that bound the user
/// id, e.g. `.bind(user.id)`).
fn find_authorized_sql_call_in_chain<'tree>(
    value: Node<'tree>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
) -> Option<(Node<'tree>, Vec<ValueRef>)> {
    let mut bind_arg_refs: Vec<ValueRef> = Vec::new();
    let mut cur = unwrap_try_like(value);
    let mut steps = 0;
    while steps < 16 {
        steps += 1;
        if !matches!(
            cur.kind(),
            "call_expression" | "call" | "method_invocation" | "method_call_expression"
        ) {
            return None;
        }
        // Collect any non-literal arg value-refs from this call —
        // these typically include the bound user id (e.g.
        // `.bind(user.id)` → adds `user.id` as a subject).
        if let Some(args_node) = cur.child_by_field_name("arguments") {
            for arg in named_children(args_node) {
                if matches!(
                    arg.kind(),
                    "string_literal" | "raw_string_literal" | "string"
                ) {
                    continue;
                }
                bind_arg_refs.extend(extract_value_refs(arg, bytes));
            }
        }

        let callee = call_name(cur, bytes);
        let last_segment = bare_method_name(&callee);
        if is_sql_prepare_method(last_segment) {
            // Check first arg is a string literal that classifies
            // as authorized.
            let args = cur
                .child_by_field_name("arguments")
                .map(named_children)
                .unwrap_or_default();
            if let Some(first_arg) = args.first().copied()
                && let Some(literal) = collect_string_literal_text(first_arg, bytes)
                && crate::auth_analysis::sql_semantics::classify_sql_query(
                    &literal,
                    &rules.acl_tables,
                )
                .is_some()
            {
                return Some((cur, bind_arg_refs));
            }
            // Method matched but arg isn't a literal we recognise
            // as authorized — bail.
            return None;
        }

        // Descend through the receiver/object of this call to look
        // for an inner SQL prepare.
        let next = cur
            .child_by_field_name("receiver")
            .or_else(|| {
                cur.child_by_field_name("function").and_then(|fun| {
                    fun.child_by_field_name("object")
                        .or_else(|| fun.child_by_field_name("operand"))
                        .or_else(|| fun.child_by_field_name("argument"))
                        .or_else(|| fun.child_by_field_name("value"))
                })
            })
            .or_else(|| cur.child_by_field_name("object"));
        let next = next?;
        cur = unwrap_try_like(next);
    }
    None
}

/// Recognised SQL prepare/query method names. Matched against the
/// last segment of the callee.  String comparison only — we don't
/// constrain the receiver to a specific type; known DB connection
/// receivers are classified by the sink-class type gate, and this
/// list is the orthogonal verb axis.
fn is_sql_prepare_method(method: &str) -> bool {
    matches!(
        method,
        "prepare"
            | "query"
            | "query_one"
            | "query_all"
            | "query_as"
            | "query_map"
            | "query_row"
            | "query_scalar"
            | "fetch"
            | "fetch_one"
            | "fetch_all"
            | "fetch_optional"
            | "fetch_scalar"
            | "execute"
            | "exec"
    )
}

/// Extract the string content from a Rust string literal node, joining
/// adjacent fragments (e.g. `"a" "b"` becomes `"ab"`).  Returns `None`
/// when the node isn't a string literal at all.
fn collect_string_literal_text(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "string_literal" | "raw_string_literal" => {
            let mut buf = String::new();
            let mut found = false;
            for child in named_children(node) {
                if child.kind() == "string_content" {
                    buf.push_str(&text(child, bytes));
                    found = true;
                }
            }
            if found {
                Some(buf)
            } else {
                Some(strip_quotes(&text(node, bytes)))
            }
        }
        "string" | "template_string" | "interpreted_string_literal" => {
            Some(strip_quotes(&text(node, bytes)))
        }
        _ => None,
    }
}

/// B3: `for ROW in X { … }` — when `X` (the iterator value) names a
/// SQL-authorized variable, mark `ROW` authorized too AND record
/// `row_field_vars[ROW] = X` so transitive subject coverage works
/// for column reads inside the loop body.
fn collect_for_row_binding(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
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
    // The iterated expression is often `&X`, `X.iter()`, `X.into_iter()`,
    // etc.  Walk through reference / common iterator-method wrappers
    // to recover the underlying var name.
    let Some(source_var) = single_iter_source_name(value, bytes) else {
        return;
    };
    state
        .row_field_vars
        .insert(var_name.clone(), source_var.clone());
    if state.authorized_sql_vars.contains(&source_var) {
        state.authorized_sql_vars.insert(var_name);
    }
}

/// Recover the source identifier under common iteration-shape
/// wrappers: `X`, `&X`, `&mut X`, `X.iter()`, `X.iter_mut()`,
/// `X.into_iter()`, `X.values()`, `X.keys()`.  Returns `None` for
/// arbitrary expressions (`fetch_rows()`, `make_iter() + 1`, …).
fn single_iter_source_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let value = text(node, bytes);
            if value.is_empty() { None } else { Some(value) }
        }
        "reference_expression" | "parenthesized_expression" => {
            for idx in 0..node.named_child_count() {
                let Some(child) = node.named_child(idx as u32) else {
                    continue;
                };
                if let Some(name) = single_iter_source_name(child, bytes) {
                    return Some(name);
                }
            }
            None
        }
        "call_expression" | "call" | "method_invocation" | "method_call_expression" => {
            let callee = call_name(node, bytes);
            let last = bare_method_name(&callee);
            if !matches!(
                last,
                "iter" | "iter_mut" | "into_iter" | "values" | "keys" | "drain"
            ) {
                return None;
            }
            let receiver = node
                .child_by_field_name("receiver")
                .or_else(|| {
                    node.child_by_field_name("function").and_then(|fun| {
                        fun.child_by_field_name("object")
                            .or_else(|| fun.child_by_field_name("operand"))
                            .or_else(|| fun.child_by_field_name("argument"))
                            .or_else(|| fun.child_by_field_name("value"))
                    })
                })
                .or_else(|| node.child_by_field_name("object"))?;
            single_iter_source_name(receiver, bytes)
        }
        _ => None,
    }
}

/// B3: `let Y = ROW.method(..)` / `let Y = ROW.field` where `ROW` is
/// SQL-authorized — propagate authorized status to `Y` so any
/// downstream use (e.g. as a sink subject) is treated as covered.
/// `row_field_vars[Y] = ROW` is already populated by
/// `collect_row_field_binding`; this helper just propagates the
/// authorized-vars set along that edge.
fn propagate_sql_authorized_through_field_read(
    node: Node<'_>,
    bytes: &[u8],
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
    let Some(source) = extract_row_receiver_name(value, bytes) else {
        return;
    };
    if state.authorized_sql_vars.contains(&source) {
        state.authorized_sql_vars.insert(var_name);
    }
}

/// Recognise type names that semantically mean "the authenticated
/// actor" as the type of a function parameter.  Used by
/// `collect_typed_extractor_self_actor` to seed `self_actor_vars` so
/// that downstream `V.id`-shaped subjects on a parameter of one of
/// these types count as actor context, not foreign scoped IDs.
///
/// The recogniser is intentionally type-only — no name heuristic on
/// the variable.  A handler signature
/// `pub async fn handler(.., local_user_view: LocalUserView)` is
/// recognised because the type name matches, not because the
/// parameter is conventionally named `local_user_view`.
///
/// **Two acceptance forms:**
///
/// 1. *Tight exact set* — names whose entire identity is "auth
///    subject": `Authenticated`, `Identity`, `Principal`.  Adding new
///    bare names to this set should be done sparingly; framework
///    types that include `User` should go through the structural
///    form instead.
///
/// 2. *Structural form* — a CamelCase identifier of the shape
///    `<PREFIX>User<SUFFIX>?` where `PREFIX` is one of `Local`,
///    `Current`, `Session`, `Auth`, `Authenticated`, `LoggedIn`,
///    `Admin`, and `SUFFIX` (optional) is one of `View`, `Info`,
///    `Context`, `Session`, `Token`.  Catches `LocalUserView`
///    (lemmy), `LocalUser`, `CurrentUser`, `LoggedInUser`,
///    `AuthenticatedUserContext`, etc.
///
/// **Deliberately *not* matched:**
/// * Bare `User` — too loose; `User` parameters are very often
///   deserialised payloads, not actor extractors.
/// * `UserView`, `UserPreferences` — same reason; the prefix is what
///   carries the auth signal, not the bare `User` segment.
fn is_self_actor_type_text(ty: &str) -> bool {
    let trimmed = ty
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    let after_colons = trimmed.rsplit("::").next().unwrap_or(trimmed);
    let base = after_colons
        .split('<')
        .next()
        .unwrap_or(after_colons)
        .trim();
    if matches!(base, "Authenticated" | "Identity" | "Principal") {
        return true;
    }
    matches_self_actor_user_form(base)
}

/// Structural form: `<PREFIX>User<SUFFIX>?` where PREFIX is in the
/// authority-prefix vocabulary and SUFFIX is in the
/// auth-context-suffix vocabulary (or absent).
///
/// Implementation: strip a leading PREFIX, require the remainder to
/// start with `User`, and accept either an exact `User` match or a
/// `User`+SUFFIX match.  Case-sensitive on the segment boundaries
/// because we want CamelCase types only — `localuser` wouldn't be a
/// real Rust type name and matching it would create ambiguity with
/// payload identifiers.
fn matches_self_actor_user_form(base: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "Local",
        "Current",
        "Session",
        "Authenticated",
        "Auth",
        "LoggedIn",
        "Admin",
    ];
    const SUFFIXES: &[&str] = &["View", "Info", "Context", "Session", "Token"];
    for prefix in PREFIXES {
        let Some(rest) = base.strip_prefix(prefix) else {
            continue;
        };
        let Some(after_user) = rest.strip_prefix("User") else {
            continue;
        };
        if after_user.is_empty() {
            return true;
        }
        if SUFFIXES.contains(&after_user) {
            return true;
        }
    }
    false
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
        "field_expression"
        | "member_expression"
        | "attribute"
        | "selector_expression"
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
        if value.is_empty() { None } else { Some(value) }
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
            "try_expression"
            | "await_expression"
            | "reference_expression"
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
    if node.kind() == "parenthesized_expression"
        && let Some(inner) = node.named_child(0)
    {
        return unwrap_parens_local(inner);
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
    if alt.kind() == "else_clause"
        && let Some(block) = named_children(alt).into_iter().next()
    {
        return block;
    }
    alt
}

fn branch_has_early_exit(branch: Node<'_>) -> bool {
    named_children(branch).into_iter().any(node_is_early_exit)
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

/// Walk the tree starting at `node` and gather TS type-alias /
/// interface names whose body references a TRPC-marker type
/// (`TrpcSessionUser`, `TRPCContext`, …).  Recurses only through
/// container kinds that legitimately host top-level type aliases
/// (`program` / `module` / `export_statement` / namespace bodies);
/// stops at function or class bodies to avoid an O(units × tree)
/// blowup on files with many small functions.
///
/// No-op for non-TS files — the matched node kinds only exist in
/// the TS grammar.  Used by [`FileMeta::scan`] (called once per file
/// in `collect_top_level_units` / `attach_route_handler`) to amortise
/// the alias scan across all units in the same source file.
fn scan_trpc_aliases_visit(node: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    match node.kind() {
        "type_alias_declaration" | "interface_declaration" => {
            let body = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("body"));
            if let Some(body) = body {
                let body_text = text(body, bytes);
                if body_text_references_trpc_marker(&body_text)
                    && let Some(name_node) = node.child_by_field_name("name")
                {
                    let name = text(name_node, bytes);
                    if !name.is_empty() {
                        out.insert(name);
                    }
                }
            }
            return;
        }
        // Recurse only through container kinds that legitimately host
        // top-level type aliases.  Skipping into function bodies /
        // class bodies / call arguments avoids an O(unit × tree)
        // blowup when `build_function_unit` triggers this scan once
        // per unit on files with thousands of small functions
        // (`tests/hostile_input_tests::many_small_functions_do_not_explode`).
        "program"
        | "source_file"
        | "module"
        | "export_statement"
        | "namespace_declaration"
        | "module_declaration"
        | "internal_module"
        | "ambient_declaration"
        | "lexical_declaration"
        | "variable_declaration"
        | "statement_block" => {}
        _ => return,
    }
    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        scan_trpc_aliases_visit(child, bytes, out);
    }
}

fn body_text_references_trpc_marker(body_text: &str) -> bool {
    body_text.contains("TrpcSessionUser")
        || body_text.contains("TRPCContext")
        || body_text.contains("ProtectedTRPCContext")
        || body_text.contains("TrpcContext")
}

/// Recognise a TS `required_parameter` / `optional_parameter` whose
/// type annotation refers to a TRPC-shaped Options alias (or
/// inlines `TrpcSessionUser` directly), and add the destructured /
/// declared `ctx`-base to `self_scoped_session_bases` so subjects
/// rooted at `ctx.user.<id-like>` count as actor context downstream.
///
/// Three pattern shapes are handled:
///   1. Destructured shorthand: `({ ctx, input }: GetOptions)` →
///      add `"ctx.user"`.
///   2. Destructured rename: `({ ctx: c, input }: GetOptions)` →
///      add `"c.user"`.
///   3. Plain identifier: `(opts: GetOptions)` → add `"opts.ctx.user"`.
///
/// The rule is principled: we only fire when the param's type either
/// IS one of the file-level TRPC aliases (`state.trpc_alias_names`,
/// populated by [`scan_trpc_aliases_from_node_root`]) or its annotation
/// text inlines `TrpcSessionUser` directly.  Bare `ctx.user` is never
/// added to the static session-base list — that would over-suppress
/// in non-TRPC code.  Instead, the dynamic per-unit set
/// `self_scoped_session_bases` carries the lift.
fn collect_trpc_ctx_param(node: Node<'_>, bytes: &[u8], state: &mut UnitState) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(ty_node) = node.child_by_field_name("type") else {
        return;
    };
    let ty_text = text(ty_node, bytes);
    if !type_text_is_trpc_options(&ty_text, &state.trpc_alias_names) {
        return;
    }

    if pattern.kind() == "object_pattern" {
        for idx in 0..pattern.named_child_count() {
            let Some(child) = pattern.named_child(idx as u32) else {
                continue;
            };
            match child.kind() {
                "shorthand_property_identifier_pattern" => {
                    let name = text(child, bytes);
                    if name.eq_ignore_ascii_case("ctx") {
                        state
                            .self_scoped_session_bases
                            .insert(format!("{name}.user"));
                    }
                }
                "object_assignment_pattern" => {
                    if let Some(left) = child.child_by_field_name("left") {
                        let name = if matches!(
                            left.kind(),
                            "identifier" | "shorthand_property_identifier_pattern"
                        ) {
                            text(left, bytes)
                        } else {
                            first_identifier_name(left, bytes).unwrap_or_default()
                        };
                        if name.eq_ignore_ascii_case("ctx") {
                            state
                                .self_scoped_session_bases
                                .insert(format!("{name}.user"));
                        }
                    }
                }
                "pair_pattern" => {
                    let key_node = child.child_by_field_name("key");
                    let local_node = child.child_by_field_name("value");
                    if let (Some(k), Some(v)) = (key_node, local_node) {
                        let key = text(k, bytes);
                        let local = first_identifier_name(v, bytes).unwrap_or_default();
                        if !local.is_empty() && key.eq_ignore_ascii_case("ctx") {
                            state
                                .self_scoped_session_bases
                                .insert(format!("{local}.user"));
                        }
                    }
                }
                _ => {}
            }
        }
        return;
    }

    if let Some(name) = first_identifier_name(pattern, bytes)
        && !name.is_empty()
    {
        state
            .self_scoped_session_bases
            .insert(format!("{name}.ctx.user"));
    }
}

/// True when the type-annotation text identifies a TRPC-shaped Options
/// type: it contains `TrpcSessionUser` directly (inline object type
/// literal), or it references one of the file-level TRPC alias names
/// from the pre-scan.
fn type_text_is_trpc_options(ty_text: &str, trpc_alias_names: &HashSet<String>) -> bool {
    if body_text_references_trpc_marker(ty_text) {
        return true;
    }
    let trimmed = ty_text.trim_start_matches(':').trim();
    if trimmed.is_empty() {
        return false;
    }
    // Match the leading identifier of the type (dropping any generic
    // suffix `<...>`).  This covers `GetOptions` and
    // `NonNullable<GetOptions>` shapes alike.
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    if trpc_alias_names.contains(head) {
        return true;
    }
    // Also accept the bare alias name appearing anywhere in the
    // annotation text — handles `Promise<GetOptions>` and other
    // wrappers without enumerating every shape.  Word-boundary check
    // avoids matching aliases that are substrings of longer
    // identifiers.
    for alias in trpc_alias_names {
        if alias.is_empty() {
            continue;
        }
        if let Some(idx) = ty_text.find(alias.as_str()) {
            let before_ok = idx == 0
                || !ty_text.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    && ty_text.as_bytes()[idx - 1] != b'_';
            let end = idx + alias.len();
            let after_ok = end >= ty_text.len()
                || !ty_text.as_bytes()[end].is_ascii_alphanumeric()
                    && ty_text.as_bytes()[end] != b'_';
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Extract the receiver-variable name from a Go `method_declaration`
/// (`func (c *Cache) ...` → `Some("c")`).  Returns `None` for any node
/// that doesn't expose a `receiver` field (Rust `function_item`,
/// Java `method_declaration`, JS arrow-functions, …).
///
/// Tree-sitter-go shape: `method_declaration` has a `receiver` field
/// whose value is a `parameter_list` containing a single
/// `parameter_declaration` with a `name` field (identifier) and a
/// `type` field (often `pointer_type`).  We only need the name.
pub fn method_receiver_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let receiver = node.child_by_field_name("receiver")?;
    extract_receiver_param_name(receiver, bytes)
}

fn extract_receiver_param_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = text(name_node, bytes);
        if !name.is_empty() {
            return Some(name);
        }
    }
    for idx in 0..node.named_child_count() {
        let Some(child) = node.named_child(idx as u32) else {
            continue;
        };
        if let Some(found) = extract_receiver_param_name(child, bytes) {
            return Some(found);
        }
    }
    None
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
        let arg_nodes = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        let args = arg_nodes.iter().map(|arg| text(*arg, bytes)).collect();
        let args_value_refs = arg_nodes
            .iter()
            .map(|arg| extract_value_refs(*arg, bytes))
            .collect();
        CallSite {
            name,
            args,
            span: span(node),
            args_value_refs,
        }
    } else {
        CallSite {
            name: text(node, bytes),
            args: Vec::new(),
            span: span(node),
            args_value_refs: Vec::new(),
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
        "identifier"
        // Ruby `@foo` instance variables and `@@foo` class variables are
        // leaves with no named children, so the catch-all recurse arm
        // would yield an empty subject set.  Surface them as Identifier
        // value-refs so receiver-side ownership checks (`@issue.visible?`)
        // produce a subject that the row-fetch exemption can match.
        | "instance_variable"
        | "class_variable"
        | "global_variable" => vec![ValueRef {
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
    let method = bare_method_name(callee);
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
        // Tight exact set: bare names whose entire identity is "auth subject".
        assert!(is_self_actor_type_text("Authenticated"));
        assert!(is_self_actor_type_text("Identity"));
        assert!(is_self_actor_type_text("Principal"));

        // Structural form: <PREFIX>User<SUFFIX?>.
        assert!(is_self_actor_type_text("CurrentUser"));
        assert!(is_self_actor_type_text("SessionUser"));
        assert!(is_self_actor_type_text("AuthUser"));
        assert!(is_self_actor_type_text("AdminUser"));
        assert!(is_self_actor_type_text("AuthenticatedUser"));
        // Lemmy: LocalUserView (the real-repo motivation for the
        // structural recogniser).
        assert!(is_self_actor_type_text("LocalUserView"));
        assert!(is_self_actor_type_text("LocalUser"));
        assert!(is_self_actor_type_text("LoggedInUser"));
        assert!(is_self_actor_type_text("CurrentUserContext"));
        assert!(is_self_actor_type_text("AuthenticatedUserSession"));
        assert!(is_self_actor_type_text("SessionUserToken"));
        assert!(is_self_actor_type_text("AdminUserInfo"));
        // Qualified paths resolve to last segment.
        assert!(is_self_actor_type_text("crate::auth::CurrentUser"));
        assert!(is_self_actor_type_text("crate::user::LocalUserView"));
        assert!(is_self_actor_type_text("&CurrentUser"));
        assert!(is_self_actor_type_text("&mut AuthUser"));
        // Generic wrappers: match on the base segment.
        assert!(is_self_actor_type_text("CurrentUser<Admin>"));
        assert!(is_self_actor_type_text("LocalUserView<Admin>"));

        // Non-matches.
        // Bare `User` — too loose; commonly a deserialised payload type.
        assert!(!is_self_actor_type_text("User"));
        assert!(!is_self_actor_type_text("UserPreferences"));
        // `UserView` lacks an authority-prefix segment and stays a
        // payload-shaped name.
        assert!(!is_self_actor_type_text("UserView"));
        // No prefix vocabulary match — still rejected.
        assert!(!is_self_actor_type_text("PaymentUser"));
        // Wrong suffix vocabulary.
        assert!(!is_self_actor_type_text("CurrentUserPreferences"));
        // Framework extractors / unrelated types.
        assert!(!is_self_actor_type_text("Db"));
        assert!(!is_self_actor_type_text("Path<(i64,)>"));
        assert!(!is_self_actor_type_text("Json<Body>"));
        // `RequireAuth` / `RequireLogin` were dropped from the exact
        // set: they aren't `User`-bearing types and aren't
        // semantically the auth subject — they're guard markers.  The
        // route-aware `axum::classify_guard_type` still treats them
        // as a login guard via the looser substring match.
        assert!(!is_self_actor_type_text("RequireAuth"));
        assert!(!is_self_actor_type_text("RequireLogin"));
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

    #[test]
    fn type_text_is_trpc_options_matches_alias_and_inline_marker() {
        use super::type_text_is_trpc_options;
        use std::collections::HashSet;
        let mut aliases = HashSet::new();
        aliases.insert("GetOptions".to_string());
        aliases.insert("UpdateOptions".to_string());

        // Inline `TrpcSessionUser` marker — accepted regardless of alias set.
        assert!(type_text_is_trpc_options(
            ": { ctx: { user: NonNullable<TrpcSessionUser> } }",
            &aliases
        ));
        assert!(type_text_is_trpc_options(
            ": { user: TrpcSessionUser }",
            &HashSet::new()
        ));

        // Plain alias name match.
        assert!(type_text_is_trpc_options(": GetOptions", &aliases));
        assert!(type_text_is_trpc_options("GetOptions", &aliases));

        // Generic-wrapped alias.
        assert!(type_text_is_trpc_options(": Promise<GetOptions>", &aliases));
        assert!(type_text_is_trpc_options(
            ": NonNullable<UpdateOptions>",
            &aliases
        ));

        // Negatives: alias not in set, no inline marker.
        assert!(!type_text_is_trpc_options(": OtherOptions", &aliases));
        assert!(!type_text_is_trpc_options(": Promise<Foo>", &aliases));
        assert!(!type_text_is_trpc_options(": SomeRandomType", &aliases));
        // Substring of a longer identifier must NOT match.
        assert!(!type_text_is_trpc_options(": MyGetOptionsX", &aliases));
    }

    #[test]
    fn body_text_references_trpc_marker_recognises_known_markers() {
        use super::body_text_references_trpc_marker as bm;
        assert!(bm("type X = { user: NonNullable<TrpcSessionUser> }"));
        assert!(bm("interface Ctx extends TRPCContext { ... }"));
        assert!(bm("type Ctx = ProtectedTRPCContext"));
        assert!(bm("export type Y = { ctx: TrpcContext }"));
        // Negatives.
        assert!(!bm("type X = { user: User }"));
        assert!(!bm("type X = SessionContext"));
        assert!(!bm("type X = { foo: SomeContext }"));
    }

    /// Pin the string-level analogue used by
    /// `value_is_self_scoped_session_id_chain`: it must accept the
    /// same set of session-scoped bases that `checks.rs::
    /// is_self_scoped_session_base` accepts.  When you add a new base
    /// to one, add it to the other and update both tests.
    #[test]
    fn is_self_scoped_session_base_text_matches_known_session_bases() {
        use super::is_self_scoped_session_base_text as bt;
        // Express / passport idioms.
        assert!(bt("req.user"));
        assert!(bt("request.user"));
        assert!(bt("req.session.user"));
        assert!(bt("req.session.currentUser"));
        // Bare session.user (Next.js / NextAuth idiom).
        assert!(bt("session.user"));
        assert!(bt("session.currentUser"));
        // Koa ctx.state / ctx.session.
        assert!(bt("ctx.session.user"));
        assert!(bt("ctx.state.user"));
        // Negatives — bases that are NOT canonical authed-user roots.
        assert!(!bt("req.body"));
        assert!(!bt("req.params"));
        assert!(!bt("ctx.user"));
        assert!(!bt("data.user"));
        assert!(!bt("user"));
    }
}
