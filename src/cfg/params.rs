use super::{
    AstMeta, Cfg, EdgeKind, NodeInfo, StmtKind, TaintMeta, collect_idents, connect_all,
    is_anon_fn_name, text_of,
};
use crate::labels::{DataLabel, LangAnalysisRules, classify, param_config};
use crate::ssa::type_facts::TypeKind;
use petgraph::graph::NodeIndex;
use smallvec::smallvec;
use tree_sitter::Node;

/// Extract parameter names + per-position [`TypeKind`] from a function
/// AST node.  Each entry's second slot is `Some(TypeKind)` when the
/// parameter's decorator, attribute, or static type annotation maps to
/// a known kind, and `None` otherwise.  Strictly additive — when no
/// type info is recoverable, behaviour is identical to the names-only
/// path.
pub(super) fn extract_param_meta<'a>(
    func_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<(String, Option<TypeKind>)> {
    let cfg = param_config(lang);
    let mut out: Vec<(String, Option<TypeKind>)> = Vec::new();
    // Try the params_field directly on the function node first.
    // For C/C++, the parameter list is nested inside the declarator
    // (function_definition > declarator:function_declarator > parameters:parameter_list),
    // so fall back to looking one level deeper via the "declarator" field.
    let params = func_node.child_by_field_name(cfg.params_field).or_else(|| {
        func_node
            .child_by_field_name("declarator")
            .and_then(|d| d.child_by_field_name(cfg.params_field))
    });
    let Some(params) = params else {
        return out;
    };
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        // Self/this parameter (e.g. Rust's `self_parameter`)
        if cfg.self_param_kinds.contains(&child.kind()) {
            out.push(("self".into(), None));
            continue;
        }

        // Regular parameter
        if cfg.param_node_kinds.contains(&child.kind()) {
            // Try each ident field in order
            let mut found = false;
            for &field in cfg.ident_fields {
                if let Some(node) = child.child_by_field_name(field) {
                    let mut tmp = Vec::new();
                    collect_idents(node, code, &mut tmp);
                    let candidate = if lang == "rust" {
                        tmp.into_iter().last()
                    } else {
                        tmp.into_iter().next()
                    };
                    if let Some(name) = candidate {
                        let ty = classify_param_type(child, lang, code);
                        out.push((name, ty));
                        found = true;
                        break;
                    }
                }
            }
            // Fallback: if the param node itself is an identifier (e.g. JS/Python)
            if !found
                && child.kind() == "identifier"
                && let Some(txt) = text_of(child, code)
            {
                out.push((txt, None));
                found = true;
            }
            // Fallback for C/C++: look for nested declarator → identifier
            if !found && child.kind() == "parameter_declaration" {
                let mut tmp = Vec::new();
                collect_idents(child, code, &mut tmp);
                if let Some(last) = tmp.pop() {
                    let ty = classify_param_type(child, lang, code);
                    out.push((last, ty));
                    found = true;
                }
            }
            // Generic fallback for typed/default parameter wrappers (e.g.
            // Python `typed_parameter`, `default_parameter`,
            // `typed_default_parameter`): the wrapper node has no `name`
            // field but contains the identifier as a child.  Pick the
            // *first* identifier — that is the parameter name; subsequent
            // identifiers are part of the type annotation or default
            // expression.
            if !found {
                let mut tmp = Vec::new();
                collect_idents(child, code, &mut tmp);
                if let Some(first) = tmp.into_iter().next() {
                    let ty = classify_param_type(child, lang, code);
                    out.push((first, ty));
                }
            }
            continue;
        }

        // Bare identifier children — e.g. Rust untyped closure params `|cmd|`
        // where the child is an `identifier` node, not a `parameter` wrapper.
        if child.kind() == "identifier" {
            if let Some(txt) = text_of(child, code) {
                out.push((txt, None));
            }
        }
    }
    out
}

/// Walk up from a function definition node and build a container path.
///
/// Records the names of enclosing classes / impls / modules / namespaces /
/// structs — and, for anonymous / nested functions, the name of an enclosing
/// named function — joined with `::`.  Also returns a `FuncKind` guess
/// reflecting the structural role.
///
/// Returns `(container, kind)`.
pub(super) fn compute_container_and_kind(
    func_node: Node<'_>,
    ast_kind: &str,
    fn_name: &str,
    code: &[u8],
) -> (String, crate::symbol::FuncKind) {
    use crate::symbol::FuncKind;

    // Lambda / arrow / anonymous function ⇒ Closure regardless of context.
    let mut kind = if ast_kind == "lambda_expression"
        || ast_kind == "arrow_function"
        || ast_kind == "function_expression"
        || ast_kind == "anonymous_function"
        || ast_kind == "closure_expression"
        || is_anon_fn_name(fn_name)
    {
        FuncKind::Closure
    } else {
        FuncKind::Function
    };

    let mut segments: Vec<String> = Vec::new();
    let mut inside_class = false;
    let mut cursor = func_node.parent();

    while let Some(parent) = cursor {
        let pk = parent.kind();

        // Class / struct / impl / interface / namespace / module containers.
        let container_name_field: Option<&str> = match pk {
            // JS / TS / Python / Ruby / PHP / Java / Kotlin / C++ classes
            "class_declaration"
            | "class_definition"
            | "class_specifier"
            | "class"
            | "interface_declaration"
            | "interface_body"
            | "enum_declaration"
            | "trait_item"
            | "trait_declaration"
            | "enum_item"
            | "struct_specifier"
            | "struct_item" => Some("name"),
            // Rust impl blocks — pick the type name, not the trait name.
            "impl_item" => Some("type"),
            // Go / C++ / PHP namespaces and modules.
            "namespace_definition" | "namespace_declaration" | "module_declaration" | "module" => {
                Some("name")
            }
            _ => None,
        };

        if let Some(field) = container_name_field {
            if let Some(name_node) = parent.child_by_field_name(field) {
                if let Some(text) = text_of(name_node, code) {
                    segments.push(text);
                    inside_class |= matches!(
                        pk,
                        "class_declaration"
                            | "class_definition"
                            | "class_specifier"
                            | "class"
                            | "interface_declaration"
                            | "interface_body"
                            | "trait_item"
                            | "trait_declaration"
                            | "impl_item"
                            | "struct_item"
                            | "struct_specifier"
                    );
                }
            }
        } else if pk == "function_declaration"
            || pk == "function_definition"
            || pk == "method_declaration"
            || pk == "method_definition"
            || pk == "function_item"
            || pk == "arrow_function"
            || pk == "lambda_expression"
            || pk == "function_expression"
        {
            // Nested definition — record the outer function's name and
            // classify self as Closure even if we got a real name.
            if let Some(name_node) = parent.child_by_field_name("name") {
                if let Some(text) = text_of(name_node, code) {
                    segments.push(text);
                }
            }
            if !matches!(kind, FuncKind::Closure) {
                kind = FuncKind::Closure;
            }
        }

        cursor = parent.parent();
    }

    // Upgrade to Method/Constructor when inside a class-like container.
    if inside_class && matches!(kind, FuncKind::Function) {
        kind = if fn_name == "__init__"
            || fn_name == "constructor"
            || fn_name == "initialize"
            || fn_name == "new"
        {
            FuncKind::Constructor
        } else {
            FuncKind::Method
        };
    }

    segments.reverse();
    let container = segments.join("::");
    (container, kind)
}

pub(super) fn rust_param_binding_name(param_text: &str) -> Option<String> {
    let before_colon = param_text.split(':').next().unwrap_or(param_text).trim();
    let tokens: Vec<&str> = before_colon
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty() && !matches!(*token, "mut" | "ref"))
        .collect();
    tokens.last().map(|token| (*token).to_string())
}

pub(super) fn rust_param_type_text(param: Node<'_>, code: &[u8]) -> Option<String> {
    param
        .child_by_field_name("type")
        .and_then(|node| text_of(node, code))
        .or_else(|| {
            text_of(param, code).and_then(|text| {
                text.split_once(':')
                    .map(|(_, ty)| ty.trim().to_string())
                    .filter(|ty| !ty.is_empty())
            })
        })
}

pub(super) fn rust_route_attribute_bindings(func_node: Node<'_>, code: &[u8]) -> Vec<String> {
    let Some(text) = text_of(func_node, code) else {
        return Vec::new();
    };
    let mut bindings = Vec::new();

    for line in text
        .lines()
        .map(str::trim)
        .take_while(|line| line.starts_with("#["))
    {
        if !(line.starts_with("#[get")
            || line.starts_with("#[post")
            || line.starts_with("#[put")
            || line.starts_with("#[delete")
            || line.starts_with("#[patch"))
        {
            continue;
        }

        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '<' {
                let mut token = String::new();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next == '>' {
                        break;
                    }
                    token.push(next);
                }
                let token = token.trim();
                if !token.is_empty() {
                    bindings.push(token.to_string());
                }
            }
        }
    }

    bindings
}

pub(super) fn rust_framework_param_sources<'a>(
    func_node: Node<'a>,
    code: &'a [u8],
    analysis_rules: Option<&crate::labels::LangAnalysisRules>,
) -> Vec<(String, crate::labels::Cap, (usize, usize))> {
    let Some(analysis_rules) = analysis_rules else {
        return Vec::new();
    };
    let extra = analysis_rules.extra_labels.as_slice();
    if extra.is_empty() {
        return Vec::new();
    }

    let cfg = param_config("rust");
    let params = func_node.child_by_field_name(cfg.params_field);
    let Some(params) = params else {
        return Vec::new();
    };

    let rocket_route_bindings = if analysis_rules
        .frameworks
        .contains(&crate::utils::project::DetectedFramework::Rocket)
    {
        rust_route_attribute_bindings(func_node, code)
    } else {
        Vec::new()
    };

    let mut sources = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if cfg.self_param_kinds.contains(&child.kind()) || child.kind() != "parameter" {
            continue;
        }

        let Some(param_text) = text_of(child, code) else {
            continue;
        };
        let Some(binding) = rust_param_binding_name(&param_text) else {
            continue;
        };
        let span = (child.start_byte(), child.end_byte());

        let type_caps = rust_param_type_text(child, code).and_then(|type_text| {
            match classify("rust", &type_text, Some(extra)) {
                Some(DataLabel::Source(caps)) => Some(caps),
                _ => None,
            }
        });
        let route_caps = rocket_route_bindings
            .iter()
            .any(|name| name == &binding)
            .then_some(crate::labels::Cap::all());

        let Some(caps) = type_caps.or(route_caps) else {
            continue;
        };
        if !sources
            .iter()
            .any(|(name, _, existing_span)| name == &binding && existing_span == &span)
        {
            sources.push((binding, caps, span));
        }
    }

    sources
}

pub(super) fn inject_framework_param_sources(
    func_node: Node<'_>,
    code: &[u8],
    analysis_rules: Option<&crate::labels::LangAnalysisRules>,
    graph: &mut Cfg,
    entry: NodeIndex,
    enclosing_func: Option<&str>,
) -> Vec<NodeIndex> {
    let sources = rust_framework_param_sources(func_node, code, analysis_rules);
    if sources.is_empty() {
        return vec![entry];
    }

    let mut preds = vec![entry];
    for (binding, caps, span) in sources {
        let idx = graph.add_node(NodeInfo {
            kind: StmtKind::Seq,
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(caps)],
                defines: Some(binding),
                ..Default::default()
            },
            ast: AstMeta {
                span,
                enclosing_func: enclosing_func.map(|s| s.to_string()),
            },
            ..Default::default()
        });
        connect_all(graph, &preds, idx, EdgeKind::Seq);
        preds = vec![idx];
    }

    preds
}

/// Classify a parameter AST node to a [`TypeKind`] using per-language
/// decorator / attribute / annotation matchers.  Strictly additive: when
/// no recognised pattern matches, returns `None` and the engine
/// behaves exactly as before.
///
/// Recognised patterns (Phase 2):
/// * Java (Spring) — `@PathVariable`/`@RequestParam Long X` →
///   [`TypeKind::Int`]; `@RequestBody T` → object (no kind today).
/// * TypeScript (NestJS) — `@Param('id') id: number` →
///   [`TypeKind::Int`]; `@Body() dto: T` / `@Query('q') q: string`.
/// * Rust (Axum / Rocket / Actix) — `Path<i64>` / `Path<u32>` /
///   `web::Path<i64>` → [`TypeKind::Int`]; `Path<String>` →
///   [`TypeKind::String`].
/// * Python (FastAPI) — `def h(x: int)` → [`TypeKind::Int`];
///   `Annotated[int, Path()]` → [`TypeKind::Int`].
pub(super) fn classify_param_type<'a>(
    param: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Option<TypeKind> {
    match lang {
        "java" => classify_param_type_java(param, code),
        "typescript" | "ts" => classify_param_type_ts(param, code),
        "javascript" | "js" => classify_param_type_ts(param, code),
        "rust" | "rs" => classify_param_type_rust(param, code),
        "python" | "py" => classify_param_type_python(param, code),
        _ => None,
    }
}

/// Java (Spring) — recognise typed-extractor parameters via the
/// surrounding annotation.  Per Hard Rule 3, plain `Long X` without a
/// known framework annotation is **not** treated as a typed extractor —
/// the parameter could be a regular function argument that the
/// framework never validates.  Recognised annotations:
/// `@PathVariable`, `@RequestParam`, `@RequestBody`, `@RequestHeader`,
/// `@CookieValue`, `@MatrixVariable`.  When an annotation matches, the
/// parameter's static type is consulted via [`java_type_to_kind`].
fn classify_param_type_java<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    if param.kind() != "formal_parameter" && param.kind() != "spread_parameter" {
        return None;
    }
    if !has_java_framework_annotation(param, code) {
        return None;
    }
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    java_type_to_kind(&type_text)
}

/// Walk the parameter's modifiers (annotations) and check if any of
/// them are a recognised Spring web binding annotation.  Spring's
/// annotation grammar exposes annotations as `marker_annotation` /
/// `annotation` siblings inside the formal_parameter's `modifiers`
/// child.
fn has_java_framework_annotation(param: Node<'_>, code: &[u8]) -> bool {
    const KNOWN: &[&str] = &[
        "@PathVariable",
        "@RequestParam",
        "@RequestBody",
        "@RequestHeader",
        "@CookieValue",
        "@MatrixVariable",
        "@ModelAttribute",
    ];
    // Inspect modifiers child first.
    if let Some(modifiers) = param.child_by_field_name("modifiers") {
        if let Some(text) = text_of(modifiers, code) {
            for k in KNOWN {
                if text.contains(k) {
                    return true;
                }
            }
        }
    }
    // Fall back to scanning all named children: tree-sitter-java emits
    // annotations as direct children of formal_parameter in some grammar
    // versions.
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        let kind = child.kind();
        if matches!(kind, "marker_annotation" | "annotation" | "modifiers")
            && let Some(text) = text_of(child, code)
        {
            for k in KNOWN {
                if text.contains(k) {
                    return true;
                }
            }
        }
    }
    false
}

fn java_type_to_kind(t: &str) -> Option<TypeKind> {
    let bare = t.trim().trim_start_matches('@').trim();
    // Drop generic args for the leading type.
    let bare = bare.split('<').next().unwrap_or(bare).trim();
    let last = bare.rsplit('.').next().unwrap_or(bare);
    match last {
        "int" | "long" | "short" | "byte" | "Integer" | "Long" | "Short" | "Byte"
        | "BigInteger" => Some(TypeKind::Int),
        "boolean" | "Boolean" => Some(TypeKind::Bool),
        "double" | "float" | "Double" | "Float" | "BigDecimal" => Some(TypeKind::Int),
        "String" | "CharSequence" => Some(TypeKind::String),
        _ => None,
    }
}

/// TypeScript (NestJS) — recognise typed-extractor parameters via a
/// known NestJS decorator (`@Param`, `@Body`, `@Query`, `@Headers`,
/// `@Req`, `@Res`).  Per Hard Rule 3, a bare `function h(id: number)`
/// is not a framework extractor — without a NestJS decorator no
/// runtime gate is implied.  Pipe coercions (`ParseIntPipe` /
/// `ParseBoolPipe`) override the static type.
fn classify_param_type_ts<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    if !has_ts_decorator_argument(
        param,
        code,
        &[
            "@Param", "@Body", "@Query", "@Headers", "@Header", "@Cookie", "@UploadedFile",
        ],
    ) {
        return None;
    }
    // Decorator-based pipe coercion overrides the static type.
    if has_ts_decorator_argument(param, code, &["ParseIntPipe"]) {
        return Some(TypeKind::Int);
    }
    if has_ts_decorator_argument(param, code, &["ParseBoolPipe"]) {
        return Some(TypeKind::Bool);
    }
    let t = param
        .child_by_field_name("type")
        .and_then(|n| inner_ts_type_text(n, code))?;
    let stripped = t.trim().trim_start_matches(':').trim();
    let head = stripped.split('<').next().unwrap_or(stripped).trim();
    match head {
        "number" | "bigint" => Some(TypeKind::Int),
        "boolean" => Some(TypeKind::Bool),
        "string" => Some(TypeKind::String),
        _ => None,
    }
}

fn inner_ts_type_text<'a>(type_anno: Node<'a>, code: &'a [u8]) -> Option<String> {
    // type_annotation node text is `: T` — unwrap to T.
    if let Some(child) = type_anno.named_child(0) {
        return text_of(child, code);
    }
    text_of(type_anno, code)
}

/// Walk through a TypeScript / NestJS parameter's decorators looking
/// for an identifier matching `wanted` anywhere in the decorator
/// argument list (e.g. `@Query('id', ParseIntPipe)`).  Conservative
/// substring match; all decorator nodes precede the parameter.
fn has_ts_decorator_argument(param: Node<'_>, code: &[u8], wanted: &[&str]) -> bool {
    let mut cur = param.prev_sibling();
    while let Some(node) = cur {
        if node.kind() == "decorator" {
            if let Some(text) = text_of(node, code) {
                for w in wanted {
                    if text.contains(w) {
                        return true;
                    }
                }
            }
        }
        // Some grammars attach decorators as children of the param.
        cur = node.prev_sibling();
    }
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        if child.kind() == "decorator" {
            if let Some(text) = text_of(child, code) {
                for w in wanted {
                    if text.contains(w) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Rust (Axum / Rocket / Actix) — read the parameter's type text and
/// look for `Path<i64>` / `Json<T>` / `Form<T>` / `Query<T>` shapes.
/// Per Hard Rule 3, bare primitives (`fn h(id: i64)` without an
/// extractor wrapper) are **not** treated as typed extractors — only
/// framework-wrapped types qualify.
fn classify_param_type_rust<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    if param.kind() != "parameter" {
        return None;
    }
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    rust_type_to_kind(&type_text)
}

fn rust_type_to_kind(t: &str) -> Option<TypeKind> {
    let stripped = t.trim();
    // Reject reference / mutability noise so `&Path<i64>` still matches
    // the wrapper detection below.
    let stripped = stripped
        .trim_start_matches('&')
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    // Only framework wrapper extractors qualify — bare primitives like
    // `i64` could be regular function parameters with no framework
    // validation gate.
    for wrap in [
        "Path",
        "Json",
        "Form",
        "Query",
        "web::Path",
        "web::Json",
        "web::Form",
        "web::Query",
        "rocket::http::uri::Origin",
    ] {
        let prefix = format!("{wrap}<");
        if let Some(rest) = stripped.strip_prefix(&prefix) {
            if let Some(inner) = rest.strip_suffix('>') {
                let inner = inner.trim();
                // Tuple extractor `Path<(i64, String)>` — first element wins.
                if inner.starts_with('(') {
                    let inside = inner.trim_start_matches('(').trim_end_matches(')');
                    let first = inside.split(',').next().unwrap_or("").trim();
                    if let Some(k) = rust_primitive_to_kind(first) {
                        return Some(k);
                    }
                }
                // Bare path generic `Path<i64>`.
                if let Some(k) = rust_primitive_to_kind(inner) {
                    return Some(k);
                }
                // `Json<T>` / `Form<T>` / `Query<T>` / `Path<T>`
                // with a custom struct type — leave None for now;
                // Phase 6 handles DTO field-level taint.
                return None;
            }
        }
    }
    None
}

fn rust_primitive_to_kind(t: &str) -> Option<TypeKind> {
    let t = t.trim();
    match t {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" => Some(TypeKind::Int),
        "f32" | "f64" => Some(TypeKind::Int),
        "bool" => Some(TypeKind::Bool),
        "String" | "&str" | "str" => Some(TypeKind::String),
        _ => None,
    }
}

/// Python (FastAPI) — recognise typed-extractor parameters via the
/// `Annotated[X, Path()/Query()/Body()/Header()/Cookie()]` shape.  Per
/// Hard Rule 3, a bare `def h(id: int)` is **not** a framework
/// extractor — the function may be a plain Python function and the
/// type annotation provides no runtime gate.
fn classify_param_type_python<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    python_type_to_kind(&type_text)
}

fn python_type_to_kind(t: &str) -> Option<TypeKind> {
    let stripped = t.trim();
    // `Annotated[int, Path()]` — only matches when one of the generic
    // args names a recognised FastAPI binding marker.  Otherwise no
    // framework gate is implied.
    if let Some(inner) = stripped
        .strip_prefix("Annotated[")
        .or_else(|| stripped.strip_prefix("typing.Annotated["))
    {
        let inside = inner.trim_end_matches(']');
        if !contains_fastapi_marker(inside) {
            return None;
        }
        let first = inside.split(',').next().unwrap_or("").trim();
        return python_primitive_to_kind(first);
    }
    None
}

fn contains_fastapi_marker(s: &str) -> bool {
    const MARKERS: &[&str] = &[
        "Path(", "Query(", "Body(", "Header(", "Cookie(", "Form(", "File(",
    ];
    MARKERS.iter().any(|m| s.contains(m))
}

fn python_primitive_to_kind(t: &str) -> Option<TypeKind> {
    let head = t.trim().split('[').next().unwrap_or(t).trim();
    match head {
        "int" => Some(TypeKind::Int),
        "bool" => Some(TypeKind::Bool),
        "float" => Some(TypeKind::Int),
        "str" => Some(TypeKind::String),
        _ => None,
    }
}

/// Check if a callee name matches any configured terminator.
pub(super) fn is_configured_terminator(
    callee: &str,
    analysis_rules: Option<&LangAnalysisRules>,
) -> bool {
    if let Some(rules) = analysis_rules {
        let callee_lower = callee.to_ascii_lowercase();
        rules
            .terminators
            .iter()
            .any(|t| callee_lower == t.to_ascii_lowercase())
    } else {
        false
    }
}

#[cfg(test)]
mod typed_extractor_tests {
    use super::{
        contains_fastapi_marker, java_type_to_kind, python_primitive_to_kind,
        python_type_to_kind, rust_primitive_to_kind, rust_type_to_kind,
    };
    use crate::ssa::type_facts::TypeKind;

    // ── Java (Spring) ────────────────────────────────────────────────────

    #[test]
    fn java_long_path_variable_maps_to_int() {
        assert_eq!(java_type_to_kind("Long"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("long"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("Integer"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("int"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("Short"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("BigInteger"), Some(TypeKind::Int));
        assert_eq!(
            java_type_to_kind("java.lang.Long"),
            Some(TypeKind::Int),
            "fully-qualified Long must still map to Int"
        );
    }

    #[test]
    fn java_string_request_param_maps_to_string() {
        assert_eq!(java_type_to_kind("String"), Some(TypeKind::String));
        assert_eq!(java_type_to_kind("CharSequence"), Some(TypeKind::String));
    }

    #[test]
    fn java_boolean_maps_to_bool() {
        assert_eq!(java_type_to_kind("Boolean"), Some(TypeKind::Bool));
        assert_eq!(java_type_to_kind("boolean"), Some(TypeKind::Bool));
    }

    #[test]
    fn java_request_body_dto_returns_none_until_phase_six() {
        // @RequestBody CreateUserDto dto — no kind today; Phase 6 will
        // return DtoObject(name) once cross-file class resolution lands.
        assert_eq!(java_type_to_kind("CreateUserDto"), None);
        assert_eq!(java_type_to_kind("List<String>"), None);
    }

    // ── Rust (Axum / Rocket / Actix) ─────────────────────────────────────

    #[test]
    fn rust_path_int_extractor_maps_to_int() {
        assert_eq!(rust_type_to_kind("Path<i64>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("Path<u32>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("Path<usize>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("Path<i32>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("web::Path<i64>"), Some(TypeKind::Int));
    }

    #[test]
    fn rust_path_tuple_first_element_wins() {
        // Path<(i64, String)> — first slot is the int extractor that
        // matters for sink suppression.
        assert_eq!(
            rust_type_to_kind("Path<(i64, String)>"),
            Some(TypeKind::Int)
        );
    }

    #[test]
    fn rust_path_string_maps_to_string() {
        assert_eq!(rust_type_to_kind("Path<String>"), Some(TypeKind::String));
        assert_eq!(rust_type_to_kind("Path<&str>"), Some(TypeKind::String));
    }

    #[test]
    fn rust_json_dto_returns_none_until_phase_six() {
        // Json<T> / Form<T> / Query<T> with a custom struct type — no
        // primitive resolution available; Phase 6 lifts to DTO.
        assert_eq!(rust_type_to_kind("Json<CreateUserDto>"), None);
        assert_eq!(rust_type_to_kind("Form<CreateUserDto>"), None);
        assert_eq!(rust_type_to_kind("Query<Filters>"), None);
    }

    /// Per Hard Rule 3, bare primitives (`fn h(id: i64)`) are NOT
    /// framework extractors — only wrapper types (`Path<i64>` etc.)
    /// imply a framework runtime gate.  Bare i64 must return None.
    #[test]
    fn rust_bare_primitives_are_not_framework_extractors() {
        assert_eq!(rust_type_to_kind("i64"), None);
        assert_eq!(rust_type_to_kind("u32"), None);
        assert_eq!(rust_type_to_kind("bool"), None);
        assert_eq!(rust_type_to_kind("String"), None);
        // `rust_primitive_to_kind` (used for tuple inner / wrapper inner)
        // remains a separate primitive-only mapping.
        assert_eq!(rust_primitive_to_kind("i64"), Some(TypeKind::Int));
        assert_eq!(rust_primitive_to_kind("bool"), Some(TypeKind::Bool));
    }

    // ── Python (FastAPI) ─────────────────────────────────────────────────

    #[test]
    fn python_bare_primitives_are_not_framework_extractors() {
        // Per Hard Rule 3: bare `def h(id: int)` is NOT a typed
        // extractor — without an `Annotated[..., Path()/Query()/Body()]`
        // wrapper, no FastAPI gate is implied.
        assert_eq!(python_type_to_kind("int"), None);
        assert_eq!(python_type_to_kind("float"), None);
        assert_eq!(python_type_to_kind("bool"), None);
        assert_eq!(python_type_to_kind("str"), None);
        // The inner primitive resolver is unchanged.
        assert_eq!(python_primitive_to_kind("int"), Some(TypeKind::Int));
    }

    #[test]
    fn python_annotated_with_fastapi_marker_qualifies() {
        assert_eq!(
            python_type_to_kind("Annotated[int, Path()]"),
            Some(TypeKind::Int)
        );
        assert_eq!(
            python_type_to_kind("typing.Annotated[int, Path()]"),
            Some(TypeKind::Int)
        );
        assert_eq!(
            python_type_to_kind("Annotated[str, Query(max_length=50)]"),
            Some(TypeKind::String)
        );
        assert_eq!(
            python_type_to_kind("Annotated[bool, Body()]"),
            Some(TypeKind::Bool)
        );
    }

    #[test]
    fn python_annotated_without_marker_returns_none() {
        // Annotated without a FastAPI binding marker is a generic
        // type-system tag — not a framework extractor.
        assert_eq!(python_type_to_kind("Annotated[int, str]"), None);
        assert_eq!(python_type_to_kind("Annotated[int, MyMeta]"), None);
    }

    #[test]
    fn python_pydantic_model_returns_none_until_phase_six() {
        assert_eq!(python_type_to_kind("CreateUser"), None);
        assert_eq!(python_type_to_kind("BaseModel"), None);
    }

    #[test]
    fn fastapi_marker_detection() {
        assert!(contains_fastapi_marker("int, Path()"));
        assert!(contains_fastapi_marker("str, Query(max_length=5)"));
        assert!(contains_fastapi_marker("bytes, File()"));
        assert!(!contains_fastapi_marker("int, str"));
    }
}
