use super::{
    AstMeta, Cfg, EdgeKind, NodeInfo, StmtKind, TaintMeta, collect_idents, connect_all,
    is_anon_fn_name, text_of,
};
use crate::labels::{DataLabel, LangAnalysisRules, classify, param_config};
use petgraph::graph::NodeIndex;
use smallvec::smallvec;
use tree_sitter::Node;

/// Extract parameter names from a function AST node.
///
/// Uses the language's `ParamConfig` to find the parameter list field
/// and extract identifiers from each parameter child.
pub(super) fn extract_param_names<'a>(func_node: Node<'a>, lang: &str, code: &'a [u8]) -> Vec<String> {
    let cfg = param_config(lang);
    let mut names = Vec::new();
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
        return names;
    };
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        // Self/this parameter (e.g. Rust's `self_parameter`)
        if cfg.self_param_kinds.contains(&child.kind()) {
            names.push("self".into());
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
                        names.push(name);
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
                names.push(txt);
            }
            // Fallback for C/C++: look for nested declarator → identifier
            if !found && child.kind() == "parameter_declaration" {
                let mut tmp = Vec::new();
                collect_idents(child, code, &mut tmp);
                if let Some(last) = tmp.pop() {
                    names.push(last);
                }
            }
            continue;
        }

        // Bare identifier children — e.g. Rust untyped closure params `|cmd|`
        // where the child is an `identifier` node, not a `parameter` wrapper.
        if child.kind() == "identifier" {
            if let Some(txt) = text_of(child, code) {
                names.push(txt);
            }
        }
    }
    names
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

/// Check if a callee name matches any configured terminator.
pub(super) fn is_configured_terminator(callee: &str, analysis_rules: Option<&LangAnalysisRules>) -> bool {
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
