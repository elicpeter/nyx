use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::prelude::*;
use tracing::debug;
use tree_sitter::{Node, Tree};

use crate::labels::{Cap, DataLabel, Kind, LangAnalysisRules, classify, lookup, param_config};
use crate::summary::FuncSummary;
use crate::symbol::{FuncKey, Lang};
use std::collections::{HashMap, HashSet};

/// -------------------------------------------------------------------------
///  Public AST‑to‑CFG data structures
/// -------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StmtKind {
    Entry,
    Exit,
    Seq,
    If,
    Loop,
    Break,
    Continue,
    Return,
    Call,
}

#[derive(Debug, Clone, Copy)]
pub enum EdgeKind {
    Seq,   // ordinary fall‑through
    True,  // `cond == true` branch
    False, // `cond == false` branch
    Back,  // back‑edge that closes a loop
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub kind: StmtKind,
    pub span: (usize, usize),     // byte offsets in the original file
    pub label: Option<DataLabel>, // taint classification if any
    pub defines: Option<String>,  // variable written by this stmt
    pub uses: Vec<String>,        // variables read
    pub callee: Option<String>,
    /// Name of the enclosing function (set during CFG construction).
    pub enclosing_func: Option<String>,
    /// Per-function call ordinal (0-based, only meaningful for Call nodes).
    pub call_ordinal: u32,
}

/// Intra‑file function summary with graph‑local node indices.
///
/// Keeps all three cap dimensions independently so that a function that is
/// *both* a source and a sink (e.g. reads env then shells out) does not
/// lose information.
#[derive(Debug, Clone)]
pub struct LocalFuncSummary {
    #[allow(dead_code)] // used for future intra-file graph traversal
    pub entry: NodeIndex,
    #[allow(dead_code)] // used for future intra-file graph traversal
    pub exit: NodeIndex,
    pub source_caps: Cap,
    pub sanitizer_caps: Cap,
    pub sink_caps: Cap,
    pub param_count: usize,
    pub param_names: Vec<String>,
    /// Conservative: `true` if *any* parameter variable reaches the return
    /// value on *any* code path.
    pub propagates_taint: bool,
    /// Which parameter indices flow to internal sinks.
    pub tainted_sink_params: Vec<usize>,
    /// Callee identifiers found inside this function body.
    pub callees: Vec<String>,
}

pub type Cfg = Graph<NodeInfo, EdgeKind>;
pub type FuncSummaries = HashMap<FuncKey, LocalFuncSummary>;

// -------------------------------------------------------------------------
//                      Utility helpers
// -------------------------------------------------------------------------

/// Return the text of a node.
#[inline]
pub(crate) fn text_of<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
    std::str::from_utf8(&code[n.start_byte()..n.end_byte()])
        .ok()
        .map(|s| s.to_string())
}

/// Walk through chained calls / member accesses to find the root receiver.
///
/// For `Runtime.getRuntime().exec(cmd)`, the receiver of `exec` is the call
/// `Runtime.getRuntime()`.  This function drills through that to return
/// `"Runtime"` — the outermost non-call object.  This lets labels like
/// `"Runtime.exec"` match correctly.
fn root_receiver_text(n: Node, lang: &str, code: &[u8]) -> Option<String> {
    match lookup(lang, n.kind()) {
        // The receiver is itself a call — drill into ITS receiver.
        // e.g. for `Runtime.getRuntime()`, the object is `Runtime`.
        Kind::CallFn | Kind::CallMethod => {
            let inner = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("receiver"))
                .or_else(|| n.child_by_field_name("function"));
            match inner {
                Some(child) => root_receiver_text(child, lang, code),
                None => text_of(n, code),
            }
        }
        _ => text_of(n, code),
    }
}

/// Return the callee identifier for the first call / method / macro inside `n`.
/// Searches recursively through all descendants.
fn first_call_ident<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                return match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .or_else(|| c.child_by_field_name("method"))
                        .or_else(|| c.child_by_field_name("name"))
                        .and_then(|f| text_of(f, code)),
                    Kind::CallMethod => {
                        let func = c
                            .child_by_field_name("method")
                            .or_else(|| c.child_by_field_name("name"))
                            .and_then(|f| text_of(f, code));
                        let recv = c
                            .child_by_field_name("object")
                            .or_else(|| c.child_by_field_name("receiver"))
                            .and_then(|f| root_receiver_text(f, lang, code));
                        match (recv, func) {
                            (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                            (_, Some(f)) => Some(f.to_string()),
                            _ => None,
                        }
                    }
                    Kind::CallMacro => c
                        .child_by_field_name("macro")
                        .and_then(|f| text_of(f, code)),
                    _ => None,
                };
            }
            _ => {
                // Recurse into children (handles nested declarators)
                if let Some(found) = first_call_ident(c, lang, code) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Build the dot-joined text of a member_expression / attribute / selector_expression.
/// E.g. for `process.env.CMD` this returns `"process.env.CMD"`.
fn member_expr_text(n: Node, code: &[u8]) -> Option<String> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => {
            let obj = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("value"))
                .and_then(|o| member_expr_text(o, code))
                .or_else(|| {
                    n.child_by_field_name("object")
                        .or_else(|| n.child_by_field_name("value"))
                        .and_then(|o| text_of(o, code))
                });
            let prop = n
                .child_by_field_name("property")
                .or_else(|| n.child_by_field_name("attribute"))
                .or_else(|| n.child_by_field_name("field"))
                .and_then(|p| text_of(p, code));
            match (obj, prop) {
                (Some(o), Some(p)) => Some(format!("{o}.{p}")),
                (_, Some(p)) => Some(p),
                (Some(o), _) => Some(o),
                _ => text_of(n, code),
            }
        }
        _ => text_of(n, code),
    }
}

/// Recursively search `n` for a member expression whose text classifies as a label.
fn first_member_label(
    n: Node,
    lang: &str,
    code: &[u8],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<DataLabel> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => {
            if let Some(full) = member_expr_text(n, code) {
                // Try the full text first, then progressively strip the last segment
                // to match rules like "process.env" from "process.env.CMD".
                let mut candidate = full.as_str();
                loop {
                    if let Some(lbl) = classify(lang, candidate, extra_labels) {
                        return Some(lbl);
                    }
                    match candidate.rsplit_once('.') {
                        Some((prefix, _)) => candidate = prefix,
                        None => break,
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = n.walk();
    for child in n.children(&mut cursor) {
        if let Some(lbl) = first_member_label(child, lang, code, extra_labels) {
            return Some(lbl);
        }
    }
    None
}

/// Return the text of the first member expression found in `n`.
fn first_member_text(n: Node, code: &[u8]) -> Option<String> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => member_expr_text(n, code),
        _ => {
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                if let Some(t) = first_member_text(child, code) {
                    return Some(t);
                }
            }
            None
        }
    }
}

/// Check whether any descendant of `n` is a call expression.
fn has_call_descendant(n: Node, lang: &str) -> bool {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return true,
            _ => {
                if has_call_descendant(c, lang) {
                    return true;
                }
            }
        }
    }
    false
}

/// Recursively collect every identifier that occurs inside `n`.
///
/// Recognises `identifier` (most languages), `variable_name` (PHP),
/// `field_identifier` (Go), and `property_identifier` (JS/TS).
fn collect_idents(n: Node, code: &[u8], out: &mut Vec<String>) {
    match n.kind() {
        "identifier" | "field_identifier" | "property_identifier" => {
            if let Some(txt) = text_of(n, code) {
                out.push(txt);
            }
        }
        // PHP: $x is `variable_name` → `$` + `name`. Use the whole text minus `$`.
        "variable_name" => {
            if let Some(txt) = text_of(n, code) {
                out.push(txt.trim_start_matches('$').to_string());
            }
        }
        _ => {
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                collect_idents(ch, code, out);
            }
        }
    }
}

/// Return `(defines, uses)` for the AST fragment `ast`.
fn def_use(ast: Node, lang: &str, code: &[u8]) -> (Option<String>, Vec<String>) {
    match lookup(lang, ast.kind()) {
        // Declaration wrappers (let, var, short_var_declaration, etc.)
        Kind::CallWrapper => {
            let mut defs = None;
            let mut uses = Vec::new();

            // Try direct field names first (Rust `let_declaration`, Go `short_var_declaration`)
            let def_node = ast
                .child_by_field_name("pattern")
                .or_else(|| ast.child_by_field_name("name"))
                .or_else(|| ast.child_by_field_name("left"));

            let val_node = ast
                .child_by_field_name("value")
                .or_else(|| ast.child_by_field_name("right"));

            if def_node.is_some() || val_node.is_some() {
                if let Some(pat) = def_node {
                    let mut tmp = Vec::<String>::new();
                    collect_idents(pat, code, &mut tmp);
                    defs = tmp.into_iter().next();
                }
                if let Some(val) = val_node {
                    collect_idents(val, code, &mut uses);
                }
            } else {
                // Try nested declarator pattern (JS/TS `lexical_declaration` → `variable_declarator`,
                // Java `local_variable_declaration` → `variable_declarator`,
                // C/C++ `declaration` → `init_declarator`,
                // Python/Ruby `expression_statement` → `assignment`)
                let mut cursor = ast.walk();
                for child in ast.children(&mut cursor) {
                    let child_name = child
                        .child_by_field_name("name")
                        .or_else(|| child.child_by_field_name("declarator"))
                        .or_else(|| child.child_by_field_name("left"));
                    let child_value = child
                        .child_by_field_name("value")
                        .or_else(|| child.child_by_field_name("right"));

                    // Only treat this child as a declarator if it has BOTH a name
                    // and a value (or at least a value). This prevents method_invocation
                    // nodes (which have a `name` field) from being misinterpreted.
                    if child_value.is_some() {
                        if let Some(name_node) = child_name
                            && defs.is_none()
                        {
                            let mut tmp = Vec::<String>::new();
                            collect_idents(name_node, code, &mut tmp);
                            defs = tmp.into_iter().next();
                        }
                        if let Some(val_node) = child_value {
                            collect_idents(val_node, code, &mut uses);
                        }
                    }
                }

                // Fallback: if still nothing found, collect all idents as uses.
                // This handles expression_statement wrappers.
                if defs.is_none() && uses.is_empty() {
                    collect_idents(ast, code, &mut uses);
                }
            }
            (defs, uses)
        }

        // Plain assignment `x = y`
        Kind::Assignment => {
            let mut defs = None;
            let mut uses = Vec::new();
            if let Some(lhs) = ast.child_by_field_name("left") {
                let mut tmp = Vec::<String>::new();
                collect_idents(lhs, code, &mut tmp);
                defs = tmp.pop();
            }
            if let Some(rhs) = ast.child_by_field_name("right") {
                collect_idents(rhs, code, &mut uses);
            }
            (defs, uses)
        }

        // everything else – no definition, but may read vars
        _ => {
            let mut uses = Vec::new();
            collect_idents(ast, code, &mut uses);
            (None, uses)
        }
    }
}

/// Create a node in one short borrow and optionally attach a taint label.
#[allow(clippy::too_many_arguments)]
fn push_node<'a>(
    g: &mut Cfg,
    kind: StmtKind,
    ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
    call_ordinal: u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> NodeIndex {
    /* ── 1.  IDENTIFIER EXTRACTION ─────────────────────────────────────── */

    // Primary guess (varies by AST kind)
    let mut text = match lookup(lang, ast.kind()) {
        // plain `foo(bar)` style call
        Kind::CallFn => ast
            .child_by_field_name("function")
            .or_else(|| ast.child_by_field_name("method"))
            .or_else(|| ast.child_by_field_name("name"))
            .and_then(|n| text_of(n, code))
            .unwrap_or_default(),

        // method / UFCS call  `recv.method()`  or  `Type::func()`
        Kind::CallMethod => {
            let func = ast
                .child_by_field_name("method")
                .or_else(|| ast.child_by_field_name("name"))
                .and_then(|n| text_of(n, code));
            let recv = ast
                .child_by_field_name("object")
                .or_else(|| ast.child_by_field_name("receiver"))
                .and_then(|n| root_receiver_text(n, lang, code));
            match (recv, func) {
                (Some(r), Some(f)) => format!("{r}.{f}"),
                (_, Some(f)) => f,
                _ => String::new(),
            }
        }

        // `my_macro!(…)`
        Kind::CallMacro => ast
            .child_by_field_name("macro")
            .and_then(|n| text_of(n, code))
            .unwrap_or_default(),

        // everything else – fallback to raw slice
        _ => text_of(ast, code).unwrap_or_default(),
    };

    // If this is a declaration/expression wrapper or an assignment that
    // *contains* a call, prefer the first inner call identifier instead of
    // the whole line.
    if matches!(
        lookup(lang, ast.kind()),
        Kind::CallWrapper | Kind::Assignment
    ) && let Some(inner) = first_call_ident(ast, lang, code)
    {
        text = inner;
    }

    /* ── 2.  LABEL LOOK-UP  ───────────────────────────────────────────── */

    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut label = classify(lang, &text, extra);

    // For assignments like `element.innerHTML = value`, the inner-call heuristic
    // above may have overridden `text` with a call on the RHS (e.g. getElementById).
    // If that didn't produce a label, check the LHS property name — it may be a
    // sink like `innerHTML`.
    //
    // This covers both direct `Kind::Assignment` nodes and `Kind::CallWrapper`
    // nodes (expression_statement) that wrap an assignment.
    if label.is_none() {
        let assign_node = if matches!(lookup(lang, ast.kind()), Kind::Assignment) {
            Some(ast)
        } else if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
            // Walk children to find a nested assignment_expression
            let mut cursor = ast.walk();
            ast.children(&mut cursor)
                .find(|c| matches!(lookup(lang, c.kind()), Kind::Assignment))
        } else {
            None
        };

        if let Some(assign) = assign_node
            && let Some(lhs) = assign.child_by_field_name("left")
        {
            // Try full member expression first (e.g. "location.href") — more
            // specific and avoids false positives on `a.href`.
            if let Some(full) = member_expr_text(lhs, code) {
                label = classify(lang, &full, extra);
            }
            // Fall back to property-only (e.g. "innerHTML") for sinks that
            // don't need object context.
            if label.is_none()
                && let Some(prop) = lhs.child_by_field_name("property")
                && let Some(prop_text) = text_of(prop, code)
            {
                label = classify(lang, &prop_text, extra);
            }
        }
    }

    // For declarations/assignments whose RHS is a member expression (not a call),
    // try to classify the member expression text as a source.
    // This handles `var x = process.env.CMD` (JS), `os.environ["KEY"]` (Python),
    // and similar property-access-based source patterns.
    if label.is_none()
        && matches!(
            lookup(lang, ast.kind()),
            Kind::CallWrapper | Kind::Assignment
        )
        && let Some(found) = first_member_label(ast, lang, code, extra)
    {
        label = Some(found);
        // Update text so the callee name reflects the source
        if let Some(member_text) = first_member_text(ast, code) {
            text = member_text;
        }
    }

    let span = (ast.start_byte(), ast.end_byte());

    /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

    let (defines, uses) = def_use(ast, lang, code);

    let callee = if kind == StmtKind::Call {
        Some(text.clone())
    } else {
        None
    };

    let idx = g.add_node(NodeInfo {
        kind,
        span,
        label,
        defines,
        uses,
        callee,
        enclosing_func: enclosing_func.map(|s| s.to_string()),
        call_ordinal,
    });

    debug!(
        target: "cfg",
        "node {} ← {:?} txt=`{}` span={:?} label={:?}",
        idx.index(),
        kind,
        text,
        span,
        label
    );
    idx
}

/// Extract parameter names from a function AST node.
///
/// Uses the language's `ParamConfig` to find the parameter list field
/// and extract identifiers from each parameter child.
fn extract_param_names<'a>(func_node: Node<'a>, lang: &str, code: &'a [u8]) -> Vec<String> {
    let cfg = param_config(lang);
    let mut names = Vec::new();
    let Some(params) = func_node.child_by_field_name(cfg.params_field) else {
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
                    if let Some(first) = tmp.into_iter().next() {
                        names.push(first);
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
    }
    names
}

/// Check if a callee name matches any configured terminator.
fn is_configured_terminator(callee: &str, analysis_rules: Option<&LangAnalysisRules>) -> bool {
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

/// Add the same edge (of the same kind) from every node in `froms` to `to`.
#[inline]
fn connect_all(g: &mut Cfg, froms: &[NodeIndex], to: NodeIndex, kind: EdgeKind) {
    for &f in froms {
        debug!(target: "cfg", "edge {} → {} ({:?})", f.index(), to.index(), kind);
        g.add_edge(f, to, kind);
    }
}

// -------------------------------------------------------------------------
//    The recursive *work‑horse* that converts an AST node into a CFG slice.
//    Returns the set of *exit* nodes that need to be wired further.
// -------------------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
fn build_sub<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex], // predecessor frontier
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
    file_path: &str,
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
    break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
) -> Vec<NodeIndex> {
    match lookup(lang, ast.kind()) {
        // ─────────────────────────────────────────────────────────────────
        //  IF‑/ELSE: two branches that re‑merge afterwards
        // ─────────────────────────────────────────────────────────────────
        Kind::If => {
            // Condition node
            let cond = push_node(
                g,
                StmtKind::If,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, cond, EdgeKind::Seq);

            // Locate then & else blocks using field-based lookup first,
            // then positional fallback (Rust uses positional blocks).
            let (then_block, else_block) = {
                let field_then = ast
                    .child_by_field_name("consequence")
                    .or_else(|| ast.child_by_field_name("body"));
                let field_else = ast.child_by_field_name("alternative");

                if field_then.is_some() || field_else.is_some() {
                    (field_then, field_else)
                } else {
                    // Fallback: positional block children (Rust `if_expression`)
                    let mut cursor = ast.walk();
                    let blocks: Vec<_> = ast
                        .children(&mut cursor)
                        .filter(|n| lookup(lang, n.kind()) == Kind::Block)
                        .collect();
                    (blocks.first().copied(), blocks.get(1).copied())
                }
            };

            // THEN branch
            let then_first_node = NodeIndex::new(g.node_count());
            let then_exits = if let Some(b) = then_block {
                let exits = build_sub(
                    b,
                    &[cond],
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                );
                // Add True edge from condition to first node of then-branch.
                // We use the first node created (by index) rather than the
                // exit, because the branch may terminate (return/break) and
                // have no exits.
                if then_first_node.index() < g.node_count() {
                    connect_all(g, &[cond], then_first_node, EdgeKind::True);
                } else if let Some(&first) = exits.first() {
                    connect_all(g, &[cond], first, EdgeKind::True);
                }
                exits
            } else {
                vec![cond]
            };

            // ELSE branch
            let else_first_node = NodeIndex::new(g.node_count());
            let else_exits = if let Some(b) = else_block {
                let exits = build_sub(
                    b,
                    &[cond],
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                );
                if else_first_node.index() < g.node_count() {
                    connect_all(g, &[cond], else_first_node, EdgeKind::False);
                } else if let Some(&first) = exits.first() {
                    connect_all(g, &[cond], first, EdgeKind::False);
                }
                exits
            } else {
                // No explicit else → if the then-branch falls through
                // (non-empty exits), the false branch merges with those exits.
                // If the then-branch terminates (break/return/continue →
                // empty exits), the false branch flows from the condition
                // to whatever comes next.
                if then_exits.is_empty() {
                    vec![cond]
                } else {
                    if let Some(&first) = then_exits.first() {
                        connect_all(g, &[cond], first, EdgeKind::False);
                    }
                    then_exits.clone()
                }
            };

            // Frontier = union of both branches
            then_exits.into_iter().chain(else_exits).collect()
        }

        Kind::InfiniteLoop => {
            // Synthetic header node
            let header = push_node(
                g,
                StmtKind::Loop,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, header, EdgeKind::Seq);

            // Fresh break/continue targets scoped to this loop
            let mut loop_breaks = Vec::new();
            let mut loop_continues = Vec::new();

            // The body is the single `block` child
            let body = ast.child_by_field_name("body").expect("loop without body");
            let body_exits = build_sub(
                body,
                &[header],
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                &mut loop_breaks,
                &mut loop_continues,
            );

            // Back-edge from every linear exit to header
            for &e in &body_exits {
                connect_all(g, &[e], header, EdgeKind::Back);
            }
            // Wire continue targets as back edges to header
            for &c in &loop_continues {
                connect_all(g, &[c], header, EdgeKind::Back);
            }
            // Break targets become exits of the loop
            if loop_breaks.is_empty() {
                // No break → infinite loop; header is the only exit for
                // downstream code (fallthrough semantics)
                vec![header]
            } else {
                loop_breaks
            }
        }

        // ─────────────────────────────────────────────────────────────────
        //  WHILE / FOR: classic loop with a back edge.
        // ─────────────────────────────────────────────────────────────────
        Kind::While | Kind::For => {
            let header = push_node(
                g,
                StmtKind::Loop,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, header, EdgeKind::Seq);

            // Fresh break/continue targets scoped to this loop
            let mut loop_breaks = Vec::new();
            let mut loop_continues = Vec::new();

            // Body = first (and usually only) block child.
            let body = ast
                .child_by_field_name("body")
                .or_else(|| {
                    let mut c = ast.walk();
                    ast.children(&mut c)
                        .find(|n| lookup(lang, n.kind()) == Kind::Block)
                })
                .expect("loop without body");

            let body_exits = build_sub(
                body,
                &[header],
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                &mut loop_breaks,
                &mut loop_continues,
            );

            // Back‑edge for every linear exit → header.
            for &e in &body_exits {
                connect_all(g, &[e], header, EdgeKind::Back);
            }
            // Wire continue targets as back edges to header
            for &c in &loop_continues {
                connect_all(g, &[c], header, EdgeKind::Back);
            }
            // Falling out of the loop = header’s false branch +
            // any break targets that exit the loop.
            let mut exits = vec![header];
            exits.extend(loop_breaks);
            exits
        }

        // ─────────────────────────────────────────────────────────────────
        //  Control-flow sinks (return / break / continue).
        // ─────────────────────────────────────────────────────────────────
        Kind::Return => {
            if has_call_descendant(ast, lang) {
                // Return-call bug fix: emit a Call node BEFORE the Return so
                // that callee labels (source/sanitizer/sink) are applied.
                let ord = *call_ordinal;
                *call_ordinal += 1;
                let call_idx = push_node(
                    g,
                    StmtKind::Call,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    ord,
                    analysis_rules,
                );
                connect_all(g, preds, call_idx, EdgeKind::Seq);
                let ret = push_node(
                    g,
                    StmtKind::Return,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, &[call_idx], ret, EdgeKind::Seq);
                Vec::new()
            } else {
                let ret = push_node(
                    g,
                    StmtKind::Return,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, preds, ret, EdgeKind::Seq);
                Vec::new() // terminates this path
            }
        }
        Kind::Break => {
            let brk = push_node(
                g,
                StmtKind::Break,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, brk, EdgeKind::Seq);
            break_targets.push(brk);
            Vec::new()
        }
        Kind::Continue => {
            let cont = push_node(
                g,
                StmtKind::Continue,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, cont, EdgeKind::Seq);
            continue_targets.push(cont);
            Vec::new()
        }

        // ─────────────────────────────────────────────────────────────────
        //  BLOCK: statements execute sequentially
        // ─────────────────────────────────────────────────────────────────
        Kind::SourceFile | Kind::Block => {
            let mut cursor = ast.walk();
            let mut frontier = preds.to_vec();
            // Track the last frontier before a function emptied it — used to
            // keep subsequent functions reachable.
            let mut last_live_frontier = preds.to_vec();
            let mut prev_was_preproc = false;
            for child in ast.children(&mut cursor) {
                let child_is_fn = lookup(lang, child.kind()) == Kind::Function;

                // At module / source-file level, each function definition is an
                // independent entry point — it must always be reachable from the
                // file-level predecessors.  Without this, a preceding function
                // that ends with `return` (frontier = []) would leave subsequent
                // functions disconnected from the graph.
                //
                // Similarly, when a preprocessor block (`#ifdef ... #endif`)
                // contains an `if/else` whose else branch is on the other side
                // of the `#endif`, tree-sitter parses a dangling else that
                // empties the frontier.  The code after the preproc block should
                // remain reachable.
                let child_preds = if frontier.is_empty() && (child_is_fn || prev_was_preproc) {
                    last_live_frontier.clone()
                } else {
                    frontier.clone()
                };

                let child_exits = build_sub(
                    child,
                    &child_preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                );

                let is_preproc = child.kind().starts_with("preproc_");
                if !child_exits.is_empty() {
                    last_live_frontier = child_exits.clone();
                }
                frontier = child_exits;
                prev_was_preproc = is_preproc;
            }
            frontier
        }

        // Function item – create a header and dive into its body
        Kind::Function => {
            // 1) create a header node for this fn
            // Try "name" first (most languages), then "declarator" (C/C++)
            let fn_name = ast
                .child_by_field_name("name")
                .or_else(|| ast.child_by_field_name("declarator"))
                .and_then(|n| {
                    // For C/C++ function_declarator, extract just the identifier
                    let mut tmp = Vec::new();
                    collect_idents(n, code, &mut tmp);
                    tmp.into_iter().next()
                })
                .unwrap_or_else(|| "<anon>".to_string());
            let entry_idx = push_node(
                g,
                StmtKind::Seq,
                ast,
                lang,
                code,
                Some(&fn_name),
                0,
                analysis_rules,
            );
            connect_all(g, preds, entry_idx, EdgeKind::Seq);

            // 1b) extract parameter names
            let param_names = extract_param_names(ast, lang, code);
            let param_count = param_names.len();

            // 2) build its body with a fresh call ordinal counter for this function scope
            // Snapshot the current node count so we can iterate only over nodes
            // created within this function (avoids O(N²) scan of the full graph).
            let fn_first_node: NodeIndex = NodeIndex::new(g.node_count());
            let body = ast.child_by_field_name("body").expect("fn w/o body");
            let mut fn_call_ordinal: u32 = 0;
            let mut fn_breaks = Vec::new();
            let mut fn_continues = Vec::new();
            let body_exits = build_sub(
                body,
                &[entry_idx],
                g,
                lang,
                code,
                summaries,
                file_path,
                Some(&fn_name),
                &mut fn_call_ordinal,
                analysis_rules,
                &mut fn_breaks,
                &mut fn_continues,
            );

            // ───── 3) light-weight dataflow ──────────────────────────────────────
            //
            // Sweep every node inside this function’s span.  Track:
            //  • which cap bits each variable carries (var_taint)
            //  • independent source / sanitizer / sink caps for the function
            //  • which params flow to sinks (tainted_sink_params)
            //  • whether any param reaches a return value (propagates_taint)
            //  • all callees
            let mut var_taint = HashMap::<String, Cap>::new();
            let mut node_bits = HashMap::<NodeIndex, Cap>::new();
            let mut fn_src_bits = Cap::empty();
            let mut fn_sani_bits = Cap::empty();
            let mut fn_sink_bits = Cap::empty();
            let mut callees = Vec::<String>::new();
            let mut tainted_sink_params: Vec<usize> = Vec::new();

            let param_set: HashSet<&str> = param_names.iter().map(|s| s.as_str()).collect();

            // Iterate only over nodes created within this function scope
            // (entry_idx .. current end) instead of the entire graph.
            let fn_node_range = entry_idx.index()..g.node_count();
            for raw in fn_node_range {
                let idx = NodeIndex::new(raw);
                let info = &g[idx];

                // collect callee names
                if let Some(callee) = &info.callee
                    && !callees.contains(callee)
                {
                    callees.push(callee.clone());
                }

                // record explicit label caps (all three independently)
                if let Some(DataLabel::Source(bits)) = info.label {
                    fn_src_bits |= bits;
                }
                if let Some(DataLabel::Sanitizer(bits)) = info.label {
                    fn_sani_bits |= bits;
                }
                if let Some(DataLabel::Sink(bits)) = info.label {
                    fn_sink_bits |= bits;

                    // check whether any param flows to this sink
                    for u in &info.uses {
                        if let Some(pos) = param_names.iter().position(|p| p == u)
                            && !tainted_sink_params.contains(&pos)
                        {
                            tainted_sink_params.push(pos);
                        }
                    }
                }

                //  a) incoming taint from any vars we read
                let mut in_bits = Cap::empty();
                for u in &info.uses {
                    if let Some(b) = var_taint.get(u) {
                        in_bits |= *b;
                    }
                }

                //  b) apply this node’s own label
                let mut out_bits = in_bits;
                if let Some(lab) = &info.label {
                    match *lab {
                        DataLabel::Source(bits) => out_bits |= bits,
                        DataLabel::Sanitizer(bits) => out_bits &= !bits,
                        DataLabel::Sink(_) => { /* no-op */ }
                    }
                }

                //  c) write it back to the var we define (if any)
                if let Some(def) = &info.defines {
                    if out_bits.is_empty() {
                        var_taint.remove(def);
                    } else {
                        var_taint.insert(def.clone(), out_bits);
                    }
                }

                //  d) stash it for later
                node_bits.insert(idx, out_bits);
            }

            // fold in explicit returns
            for (&idx, &bits) in &node_bits {
                if g[idx].kind == StmtKind::Return {
                    fn_src_bits |= bits;
                }
            }

            // implicit returns via fall-through exits
            for &pred in &body_exits {
                if let Some(&bits) = node_bits.get(&pred) {
                    fn_src_bits |= bits;
                }
            }

            // ───── propagates_taint ──────────────────────────────────────────────
            //
            // A function propagates taint when a parameter variable reaches a
            // return value (explicit or implicit) while still carrying taint bits.
            //
            // We approximate this: if any param name still appears in `var_taint`
            // at any return/exit node, we conservatively say yes.
            let propagates = {
                let mut prop = false;

                // check explicit returns
                for &idx in node_bits.keys() {
                    if g[idx].kind == StmtKind::Return {
                        for u in &g[idx].uses {
                            if param_set.contains(u.as_str()) {
                                prop = true;
                            }
                            // also check if the var was derived from a param
                            if let Some(bits) = var_taint.get(u)
                                && !bits.is_empty()
                                && param_names.iter().any(|p| var_taint.contains_key(p))
                            {
                                prop = true;
                            }
                        }
                    }
                }

                // check implicit returns (fall-through body exits)
                for &exit_pred in &body_exits {
                    let info = &g[exit_pred];
                    for u in &info.uses {
                        if param_set.contains(u.as_str()) {
                            prop = true;
                        }
                    }
                    if let Some(def) = &info.defines
                        && param_set.contains(def.as_str())
                    {
                        prop = true;
                    }
                }

                prop
            };

            tainted_sink_params.sort_unstable();
            tainted_sink_params.dedup();

            /* ───── 4) synthesise an explicit exit-node and wire it up ──────────── */
            let exit_idx = g.add_node(NodeInfo {
                kind: StmtKind::Return,
                span: (ast.start_byte(), ast.end_byte()),
                label: None,
                defines: None,
                uses: Vec::new(),
                callee: None,
                enclosing_func: Some(fn_name.clone()),
                call_ordinal: 0,
            });
            // Wire body exits (fall-through) to the exit node.
            for &b in &body_exits {
                connect_all(g, &[b], exit_idx, EdgeKind::Seq);
            }
            // Also wire any Return nodes inside the function to the exit
            // node.  `build_sub` for Kind::Return returns Vec::new() (no
            // exits), so those nodes are dead-ends in the graph.  Without
            // this edge, the synthetic exit node is unreachable whenever
            // the function body ends with a `return` statement, which
            // disconnects all subsequent functions at the module level.
            //
            // Only scan nodes created within this function scope.
            for raw in fn_first_node.index()..g.node_count() {
                let idx = NodeIndex::new(raw);
                let info = &g[idx];
                if info.kind == StmtKind::Return
                    && idx != exit_idx
                    && !g.contains_edge(idx, exit_idx)
                {
                    connect_all(g, &[idx], exit_idx, EdgeKind::Seq);
                }
            }

            /* ───── 5) store the rich summary ──────────────────────────────────── */
            let key = FuncKey {
                lang: Lang::from_slug(lang).unwrap_or(Lang::Rust),
                namespace: file_path.to_owned(),
                name: fn_name.clone(),
                arity: Some(param_count),
            };
            summaries.insert(
                key,
                LocalFuncSummary {
                    entry: entry_idx,
                    exit: exit_idx,
                    source_caps: fn_src_bits,
                    sanitizer_caps: fn_sani_bits,
                    sink_caps: fn_sink_bits,
                    param_count,
                    param_names,
                    propagates_taint: propagates,
                    tainted_sink_params,
                    callees,
                },
            );

            vec![exit_idx]
        }

        // Statements that **may** contain a call ---------------------------------
        Kind::CallWrapper => {
            let mut cursor = ast.walk();

            if let Some(inner) = ast.children(&mut cursor).find(|c| {
                matches!(
                    lookup(lang, c.kind()),
                    Kind::InfiniteLoop | Kind::While | Kind::For | Kind::If
                )
            }) {
                return build_sub(
                    inner,
                    preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                );
            }

            let has_call = has_call_descendant(ast, lang);

            let kind = if has_call {
                StmtKind::Call
            } else {
                StmtKind::Seq
            };
            let ord = if kind == StmtKind::Call {
                let o = *call_ordinal;
                *call_ordinal += 1;
                o
            } else {
                0
            };
            let node = push_node(
                g,
                kind,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            connect_all(g, preds, node, EdgeKind::Seq);

            // If the callee is a configured terminator, treat as a dead end
            if kind == StmtKind::Call
                && let Some(callee) = &g[node].callee
                && is_configured_terminator(callee, analysis_rules)
            {
                return Vec::new();
            }
            vec![node]
        }

        // Direct call nodes (Ruby `call`, Python `call`, etc. when they appear
        // as direct children of a block rather than wrapped in expression_statement)
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
            let ord = *call_ordinal;
            *call_ordinal += 1;
            let n = push_node(
                g,
                StmtKind::Call,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            connect_all(g, preds, n, EdgeKind::Seq);

            // If the callee is a configured terminator, treat as a dead end
            if let Some(callee) = &g[n].callee
                && is_configured_terminator(callee, analysis_rules)
            {
                return Vec::new();
            }
            vec![n]
        }

        // Assignment that may contain a call (Python `x = os.getenv(...)`, Ruby `x = gets()`)
        Kind::Assignment => {
            let has_call = has_call_descendant(ast, lang);
            let kind = if has_call {
                StmtKind::Call
            } else {
                StmtKind::Seq
            };
            let ord = if kind == StmtKind::Call {
                let o = *call_ordinal;
                *call_ordinal += 1;
                o
            } else {
                0
            };
            let n = push_node(
                g,
                kind,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            connect_all(g, preds, n, EdgeKind::Seq);
            vec![n]
        }

        // Trivia we drop completely ---------------------------------------------
        Kind::Trivia => preds.to_vec(),

        // ─────────────────────────────────────────────────────────────────
        //  Every other node = simple sequential statement
        // ─────────────────────────────────────────────────────────────────
        _ => {
            let n = push_node(
                g,
                StmtKind::Seq,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, n, EdgeKind::Seq);
            vec![n]
        }
    }
}

// -------------------------------------------------------------------------
//  === PUBLIC ENTRY POINT =================================================
// -------------------------------------------------------------------------

/// Build an intraprocedural CFG and return (graph, entry_node).
///
/// * Walks the Tree‑Sitter AST.
/// * Creates `StmtKind::*` nodes only for *statement‑level* constructs to keep
///   the graph compact.
/// * Wires a synthetic `Entry` node in front and a synthetic `Exit` node after
///   all real sinks.
pub(crate) fn build_cfg<'a>(
    tree: &'a Tree,
    code: &'a [u8],
    lang: &str,
    file_path: &str,
    analysis_rules: Option<&LangAnalysisRules>,
) -> (Cfg, NodeIndex, FuncSummaries) {
    debug!(target: "cfg", "Building CFG for {:?}", tree.root_node());

    let mut g: Cfg = Graph::with_capacity(128, 256);
    let mut summaries = FuncSummaries::new();
    let entry = g.add_node(NodeInfo {
        kind: StmtKind::Entry,
        span: (0, 0),
        label: None,
        defines: None,
        uses: Vec::new(),
        callee: None,
        enclosing_func: None,
        call_ordinal: 0,
    });
    let exit = g.add_node(NodeInfo {
        kind: StmtKind::Exit,
        span: (code.len(), code.len()),
        label: None,
        defines: None,
        uses: Vec::new(),
        callee: None,
        enclosing_func: None,
        call_ordinal: 0,
    });

    // Build the body below the synthetic ENTRY.
    let mut top_ordinal: u32 = 0;
    let mut top_breaks = Vec::new();
    let mut top_continues = Vec::new();
    let exits = build_sub(
        tree.root_node(),
        &[entry],
        &mut g,
        lang,
        code,
        &mut summaries,
        file_path,
        None,
        &mut top_ordinal,
        analysis_rules,
        &mut top_breaks,
        &mut top_continues,
    );
    debug!(target: "cfg", "exits: {:?}", exits);
    // Wire every real exit to our synthetic EXIT node.
    for e in exits {
        connect_all(&mut g, &[e], exit, EdgeKind::Seq);
    }

    debug!(target: "cfg", "CFG DONE — nodes: {}, edges: {}", g.node_count(), g.edge_count());

    if cfg!(debug_assertions) {
        // List every node
        for idx in g.node_indices() {
            debug!(target: "cfg", "  node {:>3}: {:?}", idx.index(), g[idx]);
        }
        // List every edge
        for e in g.edge_references() {
            debug!(
                target: "cfg",
                "  edge {:>3} → {:<3} ({:?})",
                e.source().index(),
                e.target().index(),
                e.weight()
            );
        }

        // Reachability check
        let mut reachable: HashSet<NodeIndex> = Default::default();
        let mut bfs = Bfs::new(&g, entry);
        while let Some(nx) = bfs.next(&g) {
            reachable.insert(nx);
        }
        debug!(
            target: "cfg",
            "reachable nodes: {}/{}",
            reachable.len(),
            g.node_count()
        );
        if reachable.len() != g.node_count() {
            let unreachable: Vec<_> = g
                .node_indices()
                .filter(|i| !reachable.contains(i))
                .collect();
            debug!(target: "cfg", "‼︎ unreachable nodes: {:?}", unreachable);
        }

        // (Optional) Dominator tree sanity check
        let doms: Dominators<_> = simple_fast(&g, entry);
        debug!(target: "cfg", "dominator tree computed (len = {:?})", doms);
    }

    (g, entry, summaries)
}

/// Convert the graph‑local `FuncSummaries` into serialisable [`FuncSummary`]
/// values suitable for cross‑file persistence.
pub(crate) fn export_summaries(
    summaries: &FuncSummaries,
    file_path: &str,
    lang: &str,
) -> Vec<FuncSummary> {
    summaries
        .iter()
        .map(|(key, local)| FuncSummary {
            name: key.name.clone(),
            file_path: file_path.to_owned(),
            lang: lang.to_owned(),
            param_count: local.param_count,
            param_names: local.param_names.clone(),
            source_caps: local.source_caps.bits(),
            sanitizer_caps: local.sanitizer_caps.bits(),
            sink_caps: local.sink_caps.bits(),
            propagates_taint: local.propagates_taint,
            tainted_sink_params: local.tainted_sink_params.clone(),
            callees: local.callees.clone(),
        })
        .collect()
}

// pub(crate) fn dump_cfg(g: &Cfg) {
//     debug!(target: "taint", "CFG DUMP: nodes = {}, edges = {}", g.node_count(), g.edge_count());
//     for idx in g.node_indices() {
//         debug!(target: "taint", "  node {:>3}: {:?}", idx.index(), g[idx]);
//     }
//     for e in g.edge_references() {
//         debug!(
//             target: "taint",
//             "  edge {:>3} → {:<3} ({:?})",
//             e.source().index(),
//             e.target().index(),
//             e.weight()
//         );
//     }
// }
