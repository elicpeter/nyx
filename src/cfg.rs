#![allow(
    clippy::collapsible_if,
    clippy::let_and_return,
    clippy::unnecessary_map_or
)]

use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::prelude::*;
use tracing::debug;
use tree_sitter::{Node, Tree};

use crate::labels::{
    Cap, DataLabel, Kind, LangAnalysisRules, classify, classify_all, classify_gated_sink, lookup,
    param_config,
};
use crate::summary::FuncSummary;
use crate::symbol::{FuncKey, Lang};
use smallvec::SmallVec;
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
    Seq,       // ordinary fall‑through
    True,      // `cond == true` branch
    False,     // `cond == false` branch
    Back,      // back‑edge that closes a loop
    Exception, // from call/throw inside try body → catch entry
}

/// Maximum number of identifiers to store from a condition expression.
const MAX_COND_VARS: usize = 8;
const MAX_CONDITION_TEXT_LEN: usize = 256;

/// Binary operator extracted from the AST.
///
/// Only set when the SSA assignment maps one-to-one to a single
/// binary expression. Left `None` for nested, compound, or boolean
/// expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    LeftShift,
    RightShift,
    // Comparison
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub kind: StmtKind,
    pub span: (usize, usize), // byte offsets in the original file
    pub labels: SmallVec<[DataLabel; 2]>, // taint classifications (multi-label)
    pub defines: Option<String>, // variable written by this stmt
    /// Additional variable definitions from destructuring patterns.
    /// E.g. `const { a, b, c } = source()` → defines="a", extra_defines=["b", "c"].
    pub extra_defines: Vec<String>,
    pub uses: Vec<String>, // variables read
    pub callee: Option<String>,
    /// For `CallMethod` nodes: the receiver identifier (e.g. `tainted` in
    /// `tainted.foo()`).  `None` for non-method calls or complex receivers
    /// (member expressions, call expressions, etc.).
    pub receiver: Option<String>,
    /// Name of the enclosing function (set during CFG construction).
    pub enclosing_func: Option<String>,
    /// Per-function call ordinal (0-based, only meaningful for Call nodes).
    pub call_ordinal: u32,
    /// For If nodes: raw condition text (truncated to 256 chars). None for non-If nodes.
    pub condition_text: Option<String>,
    /// For If nodes: identifiers referenced in the condition (sorted, deduped, max 8).
    pub condition_vars: Vec<String>,
    /// For If nodes: whether the condition has a leading negation (`!` / `not`).
    pub condition_negated: bool,
    /// Per-argument identifiers for Call nodes. Each inner Vec holds the
    /// identifiers from one argument expression, in parameter-position order.
    /// Empty for non-call nodes or when argument boundaries can't be determined.
    pub arg_uses: Vec<Vec<String>>,
    /// For gated sinks: which argument positions carry the tainted payload.
    /// When `Some`, only variables from these `arg_uses` positions are checked
    /// for taint.  `None` = all arguments are payload (default).
    pub sink_payload_args: Option<Vec<usize>>,
    /// True when this is a Call node whose argument list contains only
    /// syntactic literal values (strings, numbers, booleans, null/nil,
    /// arrays/lists/tuples of literals). Also true for zero-argument calls
    /// (no argument-carried taint vector).
    ///
    /// This flag is scoped to taint-style sink suppression: it indicates
    /// that no attacker-controlled data enters through the immediate
    /// arguments. It does NOT mean the call is "safe" in general — other
    /// detectors (resource lifecycle, structural analysis) may still
    /// legitimately flag these calls.
    pub all_args_literal: bool,
    /// True for synthetic catch-parameter nodes injected at catch clause entry.
    /// The taint transfer function uses this to conservatively taint the
    /// caught exception variable.
    pub catch_param: bool,
    /// Raw text of a constant/literal RHS when this node defines a variable
    /// from a syntactic literal with no uses. Used by SSA constant propagation.
    pub const_text: Option<String>,
    /// For Call nodes: the callee name of the call expression wrapping each
    /// argument (per-position, matching arg_uses). For Assignment sink nodes:
    /// the RHS call callee at position 0 (if the RHS is a call expression).
    /// Used by SSA sink detection for interprocedural sanitizer resolution.
    pub arg_callees: Vec<Option<String>>,
    /// When `find_classifiable_inner_call` overrides the primary callee
    /// (e.g. `parts.add(req.getParameter("input"))` → callee becomes
    /// "req.getParameter"), this field preserves the original outer callee
    /// ("parts.add") so container propagation can still recognise it.
    pub outer_callee: Option<String>,
    /// For cast/type-assertion expressions: the target type name extracted
    /// from the AST.  E.g. `(String) x` → `"String"`, `x as number` → `"number"`,
    /// `x.(io.Reader)` → `"io.Reader"`.  Used by type-flow constraint solving
    /// to refine the type environment at the SSA level.
    pub cast_target_type: Option<String>,
    /// Arithmetic operator for binary expression assignments (Phase 17).
    /// Only set when the CFG node is a single binary expression with a
    /// clear one-to-one operator mapping. `None` for nested, compound,
    /// boolean, or ambiguous expressions.
    pub bin_op: Option<BinOp>,
    /// Parsed literal operand from a binary expression (Phase 26).
    /// When `bin_op` is set and one operand is a numeric literal (the other
    /// being an identifier captured in `uses`), this holds the parsed value.
    /// Enables abstract-domain transfer even when the SSA instruction has
    /// only one use (the literal isn't an identifier and isn't in `uses`).
    pub bin_op_const: Option<i64>,
    /// True when this acquisition node is inside a language-managed cleanup
    /// scope (Python `with`, Java try-with-resources, C# `using`).
    /// Only meaningful on Call nodes that define a resource variable.
    /// Leak detectors check this flag on the acquire site, not the variable.
    pub managed_resource: bool,
    /// True when this Call node is a deferred release (Go `defer f.Close()`).
    /// Deferred releases are not processed as immediate closes; instead they
    /// suppress leak findings (defer guarantees cleanup at function exit).
    /// Only set on Call nodes, not on all nodes within a defer_statement.
    pub in_defer: bool,
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
    /// Which parameter indices (0‑based) flow through to the return value.
    pub propagating_params: Vec<usize>,
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

/// Check if a callee represents an RAII-managed factory whose resources are
/// automatically cleaned up by language semantics (Rust ownership/Drop, C++
/// smart pointers).  Returns `true` to set `managed_resource` on the acquire
/// node, suppressing false `state-resource-leak` findings.
fn is_raii_factory(lang: &str, callee: &str) -> bool {
    fn matches_any(callee: &str, patterns: &[&str]) -> bool {
        let cl = callee.to_ascii_lowercase();
        // Strip C++ template arguments: make_unique<int> → make_unique
        let base = cl.split('<').next().unwrap_or(&cl);
        patterns.iter().any(|p| base == *p || base.ends_with(p))
    }

    match lang {
        "cpp" => {
            static CPP_RAII_FACTORIES: &[&str] = &[
                "make_unique",
                "make_shared",
                "std::make_unique",
                "std::make_shared",
            ];
            matches_any(callee, CPP_RAII_FACTORIES)
        }
        "rust" => {
            static RUST_RAII_CONSTRUCTORS: &[&str] = &[
                "file::open",
                "file::create",
                "box::new",
                "bufwriter::new",
                "bufreader::new",
                "tcplistener::bind",
                "tcpstream::connect",
                "udpsocket::bind",
                "mutex::new",
                "rwlock::new",
                "fs::file::open",
                "fs::file::create",
                "std::fs::file::open",
                "std::fs::file::create",
            ];
            matches_any(callee, RUST_RAII_CONSTRUCTORS)
        }
        _ => false,
    }
}

/// Fallback for constructor expressions whose grammar lacks field names.
/// For example, PHP `object_creation_expression` has positional children
/// `new name arguments` where `name` is a node kind (not a field).
/// Returns the first child whose kind is `"name"` or `"type_identifier"`.
fn find_constructor_type_child(n: Node) -> Option<Node> {
    let mut cursor = n.walk();
    n.children(&mut cursor)
        .find(|c| matches!(c.kind(), "name" | "type_identifier" | "qualified_name"))
}

/// Return the callee identifier for the first call / method / macro inside `n`.
/// Searches recursively through all descendants.
fn first_call_ident<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                // C++ new/delete: normalize callee before returning.
                if lang == "cpp" && c.kind() == "new_expression" {
                    return Some("new".to_string());
                }
                if lang == "cpp" && c.kind() == "delete_expression" {
                    return Some("delete".to_string());
                }
                return match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .or_else(|| c.child_by_field_name("method"))
                        .or_else(|| c.child_by_field_name("name"))
                        .or_else(|| c.child_by_field_name("type"))
                        .or_else(|| c.child_by_field_name("constructor"))
                        // Fallback for constructors whose grammar lacks field names
                        // (e.g. PHP `object_creation_expression` has positional children).
                        .or_else(|| find_constructor_type_child(c))
                        .and_then(|f| text_of(f, code)),
                    Kind::CallMethod => {
                        let func = c
                            .child_by_field_name("method")
                            .or_else(|| c.child_by_field_name("name"))
                            .and_then(|f| text_of(f, code));
                        let recv = c
                            .child_by_field_name("object")
                            .or_else(|| c.child_by_field_name("receiver"))
                            .or_else(|| c.child_by_field_name("scope"))
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

/// Search recursively for any nested call whose identifier classifies as a label.
/// Used for cases like `str(eval(expr))` where `str` doesn't match but `eval` does.
fn find_classifiable_inner_call<'a>(
    n: Node<'a>,
    lang: &str,
    code: &'a [u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<(String, DataLabel)> {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                let ident = match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .or_else(|| c.child_by_field_name("method"))
                        .or_else(|| c.child_by_field_name("name"))
                        .or_else(|| c.child_by_field_name("type"))
                        .and_then(|f| text_of(f, code)),
                    Kind::CallMethod => {
                        let func = c
                            .child_by_field_name("method")
                            .or_else(|| c.child_by_field_name("name"))
                            .and_then(|f| text_of(f, code));
                        let recv = c
                            .child_by_field_name("object")
                            .or_else(|| c.child_by_field_name("receiver"))
                            .or_else(|| c.child_by_field_name("scope"))
                            .and_then(|f| root_receiver_text(f, lang, code));
                        match (recv, func) {
                            (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                            (_, Some(f)) => Some(f),
                            _ => None,
                        }
                    }
                    Kind::CallMacro => c
                        .child_by_field_name("macro")
                        .and_then(|f| text_of(f, code)),
                    _ => None,
                };
                if let Some(ref id) = ident
                    && let Some(lbl) = classify(lang, id, extra)
                {
                    return Some((id.clone(), lbl));
                }
                // Recurse into arguments of this call
                if let Some(found) = find_classifiable_inner_call(c, lang, code, extra) {
                    return Some(found);
                }
            }
            _ => {
                if let Some(found) = find_classifiable_inner_call(c, lang, code, extra) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Build the dot-joined text of a member_expression / attribute / selector_expression.
/// E.g. for `process.env.CMD` this returns `"process.env.CMD"`.
/// Field paths are capped at 3 segments (2 dots) to bound state size.
fn member_expr_text(n: Node, code: &[u8]) -> Option<String> {
    let path = member_expr_text_inner(n, code)?;
    // Depth limit: keep at most 3 segments (2 dots)
    let mut dots = 0;
    for (i, c) in path.char_indices() {
        if c == '.' {
            dots += 1;
        }
        if dots >= 3 {
            return Some(path[..i].to_string());
        }
    }
    Some(path)
}

fn member_expr_text_inner(n: Node, code: &[u8]) -> Option<String> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => {
            let obj = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("value"))
                .and_then(|o| member_expr_text_inner(o, code))
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
        // PHP/Python/Ruby subscript access: `$_GET['cmd']`, `os.environ['KEY']`, `params[:cmd]`
        // Try to classify the object (before the `[`) as a source.
        "subscript_expression" | "subscript" | "element_reference" => {
            if let Some(obj) = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("value"))
                .or_else(|| n.child(0))
            {
                if let Some(txt) = text_of(obj, code)
                    && let Some(lbl) = classify(lang, &txt, extra_labels)
                {
                    return Some(lbl);
                }
                // Recurse into the object for nested member accesses
                if let Some(lbl) = first_member_label(obj, lang, code, extra_labels) {
                    return Some(lbl);
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
        "subscript_expression" | "subscript" | "element_reference" => n
            .child_by_field_name("object")
            .or_else(|| n.child_by_field_name("value"))
            .or_else(|| n.child(0))
            .and_then(|obj| text_of(obj, code)),
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
/// Collect function-expression nodes nested inside a call's arguments.
///
/// This finds anonymous functions / arrow functions / closures that are
/// passed as arguments to a call and should be analysed as separate
/// function scopes.  Only direct function-argument children are collected
/// (not functions nested inside other functions — those get handled when
/// the outer function is recursed into).
fn collect_nested_function_nodes<'a>(n: Node<'a>, lang: &str) -> Vec<Node<'a>> {
    let mut funcs = Vec::new();
    collect_nested_functions_rec(n, lang, &mut funcs, false);
    funcs
}

fn collect_nested_functions_rec<'a>(
    n: Node<'a>,
    lang: &str,
    out: &mut Vec<Node<'a>>,
    inside_function: bool,
) {
    let kind = lookup(lang, n.kind());
    // Only treat as a function if it's a real function node (has children),
    // not a keyword token like `function` in JS which shares the same kind name.
    if kind == Kind::Function && n.child_count() > 0 {
        if inside_function {
            // Don't recurse into nested functions of nested functions
            return;
        }
        out.push(n);
        return;
    }
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        collect_nested_functions_rec(c, lang, out, inside_function);
    }
}

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

/// Recursively collect identifiers AND full dotted member-expression paths.
///
/// For `member_expression` / `attribute` / `selector_expression` / `field_expression`
/// nodes the full dotted path (via `member_expr_text`) is pushed into `paths`,
/// and the individual leaf identifiers are pushed into `idents` as a fallback.
/// Plain identifiers go only into `idents`.
fn collect_idents_with_paths(
    n: Node,
    code: &[u8],
    idents: &mut Vec<String>,
    paths: &mut Vec<String>,
) {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" | "field_expression" => {
            if let Some(path) = member_expr_text(n, code) {
                paths.push(path);
            }
            // Also collect individual idents as fallback
            collect_idents(n, code, idents);
        }
        "identifier"
        | "field_identifier"
        | "property_identifier"
        | "shorthand_property_identifier_pattern" => {
            if let Some(txt) = text_of(n, code) {
                idents.push(txt);
            }
        }
        "variable_name" => {
            if let Some(txt) = text_of(n, code) {
                idents.push(txt.trim_start_matches('$').to_string());
            }
        }
        _ => {
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                collect_idents_with_paths(ch, code, idents, paths);
            }
        }
    }
}

/// Recursively collect every identifier that occurs inside `n`.
///
/// Recognises `identifier` (most languages), `variable_name` (PHP),
/// `field_identifier` (Go), `property_identifier` (JS/TS), and
/// `shorthand_property_identifier_pattern` (JS/TS destructuring).
fn collect_idents(n: Node, code: &[u8], out: &mut Vec<String>) {
    match n.kind() {
        "identifier"
        | "field_identifier"
        | "property_identifier"
        | "shorthand_property_identifier_pattern" => {
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

// -------------------------------------------------------------------------
//    Short-circuit boolean operator helpers
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum BoolOp {
    And,
    Or,
}

/// Check if an AST node is a boolean operator (`&&`/`||`/`and`/`or`).
fn is_boolean_operator(node: Node) -> Option<BoolOp> {
    match node.kind() {
        "binary_expression" | "boolean_operator" | "binary" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "&&" | "and" => return Some(BoolOp::And),
                    "||" | "or" => return Some(BoolOp::Or),
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

/// Strip parenthesized_expression wrappers.
fn unwrap_parens(node: Node) -> Node {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return unwrap_parens(inner);
        }
    }
    node
}

/// Extract `left` and `right` operands from a binary boolean node.
fn get_boolean_operands<'a>(node: Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    // Field-based (all supported grammars)
    if let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        return Some((left, right));
    }
    // Positional fallback (safety net)
    let mut cursor = node.walk();
    let named: Vec<_> = node.named_children(&mut cursor).collect();
    if named.len() >= 2 {
        return Some((named[0], named[named.len() - 1]));
    }
    None
}

/// Create a lightweight `StmtKind::If` node for a sub-condition in a boolean chain.
fn push_condition_node<'a>(
    g: &mut Cfg,
    cond_ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
) -> NodeIndex {
    // Pass cond_ast as both args — sub-conditions are never `unless` nodes
    let (inner, negated) = detect_negation(cond_ast, cond_ast, lang);
    let mut vars = Vec::new();
    collect_idents(inner, code, &mut vars);
    vars.sort();
    vars.dedup();
    vars.truncate(MAX_COND_VARS);
    let text = text_of(cond_ast, code).map(|t| {
        if t.len() > MAX_CONDITION_TEXT_LEN {
            t[..MAX_CONDITION_TEXT_LEN].to_string()
        } else {
            t
        }
    });
    let span = (cond_ast.start_byte(), cond_ast.end_byte());
    g.add_node(NodeInfo {
        kind: StmtKind::If,
        span,
        labels: SmallVec::new(),
        defines: None,
        extra_defines: vec![],
        uses: Vec::new(),
        callee: None,
        receiver: None,
        enclosing_func: enclosing_func.map(|s| s.to_string()),
        call_ordinal: 0,
        condition_text: text,
        condition_vars: vars,
        condition_negated: negated,
        arg_uses: Vec::new(),
        sink_payload_args: None,
        all_args_literal: false,
        catch_param: false,
        const_text: None,
        arg_callees: Vec::new(),
        outer_callee: None,
        cast_target_type: None,
        bin_op: None,
        bin_op_const: None,
        managed_resource: false,
        in_defer: false,
    })
}

/// Recursively decompose a boolean condition into a chain of `StmtKind::If` nodes
/// with short-circuit edges.
///
/// Returns `(true_exits, false_exits)` — the sets of nodes from which True/False
/// edges should connect to the then/else branches.
fn build_condition_chain<'a>(
    cond_ast: Node<'a>,
    preds: &[NodeIndex],
    pred_edge: EdgeKind,
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let inner = unwrap_parens(cond_ast);

    match is_boolean_operator(inner) {
        Some(BoolOp::And) => {
            if let Some((left, right)) = get_boolean_operands(inner) {
                // Left operand with current preds
                let (left_true, left_false) =
                    build_condition_chain(left, preds, pred_edge, g, lang, code, enclosing_func);
                // Right operand only evaluated when left is true
                let (right_true, right_false) = build_condition_chain(
                    right,
                    &left_true,
                    EdgeKind::True,
                    g,
                    lang,
                    code,
                    enclosing_func,
                );
                // AND: true only when both true; false when either false
                let mut false_exits = left_false;
                false_exits.extend(right_false);
                (right_true, false_exits)
            } else {
                // Safety fallback: treat as leaf
                let node = push_condition_node(g, inner, lang, code, enclosing_func);
                connect_all(g, preds, node, pred_edge);
                (vec![node], vec![node])
            }
        }
        Some(BoolOp::Or) => {
            if let Some((left, right)) = get_boolean_operands(inner) {
                // Left operand with current preds
                let (left_true, left_false) =
                    build_condition_chain(left, preds, pred_edge, g, lang, code, enclosing_func);
                // Right operand only evaluated when left is false
                let (right_true, right_false) = build_condition_chain(
                    right,
                    &left_false,
                    EdgeKind::False,
                    g,
                    lang,
                    code,
                    enclosing_func,
                );
                // OR: true when either true; false only when both false
                let mut true_exits = left_true;
                true_exits.extend(right_true);
                (true_exits, right_false)
            } else {
                // Safety fallback: treat as leaf
                let node = push_condition_node(g, inner, lang, code, enclosing_func);
                connect_all(g, preds, node, pred_edge);
                (vec![node], vec![node])
            }
        }
        None => {
            // Leaf: single condition node
            let node = push_condition_node(g, inner, lang, code, enclosing_func);
            connect_all(g, preds, node, pred_edge);
            (vec![node], vec![node])
        }
    }
}

/// Find the inner CallFn/CallMethod/CallMacro node within an AST node.
/// For direct call nodes, returns the node itself. For wrappers, searches
/// up to two levels of children.
fn find_call_node<'a>(n: Node<'a>, lang: &str) -> Option<Node<'a>> {
    match lookup(lang, n.kind()) {
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => Some(n),
        _ => {
            let mut cursor = n.walk();
            for c in n.children(&mut cursor) {
                match lookup(lang, c.kind()) {
                    Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return Some(c),
                    _ => {}
                }
            }
            // Recurse one more level (handles `expression_statement > variable_declarator > call`)
            let mut cursor2 = n.walk();
            for c in n.children(&mut cursor2) {
                let mut cursor3 = c.walk();
                for gc in c.children(&mut cursor3) {
                    if matches!(
                        lookup(lang, gc.kind()),
                        Kind::CallFn | Kind::CallMethod | Kind::CallMacro
                    ) {
                        return Some(gc);
                    }
                }
            }
            None
        }
    }
}

/// Extract the string-literal content at argument position `index` (0-based).
/// Returns `None` if the argument is not a string literal or the index is out of range.
fn extract_const_string_arg(call_node: Node, index: usize, code: &[u8]) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let arg = args.named_children(&mut cursor).nth(index)?;
    match arg.kind() {
        "string" | "string_literal" => {
            let raw = text_of(arg, code)?;
            if raw.len() >= 2 {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        }
        "template_string" => {
            // Only treat as constant if no interpolation (no template_substitution children)
            let mut c = arg.walk();
            if arg
                .named_children(&mut c)
                .any(|ch| ch.kind() == "template_substitution")
            {
                return None; // dynamic
            }
            let raw = text_of(arg, code)?;
            if raw.len() >= 2 {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the value of a keyword argument from a call node (e.g. Python `shell=True`).
/// Walks argument children looking for `keyword_argument` nodes, matches the keyword
/// name, and extracts the value node text for literals.
fn extract_const_keyword_arg(call_node: Node, keyword_name: &str, code: &[u8]) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            // keyword_argument has a "name" field and a "value" field in Python tree-sitter
            let name_node = child.child_by_field_name("name")?;
            let name_text = text_of(name_node, code)?;
            if name_text == keyword_name {
                let value_node = child.child_by_field_name("value")?;
                return text_of(value_node, code).map(|s| s.to_string());
            }
        }
    }
    None
}

/// Returns true when a tree-sitter node is a syntactic literal value.
///
/// Intentionally conservative: if in doubt, returns false. It is better
/// to miss a suppression opportunity than to suppress a real tainted flow.
///
/// NOTE: Literal-kind classification also exists in `ast.rs::is_literal_node`.
/// The two must stay aligned across languages. TODO: consider extracting a
/// shared literal-kind helper if a third call site appears.
#[allow(clippy::only_used_in_recursion)]
fn is_syntactic_literal(node: Node, code: &[u8]) -> bool {
    match node.kind() {
        // Scalar strings — but reject if they contain interpolation
        // (e.g. Ruby `"hello #{name}"`, Python f-strings).
        "string"
        | "string_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "string_content"
        | "string_fragment" => !has_string_interpolation(node),

        // Numbers
        "integer" | "integer_literal" | "int_literal" | "float" | "float_literal" | "number" => {
            true
        }

        // Booleans / null / nil / none
        "true" | "false" | "null" | "nil" | "none" | "null_literal" | "boolean"
        | "boolean_literal" => true,

        // PHP encapsed_string: safe only if no variable interpolation
        "encapsed_string" => !has_interpolation_cfg(node),

        // Wrapper: PHP/Go wrap each arg in an `argument` node — unwrap
        "argument" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_syntactic_literal(c, code))
        }

        // Unary minus on a number literal: `-42`
        "unary_expression" | "unary_op" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_syntactic_literal(c, code))
        }

        // String concatenation of literals: `"a" + "b"` or `"a" . "b"`
        "binary_expression" | "concatenated_string" => {
            let count = node.named_child_count();
            count >= 2
                && (0..count).all(|i| {
                    node.named_child(i as u32)
                        .is_some_and(|c| is_syntactic_literal(c, code))
                })
        }

        // JS/TS template string: only if no interpolation substitution
        "template_string" => {
            let mut c = node.walk();
            !node
                .named_children(&mut c)
                .any(|ch| ch.kind() == "template_substitution")
        }

        // Containers: all elements must be syntactic literals
        "list"
        | "array"
        | "array_expression"
        | "array_creation_expression"
        | "tuple"
        | "tuple_expression" => {
            let mut c = node.walk();
            node.named_children(&mut c)
                .all(|ch| is_syntactic_literal(ch, code))
        }

        // Container entries: `{"key": "value"}` style pairs
        "pair" => {
            let mut c = node.walk();
            node.named_children(&mut c)
                .all(|ch| is_syntactic_literal(ch, code))
        }

        _ => false,
    }
}

/// Check if a string node contains interpolation children
/// (e.g. Ruby `"hello #{name}"` has `interpolation` children,
/// Python f-strings may have `interpolation` children).
fn has_string_interpolation(node: Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind().contains("interpolation") {
            return true;
        }
    }
    false
}

/// Check if an encapsed_string node contains interpolation (PHP).
fn has_interpolation_cfg(node: Node) -> bool {
    for i in 0..node.child_count() as u32 {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if kind == "variable_name"
                || kind == "simple_variable"
                || kind.contains("interpolation")
            {
                return true;
            }
        }
    }
    false
}

/// Extract the raw literal text from the RHS of a declaration/assignment AST node.
///
/// Walks the same value/right child paths as `def_use` and returns the text
/// if the RHS is a syntactic literal. Used to populate `NodeInfo::const_text`.
fn extract_literal_rhs(ast: Node, lang: &str, code: &[u8]) -> Option<String> {
    use crate::labels::lookup;

    // Direct value/right field (Rust let, Go short_var, etc.)
    let val_node = ast
        .child_by_field_name("value")
        .or_else(|| ast.child_by_field_name("right"));

    if let Some(val) = val_node {
        if is_syntactic_literal(val, code) {
            return text_of(val, code);
        }
    }

    // Nested declarator pattern (JS let/const → variable_declarator, etc.)
    if matches!(
        lookup(lang, ast.kind()),
        Kind::CallWrapper | Kind::Assignment
    ) {
        let mut cursor = ast.walk();
        for child in ast.children(&mut cursor) {
            let child_val = child.child_by_field_name("value").or_else(|| {
                if matches!(lookup(lang, child.kind()), Kind::Assignment) {
                    child.child_by_field_name("right")
                } else {
                    None
                }
            });
            if let Some(val) = child_val {
                if is_syntactic_literal(val, code) {
                    return text_of(val, code);
                }
            }
        }
    }

    None
}

/// Returns true when every argument in the call's argument list is a
/// syntactic literal (per `is_syntactic_literal`). Returns true for calls
/// with zero arguments (no argument-carried taint vector). Returns false
/// when the argument list cannot be found.
///
/// For method chains like `a("x").b(y).c()`, the outermost call node
/// represents the entire chain. This function walks nested call expressions
/// to verify ALL argument lists in the chain contain only literals.
fn has_only_literal_args(call_node: Node, code: &[u8]) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    for ch in args.named_children(&mut cursor) {
        if !is_syntactic_literal(ch, code) {
            return false;
        }
    }
    // Walk nested call expressions in the callee chain.
    check_inner_call_args(call_node, code)
}

/// Recursively check nested call expressions in a method chain for
/// non-literal arguments.
fn check_inner_call_args(node: Node, code: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        // Skip argument lists — those are checked by the caller.
        if kind == "arguments" || kind == "argument_list" || kind == "actual_parameters" {
            continue;
        }
        // If this child is itself a call expression, check its arguments.
        if child.child_by_field_name("arguments").is_some() {
            if !has_only_literal_args(child, code) {
                return false;
            }
        } else {
            // Recurse through non-call structural nodes (field_expression, etc.)
            if !check_inner_call_args(child, code) {
                return false;
            }
        }
    }
    true
}

/// Extract per-argument identifiers from a call node's argument list.
/// Returns one `Vec<String>` per argument (in parameter-position order).
/// Returns empty if argument list can't be found or contains spread/keyword args.
fn extract_arg_uses(call_node: Node, code: &[u8]) -> Vec<Vec<String>> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        // If we encounter a spread/splat/keyword arg, positional mapping is
        // unreliable — bail out and return empty (caller falls back to flat uses).
        let kind = child.kind();
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "keyword_argument"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
            || kind == "named_argument"
        {
            return Vec::new();
        }
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        collect_idents_with_paths(child, code, &mut idents, &mut paths);
        // Dotted paths first, then individual idents as fallback
        let mut combined = paths;
        combined.extend(idents);
        result.push(combined);
    }
    result
}

/// Like `first_call_ident`, but also checks if `n` itself is a call node.
/// `first_call_ident` only searches children, so when `n` IS the call
/// expression (e.g. the argument `sanitize(cmd)`), this function catches it.
fn call_ident_of<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    // C++ new/delete: normalize callee before field extraction.
    if lang == "cpp" && n.kind() == "new_expression" {
        return Some("new".to_string());
    }
    if lang == "cpp" && n.kind() == "delete_expression" {
        return Some("delete".to_string());
    }
    match lookup(lang, n.kind()) {
        Kind::CallFn => n
            .child_by_field_name("function")
            .or_else(|| n.child_by_field_name("method"))
            .or_else(|| n.child_by_field_name("name"))
            .or_else(|| n.child_by_field_name("type"))
            .or_else(|| find_constructor_type_child(n))
            .and_then(|f| text_of(f, code)),
        Kind::CallMethod => {
            let func = n
                .child_by_field_name("method")
                .or_else(|| n.child_by_field_name("name"))
                .and_then(|f| text_of(f, code));
            let recv = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("receiver"))
                .or_else(|| n.child_by_field_name("scope"))
                .and_then(|f| root_receiver_text(f, lang, code));
            match (recv, func) {
                (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                (_, Some(f)) => Some(f),
                _ => None,
            }
        }
        Kind::CallMacro => n
            .child_by_field_name("macro")
            .and_then(|f| text_of(f, code)),
        _ => first_call_ident(n, lang, code),
    }
}

/// For each argument of `call_node`, find the callee name if that argument
/// is itself a call expression (e.g. `sanitize(x)` in `os.system(sanitize(x))`).
/// Returns a `Vec<Option<String>>` parallel to `extract_arg_uses` output.
fn extract_arg_callees(call_node: Node, lang: &str, code: &[u8]) -> Vec<Option<String>> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        // Bail on spread/splat like extract_arg_uses does
        let kind = child.kind();
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "keyword_argument"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
            || kind == "named_argument"
        {
            return Vec::new();
        }
        result.push(call_ident_of(child, lang, code));
    }
    result
}

/// Return `(defines, uses)` for the AST fragment `ast`.
/// Returns (defines, uses, extra_defines) where extra_defines captures additional
/// bindings from destructuring patterns beyond the primary define.
fn def_use(ast: Node, lang: &str, code: &[u8]) -> (Option<String>, Vec<String>, Vec<String>) {
    match lookup(lang, ast.kind()) {
        // Declaration wrappers (let, var, short_var_declaration, etc.)
        Kind::CallWrapper => {
            let mut defs = None;
            let mut extra_defs = Vec::new();
            let mut uses = Vec::new();

            // Try direct field names first (Rust `let_declaration`, Go `short_var_declaration`)
            let def_node = ast
                .child_by_field_name("pattern")
                .or_else(|| ast.child_by_field_name("name"))
                .or_else(|| ast.child_by_field_name("left"))
                // Python `with_item`: value is `as_pattern` whose `alias` holds the target
                .or_else(|| {
                    ast.child_by_field_name("value")
                        .and_then(|v| v.child_by_field_name("alias"))
                });

            let val_node = ast
                .child_by_field_name("value")
                .or_else(|| ast.child_by_field_name("right"));

            if def_node.is_some() || val_node.is_some() {
                if let Some(pat) = def_node {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(pat, code, &mut idents, &mut paths);
                    let first = paths.pop().or_else(|| idents.first().cloned());
                    // Remaining idents are extra defines (for destructuring)
                    for ident in &idents {
                        if first.as_ref() != Some(ident) {
                            extra_defs.push(ident.clone());
                        }
                    }
                    defs = first;
                }
                if let Some(val) = val_node {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(val, code, &mut idents, &mut paths);
                    uses.extend(paths);
                    uses.extend(idents);
                }
            } else {
                // Try nested declarator pattern (JS/TS `lexical_declaration` → `variable_declarator`,
                // Java `local_variable_declaration` → `variable_declarator`,
                // C/C++ `declaration` → `init_declarator`,
                // Python/Ruby `expression_statement` → `assignment`)
                let mut cursor = ast.walk();
                for child in ast.children(&mut cursor) {
                    // Only use left/right fields for actual assignment nodes — binary
                    // expressions also have left/right but are not definitions.
                    let is_assign = matches!(lookup(lang, child.kind()), Kind::Assignment);
                    let child_name = child
                        .child_by_field_name("name")
                        .or_else(|| child.child_by_field_name("declarator"))
                        .or_else(|| {
                            if is_assign {
                                child.child_by_field_name("left")
                            } else {
                                None
                            }
                        });
                    let child_value = child.child_by_field_name("value").or_else(|| {
                        if is_assign {
                            child.child_by_field_name("right")
                        } else {
                            None
                        }
                    });

                    // Only treat this child as a declarator if it has BOTH a name
                    // and a value (or at least a value). This prevents method_invocation
                    // nodes (which have a `name` field) from being misinterpreted.
                    if child_value.is_some() {
                        if let Some(name_node) = child_name
                            && defs.is_none()
                        {
                            let mut idents = Vec::new();
                            let mut paths = Vec::new();
                            collect_idents_with_paths(name_node, code, &mut idents, &mut paths);
                            let first = paths.pop().or_else(|| idents.first().cloned());
                            for ident in &idents {
                                if first.as_ref() != Some(ident) {
                                    extra_defs.push(ident.clone());
                                }
                            }
                            defs = first;
                        }
                        if let Some(val_node) = child_value {
                            let mut idents = Vec::new();
                            let mut paths = Vec::new();
                            collect_idents_with_paths(val_node, code, &mut idents, &mut paths);
                            uses.extend(paths);
                            uses.extend(idents);
                        }
                    }
                }

                // Fallback: if still nothing found, collect all idents as uses.
                // This handles expression_statement wrappers.
                if defs.is_none() && uses.is_empty() {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(ast, code, &mut idents, &mut paths);
                    uses.extend(paths);
                    uses.extend(idents);
                }
            }
            (defs, uses, extra_defs)
        }

        // Plain assignment `x = y`
        Kind::Assignment => {
            let mut defs = None;
            let mut uses = Vec::new();
            if let Some(lhs) = ast.child_by_field_name("left") {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(lhs, code, &mut idents, &mut paths);
                // Prefer dotted path (member expression) over last ident
                defs = paths.pop().or_else(|| idents.pop());
            }
            if let Some(rhs) = ast.child_by_field_name("right") {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(rhs, code, &mut idents, &mut paths);
                uses.extend(paths);
                uses.extend(idents);
            }
            (defs, uses, vec![])
        }

        // if‑let / while‑let — the `let_condition` binds a variable from
        // the value expression.  E.g. `if let Ok(cmd) = env::var("CMD")`
        // defines `cmd` and uses `env`, `var`, `CMD`.
        Kind::If | Kind::While => {
            let cond = ast.child_by_field_name("condition");
            if let Some(c) = cond
                && c.kind() == "let_condition"
            {
                let mut defs = None;
                let mut uses = Vec::new();

                if let Some(pat) = c.child_by_field_name("pattern") {
                    let mut tmp = Vec::<String>::new();
                    collect_idents(pat, code, &mut tmp);
                    // The first plain identifier in the pattern is the binding.
                    // Skip type identifiers (e.g. "Ok" in Ok(cmd)) — take the
                    // last ident which is the inner binding name.
                    defs = tmp.into_iter().last();
                }
                if let Some(val) = c.child_by_field_name("value") {
                    collect_idents(val, code, &mut uses);
                }
                return (defs, uses, vec![]);
            }

            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(ast, code, &mut idents, &mut paths);
            let mut uses = paths;
            uses.extend(idents);
            (None, uses, vec![])
        }

        // everything else – no definition, but may read vars
        _ => {
            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(ast, code, &mut idents, &mut paths);
            let mut uses = paths;
            uses.extend(idents);
            (None, uses, vec![])
        }
    }
}

/// Extract raw condition metadata from an If AST node.
///
/// Returns `(condition_text, condition_vars, condition_negated)`.
/// The condition subtree is located via `child_by_field_name("condition")`
/// for most languages, with a positional fallback for Rust `if_expression`.
///
/// Negation is detected by checking for a leading unary `!` operator or
/// `not` keyword.  Variables are sorted, deduped, and capped at
/// [`MAX_COND_VARS`].
fn extract_condition_raw<'a>(
    ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> (Option<String>, Vec<String>, bool) {
    // 1. Find the condition subtree.
    let cond_node = ast.child_by_field_name("condition").or_else(|| {
        // Rust `if_expression` uses positional children: the condition is
        // the first child that is not a keyword, block, or `let` pattern.
        let mut cursor = ast.walk();
        ast.children(&mut cursor).find(|c| {
            let k = c.kind();
            !matches!(lookup(lang, k), Kind::Block | Kind::Trivia)
                && k != "if"
                && k != "else"
                && k != "let"
                && k != "{"
                && k != "}"
                && k != "("
                && k != ")"
        })
    });

    let Some(cond) = cond_node else {
        return (None, Vec::new(), false);
    };

    // 2. Detect leading negation (`!expr`, `not expr`, Ruby `unless`).
    let (inner, negated) = detect_negation(cond, ast, lang);

    // 3. Collect identifiers from the (inner) condition subtree.
    let mut vars = Vec::new();
    collect_idents(inner, code, &mut vars);
    vars.sort();
    vars.dedup();
    vars.truncate(MAX_COND_VARS);

    // 4. Extract text, truncated.
    let text = text_of(cond, code).map(|t| {
        if t.len() > MAX_CONDITION_TEXT_LEN {
            t[..MAX_CONDITION_TEXT_LEN].to_string()
        } else {
            t
        }
    });

    (text, vars, negated)
}

/// Detect leading negation and return the inner expression.
///
/// Handles:
/// - `!expr` (unary_expression / prefix_unary_expression with `!` operator)
/// - `not expr` (Python `not_operator`, Ruby)
///
/// NOTE: Ruby `unless` is NOT handled here. The CFG builder already swaps
/// True/False edges for `unless` (cfg.rs lines 2076-2085), so the edge labels
/// encode the correct branch semantics. Setting `condition_negated=true` here
/// would cause a double-negation in `compute_succ_states`, applying validation
/// to the wrong branch.
fn detect_negation<'a>(cond: Node<'a>, _if_ast: Node<'a>, _lang: &str) -> (Node<'a>, bool) {
    // Unwrap parenthesized_expression — JS/Java/PHP wrap if-conditions in parens.
    // This lets us detect negation inside: `if (!expr)` → cond is `(!expr)`.
    let cond = if cond.kind() == "parenthesized_expression" {
        cond.child_by_field_name("expression")
            .or_else(|| {
                let mut cursor = cond.walk();
                cond.children(&mut cursor)
                    .find(|c| c.kind() != "(" && c.kind() != ")")
            })
            .unwrap_or(cond)
    } else {
        cond
    };

    // `!expr` appears as unary_expression, not_operator, or prefix_unary_expression
    // with a `!` or `not` operator child.
    let is_negation_wrapper = matches!(
        cond.kind(),
        "unary_expression" | "not_operator" | "prefix_unary_expression" | "unary_not"
    );

    if is_negation_wrapper {
        // Check if the first child is a `!` or `not` operator.
        let has_not = cond
            .child(0)
            .is_some_and(|c| c.kind() == "!" || c.kind() == "not");

        if has_not {
            // Return the operand (inner expression after the `!` / `not`).
            let inner = cond
                .child_by_field_name("argument")
                .or_else(|| cond.child_by_field_name("operand"))
                .or_else(|| {
                    // Last non-operator child.
                    let mut cursor = cond.walk();
                    cond.children(&mut cursor)
                        .filter(|c| c.kind() != "!" && c.kind() != "not")
                        .last()
                })
                .unwrap_or(cond);
            return (inner, true);
        }
    }

    (cond, false)
}

/// Extract a binary operator from an AST node.
///
/// Covers arithmetic, bitwise, and comparison operators. Conservative
/// policy: only returns `Some(BinOp)` when the AST node directly IS a
/// binary expression or is an assignment/expression wrapper containing
/// a single binary expression as its immediate RHS. Returns `None` for
/// nested binary expressions, compound assignments (`+=`), boolean
/// operators (`&&`, `||`), and any ambiguous cases.
fn extract_bin_op(ast: Node, lang: &str) -> Option<BinOp> {
    // Find the binary expression node: either ast itself or immediate child.
    let bin_expr = find_single_binary_expr(ast, lang)?;

    // Walk children to find the operator token (anonymous node between operands).
    let mut cursor = bin_expr.walk();
    for child in bin_expr.children(&mut cursor) {
        if child.is_named() {
            continue; // Skip named children (operands)
        }
        let kind = child.kind();
        return match kind {
            "+" => Some(BinOp::Add),
            "-" => Some(BinOp::Sub),
            "*" => Some(BinOp::Mul),
            "/" => Some(BinOp::Div),
            "%" => Some(BinOp::Mod),
            // Bitwise (single-char tokens — no conflict with && / ||)
            "&" => Some(BinOp::BitAnd),
            "|" => Some(BinOp::BitOr),
            "^" => Some(BinOp::BitXor),
            "<<" => Some(BinOp::LeftShift),
            ">>" => Some(BinOp::RightShift),
            // Comparison (=== / !== are JS/TS strict equality)
            "==" | "===" => Some(BinOp::Eq),
            "!=" | "!==" => Some(BinOp::NotEq),
            "<" => Some(BinOp::Lt),
            "<=" => Some(BinOp::LtEq),
            ">" => Some(BinOp::Gt),
            ">=" => Some(BinOp::GtEq),
            _ => None, // Boolean (&&, ||), assignment ops, etc.
        };
    }
    None
}

/// Extract the numeric literal operand from a binary expression (Phase 26).
///
/// When a binary expression has one identifier operand (captured in `uses`)
/// and one numeric literal operand, this returns the parsed literal value.
/// Used for abstract-domain transfer when the SSA only has the identifier use.
fn extract_bin_op_const(ast: Node, lang: &str, code: &[u8]) -> Option<i64> {
    let bin_expr = find_single_binary_expr(ast, lang)?;
    // Look for a numeric literal child
    let left = bin_expr.named_child(0)?;
    let right = bin_expr.named_child(1)?;

    fn try_parse_number(n: Node, code: &[u8]) -> Option<i64> {
        let kind = n.kind();
        if kind == "number"
            || kind == "integer"
            || kind == "integer_literal"
            || kind == "number_literal"
            || kind == "float"
        {
            let text = std::str::from_utf8(&code[n.byte_range()]).ok()?.trim();
            // Try standard decimal parse first
            if let Ok(v) = text.parse::<i64>() {
                return Some(v);
            }
            // Try hex (0x...), octal (0o...), binary (0b...) prefixed literals
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                return i64::from_str_radix(hex, 16).ok();
            }
            if let Some(oct) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
                return i64::from_str_radix(oct, 8).ok();
            }
            if let Some(bin) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
                return i64::from_str_radix(bin, 2).ok();
            }
            None
        } else {
            None
        }
    }

    // Try left, then right — one of them should be a literal
    try_parse_number(left, code).or_else(|| try_parse_number(right, code))
}

/// Find a single binary expression node at or directly under `ast`.
///
/// Returns `None` if there are zero or multiple binary expressions
/// (ambiguous). Only descends one level into assignment/expression wrappers.
fn find_single_binary_expr<'a>(ast: Node<'a>, lang: &str) -> Option<Node<'a>> {
    let ast_kind = ast.kind();

    // Check if ast itself is a binary expression
    if is_binary_expr_kind(ast_kind, lang) {
        // Verify it has exactly 2 named children (left, right) — no nesting
        let named_count = ast.named_child_count();
        if named_count == 2 {
            // Ensure neither child is itself a binary expression (that would
            // mean the operator is for a compound expression like `a + b * c`)
            let left = ast.named_child(0);
            let right = ast.named_child(1);
            let left_is_bin = left.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
            let right_is_bin = right.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
            if !left_is_bin && !right_is_bin {
                return Some(ast);
            }
        }
        return None; // Nested or complex
    }

    // Check one level down for assignment wrappers, expression statements, etc.
    let wrapper_kinds = [
        "expression_statement",
        "assignment_expression",
        "assignment",
        "variable_declaration",
        "variable_declarator",
        "short_var_declaration",
        "lexical_declaration",
    ];
    if wrapper_kinds.contains(&ast_kind) || ast_kind.ends_with("_statement") {
        let mut found: Option<Node<'a>> = None;
        let mut cursor = ast.walk();
        for child in ast.named_children(&mut cursor) {
            if is_binary_expr_kind(child.kind(), lang) {
                if found.is_some() {
                    return None; // Multiple binary expressions → ambiguous
                }
                // Same check: must have exactly 2 non-binary named children
                if child.named_child_count() == 2 {
                    let l = child.named_child(0);
                    let r = child.named_child(1);
                    let l_bin = l.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                    let r_bin = r.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                    if !l_bin && !r_bin {
                        found = Some(child);
                    }
                }
            } else if wrapper_kinds.contains(&child.kind()) {
                // Recurse one more level into nested wrappers (e.g.,
                // variable_declaration → variable_declarator → binary_expression)
                let mut inner_cursor = child.walk();
                for grandchild in child.named_children(&mut inner_cursor) {
                    if is_binary_expr_kind(grandchild.kind(), lang) {
                        if found.is_some() {
                            return None;
                        }
                        if grandchild.named_child_count() == 2 {
                            let l = grandchild.named_child(0);
                            let r = grandchild.named_child(1);
                            let l_bin = l.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                            let r_bin = r.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                            if !l_bin && !r_bin {
                                found = Some(grandchild);
                            }
                        }
                    }
                }
            }
        }
        return found;
    }

    None
}

/// Check if an AST node kind is a binary expression in the given language.
///
/// Python uses `binary_operator` for arithmetic/bitwise and
/// `comparison_operator` for comparisons. Chained Python comparisons
/// (`a < b < c`) have 3+ named children and are rejected by the
/// `named_child_count() == 2` guard in `find_single_binary_expr`.
fn is_binary_expr_kind(kind: &str, lang: &str) -> bool {
    match lang {
        "python" => kind == "binary_operator" || kind == "comparison_operator",
        "ruby" => kind == "binary",
        _ => kind == "binary_expression",
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
            .or_else(|| ast.child_by_field_name("type"))
            // JS/TS `new_expression` uses `constructor` field.
            .or_else(|| ast.child_by_field_name("constructor"))
            // Fallback for constructors whose grammar lacks field names
            // (e.g. PHP `object_creation_expression` has positional children).
            .or_else(|| find_constructor_type_child(ast))
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
                .or_else(|| ast.child_by_field_name("scope"))
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

        // Function definitions: use just the function name, not the full
        // body text.  The raw body text can spuriously match label rules
        // (e.g. `def search\n  find_by_sql(…)\nend` would suffix-match
        // the `find_by_sql` sink via the `head = text.split('(')` logic
        // in classify_all).
        Kind::Function => ast
            .child_by_field_name("name")
            .or_else(|| ast.child_by_field_name("declarator"))
            .and_then(|n| text_of(n, code))
            .unwrap_or_default(),

        // everything else – fallback to raw slice
        _ => text_of(ast, code).unwrap_or_default(),
    };

    // C++ new/delete: normalize callee to "new"/"delete" for resource pair
    // matching.  Without this, new_expression extracts the type name (e.g.
    // "int") and delete_expression extracts the full expression text.
    // Guarded to C++ only so JS/TS `new_expression` is unaffected.
    if lang == "cpp" {
        if ast.kind() == "new_expression" {
            text = "new".to_string();
        } else if ast.kind() == "delete_expression" {
            text = "delete".to_string();
        }
    }

    // If this is a declaration/expression wrapper or an assignment that
    // *contains* a call, prefer the first inner call identifier instead of
    // the whole line.
    if matches!(
        lookup(lang, ast.kind()),
        Kind::CallWrapper | Kind::Assignment | Kind::Return
    ) {
        if let Some(inner) = first_call_ident(ast, lang, code) {
            text = inner;
        } else if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
            // Fallback for language-construct "calls" (e.g. PHP `echo_statement`,
            // `print` expression):  the first child is a keyword leaf (e.g. "echo")
            // that acts as a callee but is not a function_call_expression.
            let mut cursor = ast.walk();
            if let Some(first) = ast.children(&mut cursor).next()
                && first.child_count() == 0
                && let Some(kw) = text_of(first, code)
                && kw.len() <= 16
            {
                text = kw;
            }
        }
    }

    /* ── 2.  LABEL LOOK-UP  ───────────────────────────────────────────── */

    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut labels = classify_all(lang, &text, extra);

    // If the outermost call didn't classify, try inner/nested calls.
    // E.g. `str(eval(expr))` — `str` is not a sink, but `eval` is.
    // When the callee is overridden, save the original for container ops
    // (e.g. `parts.add(req.getParameter(...))` — callee becomes
    // "req.getParameter" but outer_callee preserves "parts.add").
    let mut outer_callee: Option<String> = None;
    if labels.is_empty()
        && matches!(
            lookup(lang, ast.kind()),
            Kind::CallWrapper | Kind::Assignment | Kind::Return
        )
        && let Some((inner_text, inner_label)) =
            find_classifiable_inner_call(ast, lang, code, extra)
    {
        labels.push(inner_label);
        outer_callee = Some(text.clone());
        text = inner_text;
    }

    // For assignments like `element.innerHTML = value`, the inner-call heuristic
    // above may have overridden `text` with a call on the RHS (e.g. getElementById).
    // If that didn't produce a label, check the LHS property name — it may be a
    // sink like `innerHTML`.
    //
    // This covers both direct `Kind::Assignment` nodes and `Kind::CallWrapper`
    // nodes (expression_statement) that wrap an assignment.
    if labels.is_empty() {
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
                if let Some(l) = classify(lang, &full, extra) {
                    labels.push(l);
                }
            }
            // Fall back to property-only (e.g. "innerHTML") for sinks that
            // don't need object context.
            if labels.is_empty()
                && let Some(prop) = lhs.child_by_field_name("property")
                && let Some(prop_text) = text_of(prop, code)
            {
                if let Some(l) = classify(lang, &prop_text, extra) {
                    labels.push(l);
                }
            }
        }
    }

    // For declarations/assignments whose RHS is a member expression (not a call),
    // try to classify the member expression text as a source.
    // This handles `var x = process.env.CMD` (JS), `os.environ["KEY"]` (Python),
    // and similar property-access-based source patterns.
    if labels.is_empty()
        && matches!(
            lookup(lang, ast.kind()),
            Kind::CallWrapper | Kind::Assignment
        )
        && let Some(found) = first_member_label(ast, lang, code, extra)
    {
        labels.push(found);
        // Update text so the callee name reflects the source.
        // Preserve the original callee in outer_callee so inter-procedural
        // summary resolution can still find the wrapping function
        // (e.g. `storeInto(req.query.input, items)` → callee="req.query.input"
        // but outer_callee="storeInto").
        if let Some(member_text) = first_member_text(ast, code) {
            if outer_callee.is_none() && text != member_text {
                outer_callee = Some(text.clone());
            }
            text = member_text;
        }
    }

    // For `if let` / `while let` patterns: try to classify the value expression
    // in the let-condition as a source/sink.  E.g. `if let Ok(cmd) = env::var("CMD")`
    // should recognise `env::var` as a taint source and label this node accordingly.
    if labels.is_empty()
        && matches!(lookup(lang, ast.kind()), Kind::If | Kind::While)
        && let Some(cond) = ast.child_by_field_name("condition")
        && cond.kind() == "let_condition"
        && let Some(val) = cond.child_by_field_name("value")
    {
        if let Some(ident) = first_call_ident(val, lang, code)
            && let Some(l) = classify(lang, &ident, extra)
        {
            labels.push(l);
            text = ident;
        }
        if labels.is_empty()
            && let Some(ident_text) = text_of(val, code)
            && let Some(l) = classify(lang, &ident_text, extra)
        {
            labels.push(l);
            text = ident_text;
        }
    }

    // Hoist call-node lookup: reused for gated sinks and arg_uses.
    let call_ast = find_call_node(ast, lang);

    // Gated sinks: argument-sensitive classification (e.g., setAttribute).
    // Runs for any node containing a classifiable call, regardless of StmtKind.
    let mut sink_payload_args: Option<Vec<usize>> = None;
    if labels.is_empty() {
        if let Some(cn) = call_ast {
            if let Some((gated_label, payload)) = classify_gated_sink(
                lang,
                &text,
                |idx| extract_const_string_arg(cn, idx, code),
                |kw| extract_const_keyword_arg(cn, kw, code),
            ) {
                labels.push(gated_label);
                if !payload.is_empty() {
                    sink_payload_args = Some(payload.to_vec());
                }
            }
        }
    }

    let span = (ast.start_byte(), ast.end_byte());

    /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

    let (defines, uses, extra_defines) = def_use(ast, lang, code);

    // Capture constant text for SSA constant propagation: when this node
    // defines a variable from a syntactic literal (no identifier uses),
    // extract the raw literal text from the AST.
    let const_text = if defines.is_some() && uses.is_empty() {
        extract_literal_rhs(ast, lang, code)
    } else {
        None
    };

    let callee = if kind == StmtKind::Call || !labels.is_empty() {
        Some(text.clone())
    } else {
        None
    };

    // Extract condition metadata for If nodes.
    let (condition_text, condition_vars, condition_negated) = if kind == StmtKind::If {
        extract_condition_raw(ast, lang, code)
    } else {
        (None, Vec::new(), false)
    };

    // Extract per-argument identifiers for Call nodes.
    // Also extract for gated-sink nodes so payload-arg filtering works.
    let mut arg_uses = if kind == StmtKind::Call || sink_payload_args.is_some() {
        call_ast
            .map(|cn| extract_arg_uses(cn, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Check whether all arguments are syntactic literals (for taint sink suppression).
    let all_args_literal = if kind == StmtKind::Call {
        call_ast
            .map(|cn| has_only_literal_args(cn, code))
            .unwrap_or(false)
    } else {
        false
    };

    // Extract per-argument inner call callees for interprocedural sanitizer resolution.
    let mut arg_callees = if kind == StmtKind::Call {
        call_ast
            .map(|cn| extract_arg_callees(cn, lang, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // For assignment sinks (including CallWrapper-wrapped assignments like
    // `element.innerHTML = clean(name)`), also extract the RHS callee.
    // This runs regardless of kind because a CallWrapper node may have
    // kind=Call (for the contained getElementById call) yet the actual
    // sink is the assignment to innerHTML.
    if !labels.is_empty() {
        let assign_node = if matches!(lookup(lang, ast.kind()), Kind::Assignment) {
            Some(ast)
        } else if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
            let mut cursor = ast.walk();
            ast.children(&mut cursor)
                .find(|c| matches!(lookup(lang, c.kind()), Kind::Assignment))
        } else {
            None
        };
        if let Some(asgn) = assign_node
            && let Some(rhs) = asgn.child_by_field_name("right")
            && let Some(callee_name) = call_ident_of(rhs, lang, code)
        {
            arg_callees.push(Some(callee_name));
        }
    }

    // For CallMethod nodes, extract the receiver identifier and prepend it
    // to arg_uses at position 0. This allows `collect_propagating_uses_taint`
    // to apply an offset so that `propagating_params[0]` maps to the first
    // real argument (not the receiver).
    let receiver = if let Some(cn) = call_ast
        && matches!(lookup(lang, cn.kind()), Kind::CallMethod)
    {
        let recv_node = cn
            .child_by_field_name("object")
            .or_else(|| cn.child_by_field_name("receiver"))
            .or_else(|| cn.child_by_field_name("scope"));
        if let Some(rn) = recv_node
            && matches!(rn.kind(), "identifier" | "variable_name")
            && let Some(recv_text) = text_of(rn, code)
        {
            // Prepend receiver as arg_uses[0]
            arg_uses.insert(0, vec![recv_text.clone()]);
            Some(recv_text)
        } else if recv_node.is_some() {
            // Complex receiver (e.g. chained call: name.replace(...).replace(...))
            // Use root_receiver_text to find the root identifier so taint can
            // flow through the chain.
            root_receiver_text(cn, lang, code).inspect(|recv_text| {
                arg_uses.insert(0, vec![recv_text.clone()]);
            })
        } else {
            // No explicit receiver (e.g. Java `buildQuery(filter)` — implicit
            // `this` call). Don't prepend anything to arg_uses so that
            // arg positions align with the callee's formal parameter indices.
            None
        }
    } else {
        None
    };

    // Extract cast/type-assertion target type from AST node.
    let cast_target_type = match ast.kind() {
        // Java: (Type) expr
        "cast_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.kind(), "type_identifier" | "scoped_type_identifier"))
            .and_then(|n| text_of(n, code)),
        // TypeScript: expr as Type
        "as_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.kind(), "type_identifier" | "predefined_type"))
            .and_then(|n| text_of(n, code)),
        // TypeScript: <Type>expr (angle-bracket syntax)
        "type_assertion" => ast
            .child(0)
            .filter(|n| matches!(n.kind(), "type_identifier" | "predefined_type"))
            .and_then(|n| text_of(n, code)),
        // Go: expr.(Type)
        "type_assertion_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.kind(), "type_identifier" | "qualified_type"))
            .and_then(|n| text_of(n, code)),
        _ => None,
    };

    // RAII-managed resource detection: tag acquire nodes whose resources
    // are automatically cleaned up by language semantics (ownership/drop,
    // smart pointers).  Follows the same pattern as `managed_resource` for
    // Python `with` and Java try-with-resources.
    let is_raii_managed = is_raii_factory(lang, &text);

    // Ruby block form auto-close: `File.open(path) { |f| f.read }` —
    // the block parameter receives the resource and Ruby guarantees close
    // at block exit.  If assigned (`f = File.open(p) { ... }`), the
    // variable holds the block's return value, not an open resource.
    let is_ruby_block_managed = lang == "ruby"
        && call_ast.is_some_and(|cn| {
            let mut c = cn.walk();
            cn.children(&mut c)
                .any(|ch| ch.kind() == "do_block" || ch.kind() == "block")
        });

    let idx = g.add_node(NodeInfo {
        kind,
        span,
        labels,
        defines,
        extra_defines,
        uses,
        callee,
        receiver,
        enclosing_func: enclosing_func.map(|s| s.to_string()),
        call_ordinal,
        condition_text,
        condition_vars,
        condition_negated,
        arg_uses,
        sink_payload_args,
        all_args_literal,
        catch_param: false,
        const_text,
        arg_callees,
        outer_callee,
        cast_target_type,
        bin_op: extract_bin_op(ast, lang),
        bin_op_const: extract_bin_op_const(ast, lang, code),
        managed_resource: is_raii_managed || is_ruby_block_managed,
        in_defer: false,
    });

    debug!(
        target: "cfg",
        "node {} ← {:?} txt=`{}` span={:?} labels={:?}",
        idx.index(),
        kind,
        text,
        span,
        g[idx].labels
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
//    Exception-source detection for try/catch wiring
// -------------------------------------------------------------------------

/// Returns true if this CFG node can implicitly raise an exception (calls).
/// Explicit throws are collected separately via `throw_targets`.
fn is_exception_source(info: &NodeInfo) -> bool {
    matches!(info.kind, StmtKind::Call)
}

/// Extract the catch parameter name from a catch clause AST node.
///
/// Returns `None` for parameter-less catch (`catch {}` in JS) or
/// catch-all (`catch(...)` in C++).
fn extract_catch_param_name<'a>(
    catch_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Option<String> {
    match lang {
        "javascript" | "js" | "typescript" | "ts" | "tsx" => {
            // JS/TS: catch_clause has a "parameter" field
            let param = catch_node.child_by_field_name("parameter")?;
            text_of(param, code)
        }
        "java" => {
            // Java: catch_clause → catch_formal_parameter → field "name"
            let mut cursor = catch_node.walk();
            for child in catch_node.children(&mut cursor) {
                if child.kind() == "catch_formal_parameter" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        return text_of(name_node, code);
                    }
                }
            }
            None
        }
        "php" => {
            // PHP: catch_clause has a "name" field, strip $ prefix
            let name_node = catch_node.child_by_field_name("name")?;
            text_of(name_node, code).map(|s| s.trim_start_matches('$').to_string())
        }
        "cpp" | "c++" => {
            // C++: catch_clause has a "parameters" field → collect idents → last
            let params = catch_node.child_by_field_name("parameters")?;
            let mut idents = Vec::new();
            collect_idents(params, code, &mut idents);
            idents.pop()
        }
        "python" | "py" => {
            // Python: except_clause has an "alias" field for `except Exception as e`
            let alias = catch_node.child_by_field_name("alias")?;
            text_of(alias, code)
        }
        "ruby" | "rb" => {
            // Ruby: rescue StandardError => e  →  exception_variable → identifier
            let var_node = catch_node.child_by_field_name("variable")?;
            let mut cursor = var_node.walk();
            for child in var_node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return text_of(child, code);
                }
            }
            None
        }
        _ => None,
    }
}

// -------------------------------------------------------------------------
//    Ruby begin/rescue/ensure handler
// -------------------------------------------------------------------------

/// Builds CFG for Ruby's `begin`/`rescue`/`ensure` blocks (and `body_statement`
/// with inline rescue).  Ruby's `begin` has no `body` field — the try-body
/// statements are direct children before `rescue`/`else`/`ensure` nodes.
#[allow(clippy::too_many_arguments)]
fn build_begin_rescue<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
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
    throw_targets: &mut Vec<NodeIndex>,
) -> Vec<NodeIndex> {
    // 1. Partition children into body / rescue / else / ensure
    let mut body_children: Vec<Node<'a>> = Vec::new();
    let mut rescue_clauses: Vec<Node<'a>> = Vec::new();
    let mut else_clause: Option<Node<'a>> = None;
    let mut ensure_clause: Option<Node<'a>> = None;

    let mut cursor = ast.walk();
    for child in ast.children(&mut cursor) {
        match child.kind() {
            "rescue" => rescue_clauses.push(child),
            "else" => else_clause = Some(child),
            "ensure" => ensure_clause = Some(child),
            _ if lookup(lang, child.kind()) == Kind::Trivia => {}
            // Keywords like "begin", "end" appear as anonymous children
            "begin" | "end" => {}
            _ => body_children.push(child),
        }
    }

    // 2. Build try body sub-CFG (sequential, like Block handler)
    let try_body_first_idx = g.node_count();
    let mut try_throw_targets = Vec::new();
    let mut frontier = preds.to_vec();
    for child in &body_children {
        frontier = build_sub(
            *child,
            &frontier,
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
            &mut try_throw_targets,
        );
    }
    let try_exits = frontier;
    let try_body_last_idx = g.node_count();

    // 3. Collect exception sources: implicit (calls) + explicit (throws)
    let mut exception_sources: Vec<NodeIndex> = Vec::new();
    for raw in try_body_first_idx..try_body_last_idx {
        let idx = NodeIndex::new(raw);
        if is_exception_source(&g[idx]) {
            exception_sources.push(idx);
        }
    }
    exception_sources.extend(&try_throw_targets);

    // 4. Build each rescue clause and wire exception edges
    let mut all_catch_exits: Vec<NodeIndex> = Vec::new();

    for rescue_node in &rescue_clauses {
        let param_name = extract_catch_param_name(*rescue_node, lang, code);

        // If the rescue has a named variable (=> e), inject a synthetic catch-param node
        let catch_preds = if let Some(ref name) = param_name {
            let synth = g.add_node(NodeInfo {
                kind: StmtKind::Seq,
                span: (rescue_node.start_byte(), rescue_node.start_byte()),
                labels: SmallVec::new(),
                defines: Some(name.clone()),
                extra_defines: vec![],
                uses: Vec::new(),
                callee: Some(format!("catch({name})")),
                receiver: None,
                enclosing_func: enclosing_func.map(|s| s.to_string()),
                call_ordinal: 0,
                condition_text: None,
                condition_vars: Vec::new(),
                condition_negated: false,
                arg_uses: Vec::new(),
                sink_payload_args: None,
                all_args_literal: false,
                catch_param: true,
                const_text: None,
                arg_callees: Vec::new(),
                outer_callee: None,
                cast_target_type: None,
                bin_op: None,
                bin_op_const: None,
                managed_resource: false,
                in_defer: false,
            });

            // Wire exception edges from every exception source → synthetic node
            for &src in &exception_sources {
                g.add_edge(src, synth, EdgeKind::Exception);
            }

            vec![synth]
        } else {
            // No param name — will wire exception edges to first rescue body node
            Vec::new()
        };

        // Build rescue body.  The rescue node's body may be in a "body" field
        // (a "then" node), or the statements may be direct children.
        let catch_first_idx = NodeIndex::new(g.node_count());
        let rescue_body = rescue_node.child_by_field_name("body");
        let catch_exits = if let Some(body_node) = rescue_body {
            build_sub(
                body_node,
                &catch_preds,
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
                throw_targets,
            )
        } else {
            // No body field — build rescue node itself as a block.
            // Filter out meta-children (exceptions, exception_variable) by
            // iterating and building only statement children.
            let mut rescue_cursor = rescue_node.walk();
            let mut rf = catch_preds.clone();
            for child in rescue_node.children(&mut rescue_cursor) {
                match child.kind() {
                    "exceptions" | "exception_variable" => {}
                    _ if lookup(lang, child.kind()) == Kind::Trivia => {}
                    "=>" | "rescue" => {}
                    _ => {
                        rf = build_sub(
                            child,
                            &rf,
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
                            throw_targets,
                        );
                    }
                }
            }
            rf
        };

        // If no param name, wire exception edges to the first rescue body node
        if param_name.is_none() {
            let catch_entry = if catch_first_idx.index() < g.node_count() {
                catch_first_idx
            } else {
                continue;
            };
            for &src in &exception_sources {
                g.add_edge(src, catch_entry, EdgeKind::Exception);
            }
        }

        all_catch_exits.extend(catch_exits);
    }

    // 5. Build else clause (runs when no exception was raised)
    let normal_exits = if let Some(else_node) = else_clause {
        build_sub(
            else_node,
            &try_exits,
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
            throw_targets,
        )
    } else {
        try_exits
    };

    // 6. Build ensure clause (Ruby's finally — always runs)
    if let Some(ensure_node) = ensure_clause {
        let mut ensure_preds: Vec<NodeIndex> = Vec::new();
        ensure_preds.extend(&normal_exits);
        ensure_preds.extend(&all_catch_exits);
        if rescue_clauses.is_empty() {
            ensure_preds.extend(&try_throw_targets);
        }

        build_sub(
            ensure_node,
            &ensure_preds,
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
            throw_targets,
        )
    } else {
        // No ensure: return normal exits + catch exits
        let mut exits = normal_exits;
        exits.extend(all_catch_exits);
        exits
    }
}

// -------------------------------------------------------------------------
//    try/catch/finally handler
// -------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_try<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
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
    throw_targets: &mut Vec<NodeIndex>,
) -> Vec<NodeIndex> {
    // Ruby begin/rescue/ensure: no "body" field, has "rescue" or "ensure" children.
    // Delegate to the dedicated handler.
    if ast.child_by_field_name("body").is_none() {
        let mut cursor = ast.walk();
        let has_rescue_or_ensure = ast
            .children(&mut cursor)
            .any(|c| c.kind() == "rescue" || c.kind() == "ensure");
        if has_rescue_or_ensure {
            return build_begin_rescue(
                ast,
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
                throw_targets,
            );
        }
    }

    // 1. Extract child AST nodes (language-aware field lookup)
    let try_body = ast.child_by_field_name("body");

    // Catch clauses: JS/TS use "handler" field, Java uses positional "catch_clause" children
    let catch_clauses: Vec<Node<'a>> = {
        let mut clauses = Vec::new();
        if let Some(handler) = ast.child_by_field_name("handler") {
            clauses.push(handler);
        }
        // Also collect positional catch_clause children (Java, PHP, C++)
        let mut cursor = ast.walk();
        for child in ast.children(&mut cursor) {
            if (child.kind() == "catch_clause" || child.kind() == "except_clause")
                && !clauses.iter().any(|c| c.id() == child.id())
            {
                clauses.push(child);
            }
        }
        clauses
    };

    // Finally: JS/TS use "finalizer" field, Java/PHP use positional "finally_clause" child
    let finally_clause = ast.child_by_field_name("finalizer").or_else(|| {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|child| child.kind() == "finally_clause")
    });

    // For Java try-with-resources: build resources as sequential predecessors
    let try_preds = if let Some(resources) = ast.child_by_field_name("resources") {
        let first_resource_idx = g.node_count();
        let result = build_sub(
            resources,
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
            throw_targets,
        );
        // Mark actual resource acquisition nodes (Call + defines) as managed.
        // Java try-with-resources guarantees AutoCloseable.close() is called.
        for raw in first_resource_idx..g.node_count() {
            let idx = NodeIndex::new(raw);
            if g[idx].kind == StmtKind::Call && g[idx].defines.is_some() {
                g[idx].managed_resource = true;
            }
        }
        result
    } else {
        preds.to_vec()
    };

    // 2. Build try body sub-CFG
    let try_body_first_idx = g.node_count();
    let mut try_throw_targets = Vec::new();
    let try_exits = if let Some(body) = try_body {
        build_sub(
            body,
            &try_preds,
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
            &mut try_throw_targets,
        )
    } else {
        try_preds
    };
    let try_body_last_idx = g.node_count();

    // 3. Collect exception sources: implicit (calls) + explicit (throws)
    let mut exception_sources: Vec<NodeIndex> = Vec::new();
    for raw in try_body_first_idx..try_body_last_idx {
        let idx = NodeIndex::new(raw);
        if is_exception_source(&g[idx]) {
            exception_sources.push(idx);
        }
    }
    exception_sources.extend(&try_throw_targets);

    // 4. Build each catch clause and wire exception edges
    let mut all_catch_exits: Vec<NodeIndex> = Vec::new();

    if catch_clauses.is_empty() {
        // try/finally without catch: throws propagate outward after finally
        // (handled below in the finally section)
    } else {
        for catch_node in &catch_clauses {
            let param_name = extract_catch_param_name(*catch_node, lang, code);

            // If the catch has a named parameter, inject a synthetic node that
            // defines it.  The taint transfer function will conservatively
            // taint this variable (catch_param = true).
            let catch_preds = if let Some(ref name) = param_name {
                let synth = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    span: (catch_node.start_byte(), catch_node.start_byte()),
                    labels: SmallVec::new(),
                    defines: Some(name.clone()),
                    extra_defines: vec![],
                    uses: Vec::new(),
                    callee: Some(format!("catch({name})")),
                    receiver: None,
                    enclosing_func: enclosing_func.map(|s| s.to_string()),
                    call_ordinal: 0,
                    condition_text: None,
                    condition_vars: Vec::new(),
                    condition_negated: false,
                    arg_uses: Vec::new(),
                    sink_payload_args: None,
                    all_args_literal: false,
                    catch_param: true,
                    const_text: None,
                    arg_callees: Vec::new(),
                    outer_callee: None,
                    cast_target_type: None,
                    bin_op: None,
                    bin_op_const: None,
                    managed_resource: false,
                    in_defer: false,
                });

                // Wire exception edges from every exception source → synthetic node
                for &src in &exception_sources {
                    g.add_edge(src, synth, EdgeKind::Exception);
                }

                vec![synth]
            } else {
                // No param name — wire exception edges directly to first catch body node
                Vec::new()
            };

            let catch_first_idx = NodeIndex::new(g.node_count());
            // Pass outer throw_targets so throws in catch propagate to enclosing try
            let catch_exits = build_sub(
                *catch_node,
                &catch_preds,
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
                throw_targets,
            );

            // If no param name, wire exception edges to the first catch body node
            if param_name.is_none() {
                let catch_entry = if catch_first_idx.index() < g.node_count() {
                    catch_first_idx
                } else {
                    continue;
                };
                for &src in &exception_sources {
                    g.add_edge(src, catch_entry, EdgeKind::Exception);
                }
            }

            all_catch_exits.extend(catch_exits);
        }
    }

    // 5. Build finally clause (if present)
    if let Some(finally_node) = finally_clause {
        // Finally predecessors = try normal exits + catch exits
        // For try/finally without catch, also include throw targets from try body
        let mut finally_preds: Vec<NodeIndex> = Vec::new();
        finally_preds.extend(&try_exits);
        finally_preds.extend(&all_catch_exits);
        if catch_clauses.is_empty() {
            finally_preds.extend(&try_throw_targets);
        }

        let finally_exits = build_sub(
            finally_node,
            &finally_preds,
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
            throw_targets,
        );
        finally_exits
    } else {
        // No finally: return try normal exits + catch exits
        let mut exits = try_exits;
        exits.extend(all_catch_exits);
        exits
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
    throw_targets: &mut Vec<NodeIndex>,
) -> Vec<NodeIndex> {
    match lookup(lang, ast.kind()) {
        // ─────────────────────────────────────────────────────────────────
        //  IF‑/ELSE: two branches that re‑merge afterwards
        // ─────────────────────────────────────────────────────────────────
        Kind::If => {
            // Check if condition contains a boolean operator for short-circuit decomposition.
            let cond_subtree = ast.child_by_field_name("condition").or_else(|| {
                // Rust `if_expression` uses positional children
                let mut cursor = ast.walk();
                ast.children(&mut cursor).find(|c| {
                    let k = c.kind();
                    !matches!(lookup(lang, k), Kind::Block | Kind::Trivia)
                        && k != "if"
                        && k != "else"
                        && k != "let"
                        && k != "{"
                        && k != "}"
                        && k != "("
                        && k != ")"
                })
            });

            let has_short_circuit = cond_subtree
                .map(|c| is_boolean_operator(unwrap_parens(c)).is_some())
                .unwrap_or(false);

            // Check for negation wrapping the entire condition (e.g. `!(a && b)`)
            // — if present, skip short-circuit decomposition (De Morgan out of scope).
            let has_short_circuit = has_short_circuit
                && cond_subtree.map_or(false, |c| {
                    let unwrapped = unwrap_parens(c);
                    !matches!(
                        unwrapped.kind(),
                        "unary_expression"
                            | "not_operator"
                            | "prefix_unary_expression"
                            | "unary_not"
                    )
                });

            let is_unless = ast.kind() == "unless";

            // Determine true/false exit sets for wiring branches.
            let (true_exits, false_exits) = if has_short_circuit {
                let cond_ast = cond_subtree.unwrap();
                build_condition_chain(
                    cond_ast,
                    preds,
                    EdgeKind::Seq,
                    g,
                    lang,
                    code,
                    enclosing_func,
                )
            } else {
                // Single-node path (original behavior)
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
                (vec![cond], vec![cond])
            };

            // For `unless`, swap: body runs when condition is false.
            let (then_preds, else_preds) = if is_unless {
                (&false_exits, &true_exits)
            } else {
                (&true_exits, &false_exits)
            };
            let (then_edge, else_edge) = if is_unless {
                (EdgeKind::False, EdgeKind::True)
            } else {
                (EdgeKind::True, EdgeKind::False)
            };

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
                    then_preds,
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
                    throw_targets,
                );
                // Add True/False edge from condition exit(s) to first node of then-branch.
                if then_first_node.index() < g.node_count() {
                    connect_all(g, then_preds, then_first_node, then_edge);
                } else if let Some(&first) = exits.first() {
                    connect_all(g, then_preds, first, then_edge);
                }
                exits
            } else {
                then_preds.to_vec()
            };

            // ELSE branch
            let else_first_node = NodeIndex::new(g.node_count());
            let else_exits = if let Some(b) = else_block {
                let exits = build_sub(
                    b,
                    else_preds,
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
                    throw_targets,
                );
                if else_first_node.index() < g.node_count() {
                    connect_all(g, else_preds, else_first_node, else_edge);
                } else if let Some(&first) = exits.first() {
                    connect_all(g, else_preds, first, else_edge);
                }
                exits
            } else {
                // No explicit else → create a synthetic pass-through node
                // for the false path.
                let pass = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    span: (ast.end_byte(), ast.end_byte()),
                    labels: SmallVec::new(),
                    defines: None,
                    extra_defines: vec![],
                    uses: Vec::new(),
                    callee: None,
                    receiver: None,
                    enclosing_func: enclosing_func.map(|s| s.to_string()),
                    call_ordinal: 0,
                    condition_text: None,
                    condition_vars: Vec::new(),
                    condition_negated: false,
                    arg_uses: Vec::new(),
                    sink_payload_args: None,
                    all_args_literal: false,
                    catch_param: false,
                    const_text: None,
                    arg_callees: Vec::new(),
                    outer_callee: None,
                    cast_target_type: None,
                    bin_op: None,
                    bin_op_const: None,
                    managed_resource: false,
                    in_defer: false,
                });
                connect_all(g, else_preds, pass, else_edge);
                vec![pass]
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
                throw_targets,
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

            // Check for short-circuit condition
            let cond_subtree = ast.child_by_field_name("condition");
            let has_short_circuit = cond_subtree
                .map(|c| {
                    let unwrapped = unwrap_parens(c);
                    is_boolean_operator(unwrapped).is_some()
                        && !matches!(
                            unwrapped.kind(),
                            "unary_expression"
                                | "not_operator"
                                | "prefix_unary_expression"
                                | "unary_not"
                        )
                })
                .unwrap_or(false);

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

            if has_short_circuit {
                let cond_ast = cond_subtree.unwrap();
                let (true_exits, false_exits) = build_condition_chain(
                    cond_ast,
                    &[header],
                    EdgeKind::Seq,
                    g,
                    lang,
                    code,
                    enclosing_func,
                );

                // Wire body from true_exits
                let body_first = NodeIndex::new(g.node_count());
                let body_exits = build_sub(
                    body,
                    &true_exits,
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
                    throw_targets,
                );
                // Add True edges from condition chain to body
                if body_first.index() < g.node_count() {
                    connect_all(g, &true_exits, body_first, EdgeKind::True);
                }

                // Back-edges go to header (not into the condition chain)
                for &e in &body_exits {
                    connect_all(g, &[e], header, EdgeKind::Back);
                }
                for &c in &loop_continues {
                    connect_all(g, &[c], header, EdgeKind::Back);
                }

                // Loop exits = false_exits + breaks
                let mut exits: Vec<NodeIndex> = false_exits;
                exits.extend(loop_breaks);
                exits
            } else {
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
                    throw_targets,
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
        Kind::Throw => {
            if has_call_descendant(ast, lang) {
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
                throw_targets.push(ret);
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
                throw_targets.push(ret);
                Vec::new()
            }
        }
        Kind::Try => build_try(
            ast,
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
            throw_targets,
        ),
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
            // Ruby body_statement with rescue/ensure = implicit begin/rescue
            if lang == "ruby" && ast.kind() == "body_statement" {
                let mut check = ast.walk();
                if ast
                    .children(&mut check)
                    .any(|c| c.kind() == "rescue" || c.kind() == "ensure")
                {
                    return build_begin_rescue(
                        ast,
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
                        throw_targets,
                    );
                }
            }

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

                // Go `defer`: record node count before recursing so we can
                // mark the deferred Call node(s) afterward.
                let is_defer = lang == "go" && child.kind() == "defer_statement";
                let defer_first_idx = if is_defer { g.node_count() } else { 0 };

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
                    throw_targets,
                );

                // Mark only Call nodes inside the defer as deferred releases.
                if is_defer {
                    for raw in defer_first_idx..g.node_count() {
                        let idx = NodeIndex::new(raw);
                        if g[idx].kind == StmtKind::Call {
                            g[idx].in_defer = true;
                        }
                    }
                }

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
                .unwrap_or_else(|| format!("<anon@{}>", ast.start_byte()));
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
            let body = ast.child_by_field_name("body").unwrap_or_else(|| {
                // Some function expressions (e.g. JS anonymous `function(…) { … }`)
                // don't have a named "body" field — find the first block child.
                let mut c = ast.walk();
                ast.children(&mut c)
                    .find(|n| matches!(lookup(lang, n.kind()), Kind::Block | Kind::SourceFile))
                    .unwrap_or_else(|| {
                        panic!(
                            "fn w/o body: kind={} text='{}'",
                            ast.kind(),
                            text_of(ast, code).unwrap_or_default()
                        )
                    })
            });
            let mut fn_call_ordinal: u32 = 0;
            let mut fn_breaks = Vec::new();
            let mut fn_continues = Vec::new();
            let mut fn_throws = Vec::new();
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
                &mut fn_throws,
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
                for lbl in &info.labels {
                    match *lbl {
                        DataLabel::Source(bits) => fn_src_bits |= bits,
                        DataLabel::Sanitizer(bits) => fn_sani_bits |= bits,
                        DataLabel::Sink(bits) => {
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
                for lab in &info.labels {
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

            // ───── propagating_params ────────────────────────────────────────────
            //
            // Per-parameter propagation: for each parameter, check whether it
            // reaches a return value (explicit or implicit) while still carrying
            // taint bits.  Records the 0-based index of each propagating param.
            let propagating_params = {
                let mut params = Vec::new();

                for (i, pname) in param_names.iter().enumerate() {
                    let mut flows = false;

                    // check explicit returns
                    for &idx in node_bits.keys() {
                        if g[idx].kind == StmtKind::Return {
                            for u in &g[idx].uses {
                                if u == pname {
                                    flows = true;
                                }
                                // check if the var was derived from this param
                                if let Some(bits) = var_taint.get(u)
                                    && !bits.is_empty()
                                    && var_taint.contains_key(pname)
                                {
                                    flows = true;
                                }
                            }
                        }
                    }

                    // check implicit returns (fall-through body exits)
                    if !flows {
                        for &exit_pred in &body_exits {
                            let info = &g[exit_pred];
                            for u in &info.uses {
                                if u == pname {
                                    flows = true;
                                }
                            }
                            if let Some(def) = &info.defines
                                && def == pname
                            {
                                flows = true;
                            }
                        }
                    }

                    if flows {
                        params.push(i);
                    }
                }
                params
            };

            tainted_sink_params.sort_unstable();
            tainted_sink_params.dedup();

            /* ───── 4) synthesise an explicit exit-node and wire it up ──────────── */
            let exit_idx = g.add_node(NodeInfo {
                kind: StmtKind::Return,
                span: (ast.start_byte(), ast.end_byte()),
                labels: SmallVec::new(),
                defines: None,
                extra_defines: vec![],
                uses: Vec::new(),
                callee: None,
                receiver: None,
                enclosing_func: Some(fn_name.clone()),
                call_ordinal: 0,
                condition_text: None,
                condition_vars: Vec::new(),
                condition_negated: false,
                arg_uses: Vec::new(),
                sink_payload_args: None,
                all_args_literal: false,
                catch_param: false,
                const_text: None,
                arg_callees: Vec::new(),
                outer_callee: None,
                cast_target_type: None,
                bin_op: None,
                bin_op_const: None,
                managed_resource: false,
                in_defer: false,
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
                    propagating_params,
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
                    throw_targets,
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

            // Python `with_item`: acquisition inside a context manager.
            // Only mark if this is actually an acquisition (Call + defines).
            if ast.kind() == "with_item"
                && g[node].kind == StmtKind::Call
                && g[node].defines.is_some()
            {
                g[node].managed_resource = true;
            }

            connect_all(g, preds, node, EdgeKind::Seq);

            // If the callee is a configured terminator, treat as a dead end
            if kind == StmtKind::Call
                && let Some(callee) = &g[node].callee
                && is_configured_terminator(callee, analysis_rules)
            {
                return Vec::new();
            }

            // Recurse into any function expressions nested in arguments
            // (e.g. `app.get('/path', function(req, res) { ... })`)
            // so that they get proper function summaries.
            let nested = collect_nested_function_nodes(ast, lang);
            for func_node in nested {
                build_sub(
                    func_node,
                    &[node],
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
                    throw_targets,
                );
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

            // Recurse into any function expressions nested in arguments
            let nested = collect_nested_function_nodes(ast, lang);
            for func_node in nested {
                build_sub(
                    func_node,
                    &[n],
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
                    throw_targets,
                );
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
        labels: SmallVec::new(),
        defines: None,
        extra_defines: vec![],
        uses: Vec::new(),
        callee: None,
        receiver: None,
        enclosing_func: None,
        call_ordinal: 0,
        condition_text: None,
        condition_vars: Vec::new(),
        condition_negated: false,
        arg_uses: Vec::new(),
        sink_payload_args: None,
        all_args_literal: false,
        catch_param: false,
        const_text: None,
        arg_callees: Vec::new(),
        outer_callee: None,
        cast_target_type: None,
        bin_op: None,
        bin_op_const: None,
        managed_resource: false,
        in_defer: false,
    });
    let exit = g.add_node(NodeInfo {
        kind: StmtKind::Exit,
        span: (code.len(), code.len()),
        labels: SmallVec::new(),
        defines: None,
        extra_defines: vec![],
        uses: Vec::new(),
        callee: None,
        receiver: None,
        enclosing_func: None,
        call_ordinal: 0,
        condition_text: None,
        condition_vars: Vec::new(),
        condition_negated: false,
        arg_uses: Vec::new(),
        sink_payload_args: None,
        all_args_literal: false,
        catch_param: false,
        const_text: None,
        arg_callees: Vec::new(),
        outer_callee: None,
        cast_target_type: None,
        bin_op: None,
        bin_op_const: None,
        managed_resource: false,
        in_defer: false,
    });

    // Build the body below the synthetic ENTRY.
    let mut top_ordinal: u32 = 0;
    let mut top_breaks = Vec::new();
    let mut top_continues = Vec::new();
    let mut top_throws = Vec::new();
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
        &mut top_throws,
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
            propagating_params: local.propagating_params.clone(),
            propagates_taint: false,
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

#[cfg(test)]
mod cfg_tests {
    use super::*;
    use petgraph::visit::EdgeRef;
    use tree_sitter::Language;

    fn parse_and_build(src: &[u8], lang_str: &str, ts_lang: Language) -> (Cfg, NodeIndex) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let (cfg, entry, _) = build_cfg(&tree, src, lang_str, "test.js", None);
        (cfg, entry)
    }

    #[test]
    fn js_try_catch_has_exception_edges() {
        let src = b"function f() { try { foo(); } catch (e) { bar(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        assert!(
            !exception_edges.is_empty(),
            "Expected at least one Exception edge"
        );
        // Verify source is a Call node
        for e in &exception_edges {
            assert_eq!(cfg[e.source()].kind, StmtKind::Call);
        }
    }

    #[test]
    fn js_try_finally_no_exception_edges() {
        let src = b"function f() { try { foo(); } finally { cleanup(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        // No catch clause → no exception edges
        assert!(
            exception_edges.is_empty(),
            "Expected no Exception edges for try/finally without catch"
        );

        // Verify finally nodes are reachable from entry
        let mut reachable = HashSet::new();
        let mut bfs = petgraph::visit::Bfs::new(&cfg, _entry);
        while let Some(nx) = bfs.next(&cfg) {
            reachable.insert(nx);
        }
        assert_eq!(
            reachable.len(),
            cfg.node_count(),
            "All nodes should be reachable (finally connected to try body)"
        );
    }

    #[test]
    fn java_try_catch_has_exception_edges() {
        let src = b"class Foo { void bar() { try { baz(); } catch (Exception e) { qux(); } } }";
        let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "java", ts_lang);

        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        assert!(
            !exception_edges.is_empty(),
            "Expected at least one Exception edge in Java try/catch"
        );
        for e in &exception_edges {
            assert_eq!(cfg[e.source()].kind, StmtKind::Call);
        }
    }

    #[test]
    fn js_try_catch_finally_all_reachable() {
        let src = b"function f() { try { foo(); } catch (e) { bar(); } finally { baz(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, entry) = parse_and_build(src, "javascript", ts_lang);

        // All nodes should be reachable
        let mut reachable = HashSet::new();
        let mut bfs = petgraph::visit::Bfs::new(&cfg, entry);
        while let Some(nx) = bfs.next(&cfg) {
            reachable.insert(nx);
        }
        assert_eq!(
            reachable.len(),
            cfg.node_count(),
            "All nodes should be reachable in try/catch/finally"
        );

        // Should have exception edges
        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        assert!(!exception_edges.is_empty());
    }

    #[test]
    fn js_throw_in_try_catch_has_exception_edge() {
        let src = b"function f() { try { throw new Error('bad'); } catch (e) { handle(e); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        assert!(
            !exception_edges.is_empty(),
            "throw inside try should create exception edge to catch"
        );
    }

    #[test]
    fn java_multiple_catch_clauses() {
        let src = b"class Foo { void bar() { try { baz(); } catch (IOException e) { a(); } catch (Exception e) { b(); } } }";
        let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "java", ts_lang);

        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        // Should have exception edges to both catch clauses
        assert!(
            exception_edges.len() >= 2,
            "Expected exception edges to multiple catch clauses, got {}",
            exception_edges.len()
        );
    }

    #[test]
    fn js_catch_param_defines_variable() {
        let src = b"function f() { try { foo(); } catch (e) { bar(e); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        // Find the synthetic catch-param node
        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert_eq!(
            catch_param_nodes.len(),
            1,
            "Expected exactly one catch_param node"
        );
        let cp = &cfg[catch_param_nodes[0]];
        assert_eq!(cp.defines.as_deref(), Some("e"));
        assert_eq!(cp.kind, StmtKind::Seq);

        // Exception edges should target the synthetic node
        let exception_targets: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .map(|e| e.target())
            .collect();
        assert!(exception_targets.iter().all(|&t| t == catch_param_nodes[0]));
    }

    #[test]
    fn java_catch_param_extracted() {
        let src = b"class Foo { void bar() { try { baz(); } catch (Exception e) { qux(e); } } }";
        let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "java", ts_lang);

        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert_eq!(
            catch_param_nodes.len(),
            1,
            "Expected exactly one catch_param node in Java"
        );
        assert_eq!(cfg[catch_param_nodes[0]].defines.as_deref(), Some("e"));
    }

    #[test]
    fn js_catch_no_param_no_synthetic() {
        // catch {} with no parameter should not create a catch_param node
        let src = b"function f() { try { foo(); } catch { bar(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert!(
            catch_param_nodes.is_empty(),
            "catch without parameter should not create a catch_param node"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    //  Ruby begin/rescue/ensure tests
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn ruby_begin_rescue_has_exception_edges() {
        let src = b"def f()\n  begin\n    foo()\n  rescue => e\n    bar(e)\n  end\nend";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        let exception_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .collect();
        assert!(
            !exception_edges.is_empty(),
            "begin/rescue should produce exception edges"
        );
    }

    #[test]
    fn ruby_rescue_catch_param_defines_variable() {
        let src =
            b"def f()\n  begin\n    foo()\n  rescue StandardError => e\n    bar(e)\n  end\nend";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert_eq!(
            catch_param_nodes.len(),
            1,
            "Expected exactly one catch_param node in Ruby rescue"
        );
        let cp = &cfg[catch_param_nodes[0]];
        assert_eq!(cp.defines.as_deref(), Some("e"));
        assert_eq!(cp.kind, StmtKind::Seq);

        // Exception edges should target the synthetic node
        let exception_targets: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .map(|e| e.target())
            .collect();
        assert!(exception_targets.iter().all(|&t| t == catch_param_nodes[0]));
    }

    #[test]
    fn ruby_begin_rescue_ensure_complete() {
        let src = b"def f()\n  begin\n    foo()\n  rescue => e\n    bar(e)\n  ensure\n    baz()\n  end\nend";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        // Should have exception edges
        let exception_count = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .count();
        assert!(
            exception_count > 0,
            "begin/rescue/ensure should have exception edges"
        );

        // All nodes should be reachable (no orphaned nodes beyond entry/exit)
        let node_count = cfg.node_count();
        assert!(node_count > 3, "CFG should have multiple nodes");
    }

    #[test]
    fn ruby_rescue_no_variable() {
        // bare rescue without => e
        let src = b"def f()\n  begin\n    foo()\n  rescue\n    bar()\n  end\nend";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        // No catch_param node should be created
        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert!(
            catch_param_nodes.is_empty(),
            "rescue without variable should not create a catch_param node"
        );

        // But exception edges should still exist
        let exception_count = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .count();
        assert!(
            exception_count > 0,
            "rescue without variable should still have exception edges"
        );
    }

    #[test]
    fn ruby_body_statement_implicit_begin() {
        // def method body with inline rescue (no explicit begin)
        let src = b"def f()\n  foo()\nrescue => e\n  bar(e)\nend";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        let exception_count = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .count();
        assert!(
            exception_count > 0,
            "implicit begin via body_statement should produce exception edges"
        );

        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert_eq!(
            catch_param_nodes.len(),
            1,
            "implicit begin rescue should have one catch_param node"
        );
        assert_eq!(cfg[catch_param_nodes[0]].defines.as_deref(), Some("e"));
    }

    #[test]
    fn ruby_multiple_rescue_clauses() {
        let src = b"def f()\n  begin\n    foo()\n  rescue IOError => e\n    handle_io(e)\n  rescue => e\n    handle_other(e)\n  end\nend";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        let catch_param_nodes: Vec<_> =
            cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
        assert_eq!(
            catch_param_nodes.len(),
            2,
            "Two rescue clauses should produce two catch_param nodes"
        );

        // Both should define "e"
        for &cp in &catch_param_nodes {
            assert_eq!(cfg[cp].defines.as_deref(), Some("e"));
        }

        // Exception edges should target both synthetic nodes
        let exception_targets: std::collections::HashSet<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Exception))
            .map(|e| e.target())
            .collect();
        for &cp in &catch_param_nodes {
            assert!(
                exception_targets.contains(&cp),
                "Exception edges should target each catch_param node"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Short-circuit evaluation tests
    // ─────────────────────────────────────────────────────────────────

    /// Helper: collect all If nodes from the CFG.
    fn if_nodes(cfg: &Cfg) -> Vec<NodeIndex> {
        cfg.node_indices()
            .filter(|&n| cfg[n].kind == StmtKind::If)
            .collect()
    }

    /// Helper: check if an edge of the given kind exists from `src` to `dst`.
    fn has_edge(
        cfg: &Cfg,
        src: NodeIndex,
        dst: NodeIndex,
        kind_match: fn(&EdgeKind) -> bool,
    ) -> bool {
        cfg.edges(src)
            .any(|e| e.target() == dst && kind_match(e.weight()))
    }

    #[test]
    fn js_if_and_short_circuit() {
        // `if (a && b) { then(); }`
        // Should produce 2 If nodes: [a] --True--> [b]
        // False from a → else-path, False from b → else-path
        let src = b"function f() { if (a && b) { then(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            2,
            "Expected 2 If nodes for `a && b`, got {}",
            ifs.len()
        );

        // Find which is `a` and which is `b` by condition_vars
        let a_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
            .copied()
            .unwrap();
        let b_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
            .copied()
            .unwrap();

        // True edge from a to b
        assert!(
            has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::True)),
            "Expected True edge from a to b"
        );

        // Both a and b should have False edges going somewhere (else-path)
        let a_false: Vec<_> = cfg
            .edges(a_node)
            .filter(|e| matches!(e.weight(), EdgeKind::False))
            .collect();
        let b_false: Vec<_> = cfg
            .edges(b_node)
            .filter(|e| matches!(e.weight(), EdgeKind::False))
            .collect();
        assert!(!a_false.is_empty(), "Expected False edge from a");
        assert!(!b_false.is_empty(), "Expected False edge from b");
    }

    #[test]
    fn js_if_or_short_circuit() {
        // `if (a || b) { then(); }`
        // Should produce 2 If nodes: [a] --False--> [b]
        // True from a → then-path, True from b → then-path
        let src = b"function f() { if (a || b) { then(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            2,
            "Expected 2 If nodes for `a || b`, got {}",
            ifs.len()
        );

        let a_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
            .copied()
            .unwrap();
        let b_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
            .copied()
            .unwrap();

        // False edge from a to b
        assert!(
            has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::False)),
            "Expected False edge from a to b"
        );

        // Both a and b should have True edges
        let a_true: Vec<_> = cfg
            .edges(a_node)
            .filter(|e| matches!(e.weight(), EdgeKind::True))
            .collect();
        let b_true: Vec<_> = cfg
            .edges(b_node)
            .filter(|e| matches!(e.weight(), EdgeKind::True))
            .collect();
        assert!(!a_true.is_empty(), "Expected True edge from a");
        assert!(!b_true.is_empty(), "Expected True edge from b");
    }

    #[test]
    fn js_if_nested_and_or() {
        // `if (a && (b || c)) { then(); }`
        // 3 If nodes: [a] --True--> [b], [b] --False--> [c]
        // True from b or c → then; False from a or c → else
        let src = b"function f() { if (a && (b || c)) { then(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            3,
            "Expected 3 If nodes for `a && (b || c)`, got {}",
            ifs.len()
        );

        let a_node = ifs
            .iter()
            .find(|&&n| {
                let vars = &cfg[n].condition_vars;
                vars.contains(&"a".to_string()) && vars.len() == 1
            })
            .copied()
            .unwrap();
        let b_node = ifs
            .iter()
            .find(|&&n| {
                let vars = &cfg[n].condition_vars;
                vars.contains(&"b".to_string()) && vars.len() == 1
            })
            .copied()
            .unwrap();
        let c_node = ifs
            .iter()
            .find(|&&n| {
                let vars = &cfg[n].condition_vars;
                vars.contains(&"c".to_string()) && vars.len() == 1
            })
            .copied()
            .unwrap();

        // a --True--> b
        assert!(has_edge(&cfg, a_node, b_node, |e| matches!(
            e,
            EdgeKind::True
        )));
        // b --False--> c
        assert!(has_edge(&cfg, b_node, c_node, |e| matches!(
            e,
            EdgeKind::False
        )));
    }

    #[test]
    fn js_while_and_short_circuit() {
        // `while (a && b) { body(); }`
        // Loop header + 2 If nodes, back-edge goes to header
        let src = b"function f() { while (a && b) { body(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            2,
            "Expected 2 If nodes in while condition, got {}",
            ifs.len()
        );

        // There should be a Loop header
        let loop_headers: Vec<_> = cfg
            .node_indices()
            .filter(|&n| cfg[n].kind == StmtKind::Loop)
            .collect();
        assert_eq!(loop_headers.len(), 1, "Expected 1 Loop header");
        let header = loop_headers[0];

        // Back-edges should go to header
        let back_edges: Vec<_> = cfg
            .edge_references()
            .filter(|e| matches!(e.weight(), EdgeKind::Back))
            .collect();
        assert!(!back_edges.is_empty(), "Expected back edges");
        for e in &back_edges {
            assert_eq!(
                e.target(),
                header,
                "Back edge should go to loop header, not into condition chain"
            );
        }
    }

    #[test]
    fn python_if_and() {
        // Python uses `boolean_operator` with `and` token
        let src = b"def f():\n    if a and b:\n        pass\n";
        let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "python", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            2,
            "Expected 2 If nodes for Python `a and b`, got {}",
            ifs.len()
        );

        let a_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
            .copied()
            .unwrap();
        let b_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
            .copied()
            .unwrap();

        assert!(
            has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::True)),
            "Expected True edge from a to b in Python and"
        );
    }

    #[test]
    fn ruby_unless_and() {
        // `unless a && b` — chain built, branches swapped
        // Body should run when condition is false
        let src = b"def f\n  unless a && b\n    x\n  end\nend\n";
        let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            2,
            "Expected 2 If nodes for Ruby `unless a && b`, got {}",
            ifs.len()
        );

        let a_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
            .copied()
            .unwrap();
        let b_node = ifs
            .iter()
            .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
            .copied()
            .unwrap();

        // Still has True edge from a to b (the chain is the same)
        assert!(
            has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::True)),
            "Expected True edge from a to b in unless"
        );

        // For `unless`, the False exits should connect to the body with False edge
        // (since body runs when condition is false)
        let a_false_targets: Vec<_> = cfg
            .edges(a_node)
            .filter(|e| matches!(e.weight(), EdgeKind::False))
            .map(|e| e.target())
            .collect();
        // a's false exit should connect to the body (not to a pass-through)
        // because for `unless (a && b)`, when a is false the full condition is false,
        // meaning the body should execute
        assert!(
            !a_false_targets.is_empty(),
            "a should have False edges in unless"
        );
    }

    #[test]
    fn while_short_circuit_continue() {
        // `while (a && b) { if (cond) { continue; } body(); }`
        // Verify continue goes to loop header
        let src = b"function f() { while (a && b) { if (cond) { continue; } body(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let loop_headers: Vec<_> = cfg
            .node_indices()
            .filter(|&n| cfg[n].kind == StmtKind::Loop)
            .collect();
        assert_eq!(loop_headers.len(), 1);
        let header = loop_headers[0];

        // Continue nodes should have back-edge to header
        let continue_nodes: Vec<_> = cfg
            .node_indices()
            .filter(|&n| cfg[n].kind == StmtKind::Continue)
            .collect();
        assert!(!continue_nodes.is_empty(), "Expected continue node");
        for &cont in &continue_nodes {
            assert!(
                has_edge(&cfg, cont, header, |e| matches!(e, EdgeKind::Back)),
                "Continue should have back-edge to loop header"
            );
        }
    }

    #[test]
    fn negated_boolean_no_decomposition() {
        // `!(a && b)` should NOT be decomposed (De Morgan out of scope)
        let src = b"function f() { if (!(a && b)) { then(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        // Should be exactly 1 If node (no decomposition)
        assert_eq!(
            ifs.len(),
            1,
            "Negated boolean should NOT be decomposed, got {} If nodes",
            ifs.len()
        );
    }

    #[test]
    fn js_triple_and_chain() {
        // `if (a && b && c) { then(); }`
        // Tree-sitter parses as `(a && b) && c` → left-to-right chain
        let src = b"function f() { if (a && b && c) { then(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            3,
            "Expected 3 If nodes for `a && b && c`, got {}",
            ifs.len()
        );
    }

    #[test]
    fn js_or_precedence_with_and() {
        // `if (a || b && c) { then(); }`
        // Tree-sitter respects precedence: `a || (b && c)`
        // → [a] --False--> [b] --True--> [c]
        // True from a or c → then; False from c (and b) → else
        let src = b"function f() { if (a || b && c) { then(); } }";
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

        let ifs = if_nodes(&cfg);
        assert_eq!(
            ifs.len(),
            3,
            "Expected 3 If nodes for `a || b && c`, got {}",
            ifs.len()
        );
    }
}
