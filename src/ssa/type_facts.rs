use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use super::ir::*;
use super::const_prop::ConstLattice;
use crate::cfg::Cfg;
use crate::symbol::Lang;

/// Inferred type kind for an SSA value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)] // All variants are part of the public API
pub enum TypeKind {
    String,
    Int,
    Bool,
    Object,
    Array,
    Null,
    Unknown,
    // Security-relevant abstract types (Phase 10)
    HttpResponse,
    DatabaseConnection,
    FileHandle,
    Url,
    HttpClient,
}

impl TypeKind {
    /// Returns the label prefix for constructing type-qualified callee names.
    /// E.g., `HttpClient` → `"HttpClient"` so `client.send()` resolves to `"HttpClient.send"`.
    pub fn label_prefix(&self) -> Option<&'static str> {
        match self {
            Self::HttpClient => Some("HttpClient"),
            Self::HttpResponse => Some("HttpResponse"),
            Self::DatabaseConnection => Some("DatabaseConnection"),
            Self::FileHandle => Some("FileHandle"),
            Self::Url => Some("URL"),
            _ => None,
        }
    }
}

/// A type fact about an SSA value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeFact {
    pub kind: TypeKind,
    pub nullable: bool,
}

impl TypeFact {
    fn unknown() -> Self {
        TypeFact {
            kind: TypeKind::Unknown,
            nullable: false,
        }
    }

    fn from_kind(kind: TypeKind) -> Self {
        let nullable = matches!(kind, TypeKind::Null);
        TypeFact { kind, nullable }
    }

    /// Meet two type facts (for phi nodes).
    fn meet(&self, other: &Self) -> Self {
        let nullable = self.nullable || other.nullable;
        let kind = if self.kind == other.kind {
            self.kind.clone()
        } else {
            TypeKind::Unknown
        };
        TypeFact { kind, nullable }
    }
}

/// Result of type fact analysis.
pub struct TypeFactResult {
    pub facts: HashMap<SsaValue, TypeFact>,
}

impl TypeFactResult {
    /// Check if an SSA value is known to be an integer type.
    /// Useful for suppressing SQL injection findings on integer-typed values.
    pub fn is_int(&self, v: SsaValue) -> bool {
        self.facts
            .get(&v)
            .is_some_and(|f| matches!(f.kind, TypeKind::Int))
    }

    /// Get the inferred type kind for an SSA value.
    pub fn get_type(&self, v: SsaValue) -> Option<&TypeKind> {
        self.facts.get(&v).map(|f| &f.kind)
    }

    /// Check if an SSA value has a specific type kind.
    pub fn is_type(&self, v: SsaValue, kind: &TypeKind) -> bool {
        self.facts.get(&v).is_some_and(|f| f.kind == *kind)
    }
}

/// Infer a type from a constructor or factory call callee name.
///
/// Maps known constructor/factory patterns to security-relevant types.
/// Uses suffix matching consistent with the label classification system.
pub(crate) fn constructor_type(lang: Lang, callee: &str) -> Option<TypeKind> {
    // Normalize: take the last segment for suffix matching
    let suffix = callee.rsplit('.').next().unwrap_or(callee);
    match lang {
        Lang::Java => match suffix {
            "URL" | "URI" => Some(TypeKind::Url),
            "newHttpClient" | "newBuilder" if callee.contains("HttpClient") => {
                Some(TypeKind::HttpClient)
            }
            "getConnection" => Some(TypeKind::DatabaseConnection),
            "FileInputStream" | "FileOutputStream" | "FileReader" | "FileWriter"
            | "BufferedReader" | "BufferedWriter" => Some(TypeKind::FileHandle),
            "getWriter" | "getOutputStream" => Some(TypeKind::HttpResponse),
            _ => None,
        },
        Lang::JavaScript | Lang::TypeScript => match suffix {
            "URL" => Some(TypeKind::Url),
            "Request" | "XMLHttpRequest" => Some(TypeKind::HttpClient),
            _ => None,
        },
        Lang::Python => {
            // Python uses qualified names: requests.get, sqlite3.connect, etc.
            if callee.starts_with("requests.") || callee == "urlopen" {
                Some(TypeKind::HttpClient)
            } else if suffix == "connect"
                && (callee.contains("sqlite3")
                    || callee.contains("psycopg2")
                    || callee.contains("mysql"))
            {
                Some(TypeKind::DatabaseConnection)
            } else if suffix == "open" && !callee.contains('.') {
                // Bare `open()` is file I/O in Python
                Some(TypeKind::FileHandle)
            } else {
                None
            }
        }
        Lang::Go => {
            if callee.contains("http.") && matches!(suffix, "NewRequest" | "Get" | "Post") {
                Some(TypeKind::HttpClient)
            } else if callee.contains("sql.") && suffix == "Open" {
                Some(TypeKind::DatabaseConnection)
            } else if callee.contains("os.") && matches!(suffix, "Open" | "Create" | "OpenFile") {
                Some(TypeKind::FileHandle)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Analyze types for all SSA values.
///
/// Uses constant propagation results to seed types from known constants,
/// then propagates through copies and phi nodes. Constructor/factory calls
/// are mapped to security-relevant types when `lang` is provided.
pub fn analyze_types(
    body: &SsaBody,
    _cfg: &Cfg,
    consts: &HashMap<SsaValue, ConstLattice>,
    lang: Option<Lang>,
) -> TypeFactResult {
    let mut facts: HashMap<SsaValue, TypeFact> = HashMap::new();

    // First pass: direct type inference from instruction kind and constant values
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let fact = match &inst.op {
                SsaOp::Const(_) => {
                    // Use constant propagation result if available
                    match consts.get(&inst.value) {
                        Some(ConstLattice::Str(_)) => TypeFact::from_kind(TypeKind::String),
                        Some(ConstLattice::Int(_)) => TypeFact::from_kind(TypeKind::Int),
                        Some(ConstLattice::Bool(_)) => TypeFact::from_kind(TypeKind::Bool),
                        Some(ConstLattice::Null) => TypeFact::from_kind(TypeKind::Null),
                        _ => TypeFact::unknown(),
                    }
                }
                SsaOp::Source => TypeFact::from_kind(TypeKind::String),
                SsaOp::Param { .. } => TypeFact::unknown(),
                SsaOp::CatchParam => TypeFact::from_kind(TypeKind::Object),
                SsaOp::Call { callee, .. } => {
                    lang.and_then(|l| constructor_type(l, callee))
                        .map(TypeFact::from_kind)
                        .unwrap_or_else(TypeFact::unknown)
                }
                SsaOp::Nop => TypeFact::unknown(),
                SsaOp::Assign(uses) if uses.len() == 1 => {
                    // Defer: will be filled in second pass
                    TypeFact::unknown()
                }
                SsaOp::Assign(_) => TypeFact::unknown(),
                SsaOp::Phi(_) => {
                    // Defer: will be filled in second pass
                    TypeFact::unknown()
                }
            };
            facts.insert(inst.value, fact);
        }
    }

    // Second pass: propagate through copies and phi nodes
    // Simple fixed-point: iterate until no changes (typically 1-2 rounds)
    for _ in 0..10 {
        let mut changed = false;

        for block in &body.blocks {
            // Phi nodes
            for inst in &block.phis {
                if let SsaOp::Phi(operands) = &inst.op {
                    let mut result: Option<TypeFact> = None;
                    for (_, val) in operands {
                        let operand_fact = facts.get(val).cloned().unwrap_or_else(TypeFact::unknown);
                        result = Some(match result {
                            None => operand_fact,
                            Some(acc) => acc.meet(&operand_fact),
                        });
                    }
                    if let Some(new_fact) = result {
                        let old = facts.get(&inst.value);
                        if old != Some(&new_fact) {
                            facts.insert(inst.value, new_fact);
                            changed = true;
                        }
                    }
                }
            }

            // Copy assignments
            for inst in &block.body {
                if let SsaOp::Assign(uses) = &inst.op {
                    if uses.len() == 1 {
                        let src_fact = facts.get(&uses[0]).cloned().unwrap_or_else(TypeFact::unknown);
                        let old = facts.get(&inst.value);
                        if old != Some(&src_fact) {
                            facts.insert(inst.value, src_fact);
                            changed = true;
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    TypeFactResult { facts }
}

// ── Java Type Hierarchy (bounded, sink-relevant) ─────────────────────────

/// Minimal Java type hierarchy for subtype queries.
///
/// Scope: **sink-relevant framework types only** (Servlet API, JDBC, HTTP
/// clients, I/O streams). NOT a general Java class hierarchy.
/// Used for `instanceof` resolution and type-qualified method dispatch.
pub struct TypeHierarchy;

/// (subtype, &[supertypes]) — sink-relevant framework types only.
static JAVA_HIERARCHY: &[(&str, &[&str])] = &[
    ("HttpServletResponse", &["ServletResponse"]),
    ("HttpServletRequest", &["ServletRequest"]),
    ("HttpURLConnection", &["URLConnection"]),
    ("CloseableHttpClient", &["HttpClient"]),
    ("FileInputStream", &["InputStream"]),
    ("FileOutputStream", &["OutputStream"]),
    ("BufferedReader", &["Reader"]),
    ("BufferedWriter", &["Writer"]),
    ("PreparedStatement", &["Statement"]),
    ("ArrayList", &["List", "Collection"]),
    ("HashMap", &["Map"]),
    ("StringBuilder", &["CharSequence"]),
    ("StringBuffer", &["CharSequence"]),
];

impl TypeHierarchy {
    /// Check if `sub` is a subtype of `super_type` in the bounded Java
    /// framework hierarchy. Returns `true` for identity (`sub == super_type`).
    pub fn is_subtype_of(sub: &str, super_type: &str) -> bool {
        if sub == super_type {
            return true;
        }
        JAVA_HIERARCHY
            .iter()
            .any(|(s, supers)| *s == sub && supers.contains(&super_type))
    }

    /// Resolve a class name through the hierarchy to a [`TypeKind`].
    ///
    /// Tries the class name directly first (via `class_name_to_type_kind`
    /// in the constraint solver), then checks if any registered supertype
    /// maps to a `TypeKind`.
    pub fn resolve_kind(class_name: &str) -> Option<TypeKind> {
        // Direct resolution via the class-name table in solver.rs
        crate::constraint::solver::class_name_to_type_kind(class_name).or_else(|| {
            // Hierarchy fallback: check supertypes
            for (sub, supers) in JAVA_HIERARCHY.iter() {
                if *sub == class_name {
                    for s in *supers {
                        if let Some(k) = crate::constraint::solver::class_name_to_type_kind(s) {
                            return Some(k);
                        }
                    }
                }
            }
            None
        })
    }
}

// ── Go Interface Satisfaction (bounded, conservative) ────────────────────

/// Go interface satisfaction table for **sink-relevant interfaces only**.
///
/// Conservative: unknown interfaces → `true` (could satisfy).
/// Only [`definitely_not`](GoInterfaceTable::definitely_not) is used for
/// suppression — it returns `true` only when the type provably cannot
/// implement the interface.
pub struct GoInterfaceTable;

impl GoInterfaceTable {
    /// Check if a [`TypeKind`] is known to satisfy a Go interface.
    pub fn satisfies(kind: &TypeKind, interface: &str) -> bool {
        match interface {
            "http.ResponseWriter" | "ResponseWriter" => {
                matches!(kind, TypeKind::HttpResponse)
            }
            "io.Writer" | "Writer" => {
                matches!(kind, TypeKind::HttpResponse | TypeKind::FileHandle)
            }
            "io.Reader" | "Reader" => matches!(kind, TypeKind::FileHandle),
            _ => true, // Unknown interface → conservative (could satisfy)
        }
    }

    /// Check if a [`TypeKind`] is known to NOT satisfy a specific interface.
    ///
    /// Returns `true` only when we are confident the type cannot implement
    /// the interface. Used for sink suppression.
    pub fn definitely_not(kind: &TypeKind, interface: &str) -> bool {
        match interface {
            "http.ResponseWriter" | "ResponseWriter" => matches!(
                kind,
                TypeKind::Int
                    | TypeKind::Bool
                    | TypeKind::String
                    | TypeKind::FileHandle
                    | TypeKind::DatabaseConnection
                    | TypeKind::Url
            ),
            _ => false, // Unknown interface → conservative
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::NodeIndex;
    use petgraph::Graph;
    use smallvec::SmallVec;

    #[test]
    fn const_types_inferred() {
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let n2 = NodeIndex::new(2);

        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("42".into())),
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Const(Some("\"hello\"".into())),
                        cfg_node: n1,
                        var_name: Some("y".into()),
                        span: (3, 10),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Source,
                        cfg_node: n2,
                        var_name: Some("z".into()),
                        span: (11, 15),
                    },
                ],
                terminator: Terminator::Return,
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef { var_name: Some("x".into()), cfg_node: n0, block: BlockId(0) },
                ValueDef { var_name: Some("y".into()), cfg_node: n1, block: BlockId(0) },
                ValueDef { var_name: Some("z".into()), cfg_node: n2, block: BlockId(0) },
            ],
            cfg_node_map: [
                (n0, SsaValue(0)),
                (n1, SsaValue(1)),
                (n2, SsaValue(2)),
            ]
            .into_iter()
            .collect(),
            exception_edges: vec![],
        };

        let consts = HashMap::from([
            (SsaValue(0), ConstLattice::Int(42)),
            (SsaValue(1), ConstLattice::Str("hello".into())),
        ]);

        let cfg: crate::cfg::Cfg = Graph::new();
        let result = analyze_types(&body, &cfg, &consts, None);

        assert!(result.is_int(SsaValue(0)));
        assert_eq!(result.facts.get(&SsaValue(1)).unwrap().kind, TypeKind::String);
        assert_eq!(result.facts.get(&SsaValue(2)).unwrap().kind, TypeKind::String); // Source
    }

    #[test]
    fn security_type_variants_distinct() {
        // New security-relevant types are distinct from each other and meet() collapses
        // mismatched types to Unknown.
        let http_client = TypeFact::from_kind(TypeKind::HttpClient);
        let url = TypeFact::from_kind(TypeKind::Url);
        let http_response = TypeFact::from_kind(TypeKind::HttpResponse);
        let db_conn = TypeFact::from_kind(TypeKind::DatabaseConnection);
        let file_handle = TypeFact::from_kind(TypeKind::FileHandle);

        // Same-type meet preserves
        assert_eq!(http_client.meet(&http_client).kind, TypeKind::HttpClient);
        assert_eq!(url.meet(&url).kind, TypeKind::Url);

        // Cross-type meet collapses to Unknown
        assert_eq!(http_client.meet(&url).kind, TypeKind::Unknown);
        assert_eq!(http_response.meet(&db_conn).kind, TypeKind::Unknown);
        assert_eq!(file_handle.meet(&http_client).kind, TypeKind::Unknown);
    }

    #[test]
    fn label_prefix_mappings() {
        assert_eq!(TypeKind::HttpClient.label_prefix(), Some("HttpClient"));
        assert_eq!(TypeKind::HttpResponse.label_prefix(), Some("HttpResponse"));
        assert_eq!(TypeKind::Url.label_prefix(), Some("URL"));
        assert_eq!(TypeKind::DatabaseConnection.label_prefix(), Some("DatabaseConnection"));
        assert_eq!(TypeKind::FileHandle.label_prefix(), Some("FileHandle"));
        // Primitive types have no label prefix
        assert_eq!(TypeKind::String.label_prefix(), None);
        assert_eq!(TypeKind::Int.label_prefix(), None);
        assert_eq!(TypeKind::Unknown.label_prefix(), None);
    }

    #[test]
    fn constructor_type_inference() {
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);

        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Call {
                            callee: "URL".into(),
                            args: vec![],
                            receiver: None,
                        },
                        cfg_node: n0,
                        var_name: Some("url".into()),
                        span: (0, 5),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Call {
                            callee: "HttpClient.newHttpClient".into(),
                            args: vec![],
                            receiver: None,
                        },
                        cfg_node: n1,
                        var_name: Some("client".into()),
                        span: (6, 20),
                    },
                ],
                terminator: Terminator::Return,
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef { var_name: Some("url".into()), cfg_node: n0, block: BlockId(0) },
                ValueDef { var_name: Some("client".into()), cfg_node: n1, block: BlockId(0) },
            ],
            cfg_node_map: [
                (n0, SsaValue(0)),
                (n1, SsaValue(1)),
            ]
            .into_iter()
            .collect(),
            exception_edges: vec![],
        };

        let consts = HashMap::new();
        let cfg: crate::cfg::Cfg = Graph::new();
        let result = analyze_types(&body, &cfg, &consts, Some(Lang::Java));

        assert_eq!(result.get_type(SsaValue(0)), Some(&TypeKind::Url));
        assert_eq!(result.get_type(SsaValue(1)), Some(&TypeKind::HttpClient));

        // JS also infers URL
        let result_js = analyze_types(&body, &cfg, &consts, Some(Lang::JavaScript));
        assert_eq!(result_js.get_type(SsaValue(0)), Some(&TypeKind::Url));
        // JS doesn't know HttpClient.newHttpClient
        assert_eq!(result_js.get_type(SsaValue(1)), Some(&TypeKind::Unknown));
    }

    #[test]
    fn get_type_and_is_type() {
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::HttpClient));
        facts.insert(SsaValue(1), TypeFact::from_kind(TypeKind::Int));
        let result = TypeFactResult { facts };

        assert_eq!(result.get_type(SsaValue(0)), Some(&TypeKind::HttpClient));
        assert!(result.is_type(SsaValue(0), &TypeKind::HttpClient));
        assert!(!result.is_type(SsaValue(0), &TypeKind::Url));
        assert!(result.is_int(SsaValue(1)));
        assert_eq!(result.get_type(SsaValue(99)), None);
    }

    // ── TypeHierarchy::is_subtype_of ─────────────────────────────────────

    #[test]
    fn hierarchy_http_servlet_response_is_servlet_response() {
        assert!(TypeHierarchy::is_subtype_of(
            "HttpServletResponse",
            "ServletResponse"
        ));
    }

    #[test]
    fn hierarchy_string_is_not_servlet_response() {
        assert!(!TypeHierarchy::is_subtype_of("String", "ServletResponse"));
    }

    #[test]
    fn hierarchy_identity_subtype() {
        assert!(TypeHierarchy::is_subtype_of(
            "HttpServletResponse",
            "HttpServletResponse"
        ));
    }

    // ── TypeHierarchy::resolve_kind ──────────────────────────────────────

    #[test]
    fn resolve_closeable_http_client() {
        assert_eq!(
            TypeHierarchy::resolve_kind("CloseableHttpClient"),
            Some(TypeKind::HttpClient)
        );
    }

    #[test]
    fn resolve_string_builder() {
        assert_eq!(
            TypeHierarchy::resolve_kind("StringBuilder"),
            Some(TypeKind::String)
        );
    }

    // ── GoInterfaceTable::definitely_not ─────────────────────────────────

    #[test]
    fn go_file_handle_definitely_not_response_writer() {
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::FileHandle,
            "http.ResponseWriter"
        ));
    }

    #[test]
    fn go_http_response_not_definitely_not_response_writer() {
        assert!(!GoInterfaceTable::definitely_not(
            &TypeKind::HttpResponse,
            "http.ResponseWriter"
        ));
    }

    // ── GoInterfaceTable::satisfies ──────────────────────────────────────

    #[test]
    fn go_http_response_satisfies_response_writer() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "http.ResponseWriter"
        ));
    }

    #[test]
    fn go_file_handle_does_not_satisfy_response_writer() {
        assert!(!GoInterfaceTable::satisfies(
            &TypeKind::FileHandle,
            "http.ResponseWriter"
        ));
    }

    #[test]
    fn go_http_response_satisfies_io_writer() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "io.Writer"
        ));
    }
}
