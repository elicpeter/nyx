use crate::interop::InteropEdge;
use crate::summary::{CalleeResolution, GlobalSummaries};
use crate::symbol::FuncKey;
use petgraph::graph::NodeIndex;
use petgraph::prelude::*;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata attached to each call-graph edge.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// The raw callee string as it appeared in source (e.g. `"env::var"`).
    /// Preserved for diagnostics — **not** the normalized form used for resolution.
    #[allow(dead_code)] // used for future diagnostics and path display
    pub call_site: String,
}

/// A callee that could not be resolved to any known function definition.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields used for future diagnostics reporting
pub struct UnresolvedCallee {
    pub caller: FuncKey,
    pub callee_name: String,
}

/// A callee that matched multiple function definitions — ambiguous.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields used for future diagnostics reporting
pub struct AmbiguousCallee {
    pub caller: FuncKey,
    pub callee_name: String,
    pub candidates: Vec<FuncKey>,
}

/// The whole-program call graph.
///
/// Nodes are [`FuncKey`]s (one per function definition across all files).
/// Edges represent call-site relationships resolved after pass 1.
pub struct CallGraph {
    pub graph: DiGraph<FuncKey, CallEdge>,
    /// `FuncKey → NodeIndex` for quick lookup.
    #[allow(dead_code)] // used for future topo-ordered analysis and call-graph queries
    pub index: HashMap<FuncKey, NodeIndex>,
    /// Callee strings that could not be resolved to any [`FuncKey`].
    pub unresolved_not_found: Vec<UnresolvedCallee>,
    /// Callee strings that matched multiple candidates.
    pub unresolved_ambiguous: Vec<AmbiguousCallee>,
}

/// Result of SCC / topological analysis on the call graph.
pub struct CallGraphAnalysis {
    /// Strongly connected components.
    pub sccs: Vec<Vec<NodeIndex>>,
    /// Maps each `NodeIndex` to its SCC index in [`sccs`].
    #[allow(dead_code)] // used for future topo-ordered taint propagation
    pub node_to_scc: HashMap<NodeIndex, usize>,
    /// SCC indices in **callee-first** (leaves-first) order.
    ///
    /// Functions with no callees appear first; callers appear later.
    /// Suitable for bottom-up taint propagation.
    #[allow(dead_code)] // used for future topo-ordered taint propagation
    pub topo_scc_callee_first: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Callee-name normalization
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the last segment of a qualified callee name for resolution.
///
/// ```text
/// "env::var"              → "var"
/// "std::process::Command" → "Command"
/// "obj.method"            → "method"
/// "pkg.mod.func"          → "func"
/// "foo"                   → "foo"  (unchanged)
/// ""                      → ""     (edge case)
/// ```
///
/// The original raw text is preserved on [`CallEdge::call_site`] for
/// diagnostics; this function only produces the lookup key.
pub(crate) fn normalize_callee_name(raw: &str) -> &str {
    // Split on "::" first (Rust-style qualification), take last segment.
    let after_colons = raw.rsplit("::").next().unwrap_or(raw);
    // Then split on "." (method calls, Python/JS dotted paths), take last segment.
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Call-graph construction
// ─────────────────────────────────────────────────────────────────────────────

/// Build the whole-program call graph from merged summaries.
///
/// Resolution mirrors `GlobalSummaries::resolve_callee_key`:
///   1. Normalize callee name (last segment after `::` or `.`)
///   2. Same-language, arity-filtered, namespace-disambiguated lookup
///   3. Interop edges (explicit cross-language bridges)
///
/// Unresolved and ambiguous callees are recorded for diagnostics but
/// do **not** create edges.
pub fn build_call_graph(summaries: &GlobalSummaries, interop_edges: &[InteropEdge]) -> CallGraph {
    let mut graph = DiGraph::new();
    let mut index = HashMap::new();

    // 1. Create one node per FuncKey.
    for (key, _) in summaries.iter() {
        let idx = graph.add_node(key.clone());
        index.insert(key.clone(), idx);
    }

    let mut unresolved_not_found = Vec::new();
    let mut unresolved_ambiguous = Vec::new();

    // 2. Resolve callees and add edges.
    for (caller_key, summary) in summaries.iter() {
        let caller_node = index[caller_key];

        for raw_callee in &summary.callees {
            let normalized = normalize_callee_name(raw_callee);

            match summaries.resolve_callee_key(
                normalized,
                caller_key.lang,
                &caller_key.namespace,
                None,
            ) {
                CalleeResolution::Resolved(target_key) => {
                    if let Some(&target_node) = index.get(&target_key) {
                        graph.add_edge(
                            caller_node,
                            target_node,
                            CallEdge {
                                call_site: raw_callee.clone(),
                            },
                        );
                    }
                }
                CalleeResolution::NotFound => {
                    // Try interop edges before recording as not-found.
                    if let Some(target_key) =
                        resolve_via_interop(raw_callee, caller_key, interop_edges)
                        && let Some(&target_node) = index.get(&target_key)
                    {
                        graph.add_edge(
                            caller_node,
                            target_node,
                            CallEdge {
                                call_site: raw_callee.clone(),
                            },
                        );
                        continue;
                    }
                    unresolved_not_found.push(UnresolvedCallee {
                        caller: caller_key.clone(),
                        callee_name: raw_callee.clone(),
                    });
                }
                CalleeResolution::Ambiguous(candidates) => {
                    unresolved_ambiguous.push(AmbiguousCallee {
                        caller: caller_key.clone(),
                        callee_name: raw_callee.clone(),
                        candidates,
                    });
                }
            }
        }
    }

    CallGraph {
        graph,
        index,
        unresolved_not_found,
        unresolved_ambiguous,
    }
}

/// Check interop edges for a matching cross-language bridge.
fn resolve_via_interop(
    raw_callee: &str,
    caller_key: &FuncKey,
    interop_edges: &[InteropEdge],
) -> Option<FuncKey> {
    for edge in interop_edges {
        if edge.from.caller_lang == caller_key.lang
            && edge.from.caller_namespace == caller_key.namespace
            && edge.from.callee_symbol == raw_callee
            && (edge.from.caller_func.is_empty() || edge.from.caller_func == caller_key.name)
        {
            return Some(edge.to.clone());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
//  SCC / topological analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Compute SCC decomposition and topological ordering of the call graph.
///
/// `petgraph::algo::tarjan_scc` returns SCCs in *reverse* topological order
/// of the condensation DAG — i.e. leaf SCCs (no outgoing cross-SCC edges)
/// come **first**.  That is exactly the **callee-first** order suitable for
/// bottom-up taint propagation.
pub fn analyse(cg: &CallGraph) -> CallGraphAnalysis {
    let sccs = petgraph::algo::tarjan_scc(&cg.graph);

    let mut node_to_scc = HashMap::with_capacity(cg.graph.node_count());
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for &node in scc {
            node_to_scc.insert(node, scc_idx);
        }
    }

    // tarjan_scc already gives callee-first ordering.
    let topo_scc_callee_first: Vec<usize> = (0..sccs.len()).collect();

    CallGraphAnalysis {
        sccs,
        node_to_scc,
        topo_scc_callee_first,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::CallSiteKey;
    use crate::summary::{FuncSummary, merge_summaries};
    use crate::symbol::Lang;

    /// Helper to create a minimal FuncSummary.
    fn make_summary(
        name: &str,
        file_path: &str,
        lang: &str,
        param_count: usize,
        callees: Vec<&str>,
    ) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: file_path.into(),
            lang: lang.into(),
            param_count,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: callees.into_iter().map(String::from).collect(),
        }
    }

    // ── normalize_callee_name ────────────────────────────────────────────

    #[test]
    fn normalize_callee_basic() {
        assert_eq!(normalize_callee_name("env::var"), "var");
        assert_eq!(normalize_callee_name("std::process::Command"), "Command");
        assert_eq!(normalize_callee_name("obj.method"), "method");
        assert_eq!(normalize_callee_name("pkg.mod.func"), "func");
        assert_eq!(normalize_callee_name("foo"), "foo");
        assert_eq!(normalize_callee_name(""), "");
    }

    // ── same name, different Rust modules ────────────────────────────────

    #[test]
    fn same_name_different_rust_modules() {
        let helper_a = make_summary("helper", "src/a.rs", "rust", 0, vec![]);
        let helper_b = make_summary("helper", "src/b.rs", "rust", 0, vec![]);
        let caller = make_summary("caller", "src/a.rs", "rust", 0, vec!["helper"]);

        let gs = merge_summaries(vec![helper_a, helper_b, caller], None);
        let cg = build_call_graph(&gs, &[]);

        // Two helper nodes + one caller node = 3 nodes
        assert_eq!(cg.graph.node_count(), 3);

        // Caller is in src/a.rs, so "helper" resolves to src/a.rs::helper
        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/a.rs".into(),
            name: "caller".into(),
            arity: Some(0),
        };
        let helper_a_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/a.rs".into(),
            name: "helper".into(),
            arity: Some(0),
        };

        let caller_node = cg.index[&caller_key];
        let helper_a_node = cg.index[&helper_a_key];

        // Exactly one edge: caller → helper_a
        let edges: Vec<_> = cg
            .graph
            .edges(caller_node)
            .filter(|e| e.target() == helper_a_node)
            .collect();
        assert_eq!(edges.len(), 1);
        assert!(cg.unresolved_not_found.is_empty());
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    // ── same name, Python vs Rust ────────────────────────────────────────

    #[test]
    fn same_name_python_and_rust() {
        let py_foo = make_summary("foo", "handler.py", "python", 0, vec![]);
        let rs_foo = make_summary("foo", "handler.rs", "rust", 0, vec![]);
        // Python caller calls "foo" — should only see the Python one
        let py_caller = make_summary("main", "app.py", "python", 0, vec!["foo"]);

        let gs = merge_summaries(vec![py_foo, rs_foo, py_caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.node_count(), 3);

        let py_foo_key = FuncKey {
            lang: Lang::Python,
            namespace: "handler.py".into(),
            name: "foo".into(),
            arity: Some(0),
        };
        let caller_key = FuncKey {
            lang: Lang::Python,
            namespace: "app.py".into(),
            name: "main".into(),
            arity: Some(0),
        };

        let caller_node = cg.index[&caller_key];
        let py_foo_node = cg.index[&py_foo_key];

        // Edge goes to Python foo, not Rust foo
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target(), py_foo_node);
    }

    // ── arity differences → separate nodes ───────────────────────────────

    #[test]
    fn arity_differences_separate_nodes() {
        let helper1 = make_summary("helper", "lib.rs", "rust", 1, vec![]);
        let helper2 = make_summary("helper", "lib.rs", "rust", 2, vec![]);

        let gs = merge_summaries(vec![helper1, helper2], None);
        let cg = build_call_graph(&gs, &[]);

        // Two separate nodes (different arity → different FuncKey)
        assert_eq!(cg.graph.node_count(), 2);

        let key1 = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "helper".into(),
            arity: Some(1),
        };
        let key2 = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "helper".into(),
            arity: Some(2),
        };
        assert!(cg.index.contains_key(&key1));
        assert!(cg.index.contains_key(&key2));
    }

    // ── recursive SCC detection ──────────────────────────────────────────

    #[test]
    fn recursive_scc_detection() {
        let a = make_summary("a", "lib.rs", "rust", 0, vec!["b"]);
        let b = make_summary("b", "lib.rs", "rust", 0, vec!["a"]);

        let gs = merge_summaries(vec![a, b], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 2); // a→b and b→a

        let analysis = analyse(&cg);

        // Both nodes should be in the same SCC
        let key_a = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "a".into(),
            arity: Some(0),
        };
        let key_b = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "b".into(),
            arity: Some(0),
        };

        let scc_a = analysis.node_to_scc[&cg.index[&key_a]];
        let scc_b = analysis.node_to_scc[&cg.index[&key_b]];
        assert_eq!(scc_a, scc_b);
        assert_eq!(analysis.sccs[scc_a].len(), 2);
    }

    // ── unresolved callee → recorded as not found ────────────────────────

    #[test]
    fn unresolved_callee_recorded_as_not_found() {
        let caller = make_summary("caller", "lib.rs", "rust", 0, vec!["nonexistent"]);

        let gs = merge_summaries(vec![caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 0);
        assert_eq!(cg.unresolved_not_found.len(), 1);
        assert_eq!(cg.unresolved_not_found[0].callee_name, "nonexistent");
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    // ── ambiguous callee → recorded as ambiguous ─────────────────────────

    #[test]
    fn ambiguous_callee_recorded() {
        // Two "helper" functions in different namespaces.
        let helper_a = make_summary("helper", "a.rs", "rust", 0, vec![]);
        let helper_b = make_summary("helper", "b.rs", "rust", 0, vec![]);
        // Caller is in a THIRD namespace, so neither is preferred.
        let caller = make_summary("caller", "c.rs", "rust", 0, vec!["helper"]);

        let gs = merge_summaries(vec![helper_a, helper_b, caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 0); // no edge — ambiguous
        assert!(cg.unresolved_not_found.is_empty());
        assert_eq!(cg.unresolved_ambiguous.len(), 1);
        assert_eq!(cg.unresolved_ambiguous[0].callee_name, "helper");
        assert_eq!(cg.unresolved_ambiguous[0].candidates.len(), 2);
    }

    // ── diamond topo order (callee-first) ────────────────────────────────

    #[test]
    fn diamond_topo_callee_first() {
        // A → B, A → C, B → D, C → D
        let d = make_summary("d", "lib.rs", "rust", 0, vec![]);
        let b = make_summary("b", "lib.rs", "rust", 0, vec!["d"]);
        let c = make_summary("c", "lib.rs", "rust", 0, vec!["d"]);
        let a = make_summary("a", "lib.rs", "rust", 0, vec!["b", "c"]);

        let gs = merge_summaries(vec![a, b, c, d], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.node_count(), 4);

        let analysis = analyse(&cg);

        let key = |name: &str| FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: name.into(),
            arity: Some(0),
        };

        let scc_of = |name: &str| analysis.node_to_scc[&cg.index[&key(name)]];
        let topo_pos = |name: &str| {
            analysis
                .topo_scc_callee_first
                .iter()
                .position(|&s| s == scc_of(name))
                .unwrap()
        };

        // D (leaf) must come before B and C, which must come before A (root).
        assert!(topo_pos("d") < topo_pos("b"));
        assert!(topo_pos("d") < topo_pos("c"));
        assert!(topo_pos("b") < topo_pos("a"));
        assert!(topo_pos("c") < topo_pos("a"));
    }

    // ── interop edge resolution ──────────────────────────────────────────

    #[test]
    fn interop_edge_resolution() {
        let py_caller = make_summary("process", "handler.py", "python", 0, vec!["js_func"]);
        let js_target = make_summary("js_func", "util.js", "javascript", 1, vec![]);

        let gs = merge_summaries(vec![py_caller, js_target], None);

        let interop = vec![InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Python,
                caller_namespace: "handler.py".into(),
                caller_func: String::new(), // wildcard
                callee_symbol: "js_func".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::JavaScript,
                namespace: "util.js".into(),
                name: "js_func".into(),
                arity: Some(1),
            },
            arg_map: vec![],
            ret_taints: false,
        }];

        let cg = build_call_graph(&gs, &interop);

        let caller_key = FuncKey {
            lang: Lang::Python,
            namespace: "handler.py".into(),
            name: "process".into(),
            arity: Some(0),
        };
        let target_key = FuncKey {
            lang: Lang::JavaScript,
            namespace: "util.js".into(),
            name: "js_func".into(),
            arity: Some(1),
        };

        let caller_node = cg.index[&caller_key];
        let target_node = cg.index[&target_key];

        let edges: Vec<_> = cg
            .graph
            .edges(caller_node)
            .filter(|e| e.target() == target_node)
            .collect();
        assert_eq!(edges.len(), 1);
        assert!(cg.unresolved_not_found.is_empty());
    }

    // ── namespace normalization consistency ───────────────────────────────

    #[test]
    fn namespace_normalization_consistency() {
        // FuncSummary::func_key with a scan root produces the same namespace
        // string that would be used as caller_namespace in resolution.
        let summary = FuncSummary {
            name: "my_func".into(),
            file_path: "/home/user/proj/src/lib.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        };

        let root = "/home/user/proj";
        let key = summary.func_key(Some(root));

        // The namespace in the key must be the same as what normalize_namespace produces
        let expected_ns = crate::symbol::normalize_namespace(&summary.file_path, Some(root));
        assert_eq!(key.namespace, expected_ns);
        assert_eq!(key.namespace, "src/lib.rs");
    }

    // ── raw call_site preserved on edge ──────────────────────────────────

    #[test]
    fn raw_call_site_preserved_on_edge() {
        // Callee "env::var" normalizes to "var" for resolution, but
        // the edge should retain the original raw text.
        let source = make_summary("var", "util.rs", "rust", 0, vec![]);
        let caller = make_summary("main", "util.rs", "rust", 0, vec!["env::var"]);

        let gs = merge_summaries(vec![source, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "util.rs".into(),
            name: "main".into(),
            arity: Some(0),
        };
        let caller_node = cg.index[&caller_key];

        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 1);
        // Raw call_site preserved, not the normalized "var"
        assert_eq!(edges[0].weight().call_site, "env::var");
    }
}
