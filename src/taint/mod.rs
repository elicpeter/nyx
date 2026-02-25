use crate::cfg::{Cfg, FuncSummaries, NodeInfo, StmtKind};
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel};
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;
use tracing::debug;

/// A detected taint finding with both source and sink locations.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The CFG node where tainted data reaches a dangerous operation.
    pub sink: NodeIndex,
    /// The CFG node where taint originated (may be Entry if source is
    /// cross-file and couldn't be pinpointed to a specific node).
    pub source: NodeIndex,
    /// The full path from source to sink through the CFG.
    #[allow(dead_code)] // used for future detailed diagnostics / path display
    pub path: Vec<NodeIndex>,
}

fn taint_hash(taint: &HashMap<String, Cap>) -> u64 {
    let mut v: Vec<_> = taint.iter().collect();
    v.sort_by_key(|(k, _)| k.as_str());
    let mut hasher = blake3::Hasher::new();
    for (k, bits) in v {
        hasher.update(k.as_bytes());
        hasher.update(&bits.bits().to_le_bytes());
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(digest.as_bytes()[0..8].try_into().unwrap())
}

/// Resolved summary for a callee — a uniform view regardless of whether the
/// summary came from a local (same‑file) or global (cross‑file) source.
struct ResolvedSummary {
    source_caps: Cap,
    sanitizer_caps: Cap,
    sink_caps: Cap,
    propagates_taint: bool,
}

/// Try to resolve a callee name using conservative same-language resolution.
///
/// Resolution order:
/// 1. Local (same-file): exact name + same lang + same namespace
/// 2. Global same-language: via `lookup_same_lang`; must be unambiguous
/// 3. Interop edges: explicit cross-language bridges
/// 4. No cross-language fallback
#[allow(clippy::too_many_arguments)]
fn resolve_callee(
    callee: &str,
    caller_lang: Lang,
    caller_namespace: &str,
    caller_func: &str,
    call_ordinal: u32,
    local: &FuncSummaries,
    global: Option<&GlobalSummaries>,
    interop_edges: &[InteropEdge],
) -> Option<ResolvedSummary> {
    // 1) Local (same-file): scan local summaries for matching name + lang + namespace
    let local_matches: Vec<_> = local
        .iter()
        .filter(|(k, _)| {
            k.name == callee && k.lang == caller_lang && k.namespace == caller_namespace
        })
        .collect();

    if local_matches.len() == 1 {
        let (_, ls) = local_matches[0];
        return Some(ResolvedSummary {
            source_caps: ls.source_caps,
            sanitizer_caps: ls.sanitizer_caps,
            sink_caps: ls.sink_caps,
            propagates_taint: ls.propagates_taint,
        });
    }

    // Multiple local matches — try arity disambiguation (future), for now return None
    if local_matches.len() > 1 {
        return None;
    }

    // 2) Global same-language
    if let Some(gs) = global {
        let matches = gs.lookup_same_lang(caller_lang, callee);
        if matches.len() == 1 {
            let (_, fs) = matches[0];
            return Some(ResolvedSummary {
                source_caps: fs.source_caps(),
                sanitizer_caps: fs.sanitizer_caps(),
                sink_caps: fs.sink_caps(),
                propagates_taint: fs.propagates_taint,
            });
        }
        // Multiple matches — try namespace match first
        if matches.len() > 1 {
            let same_ns: Vec<_> = matches
                .iter()
                .filter(|(k, _)| k.namespace == caller_namespace)
                .collect();
            if same_ns.len() == 1 {
                let (_, fs) = same_ns[0];
                return Some(ResolvedSummary {
                    source_caps: fs.source_caps(),
                    sanitizer_caps: fs.sanitizer_caps(),
                    sink_caps: fs.sink_caps(),
                    propagates_taint: fs.propagates_taint,
                });
            }
            // Still ambiguous — return None (conservative)
            return None;
        }
    }

    // 3) Interop edges: explicit cross-language bridges
    for edge in interop_edges {
        if edge.from.caller_lang == caller_lang
            && edge.from.caller_namespace == caller_namespace
            && edge.from.callee_symbol == callee
            && (edge.from.caller_func.is_empty() || edge.from.caller_func == caller_func)
            && (edge.from.ordinal == 0 || edge.from.ordinal == call_ordinal)
        {
            // Look up the target in global summaries by exact FuncKey
            if let Some(gs) = global
                && let Some(fs) = gs.get(&edge.to)
            {
                return Some(ResolvedSummary {
                    source_caps: fs.source_caps(),
                    sanitizer_caps: fs.sanitizer_caps(),
                    sink_caps: fs.sink_caps(),
                    propagates_taint: fs.propagates_taint,
                });
            }
        }
    }

    // 4) No cross-language fallback
    None
}

fn apply_taint(
    node: &NodeInfo,
    taint: &HashMap<String, Cap>,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
) -> HashMap<String, Cap> {
    debug!(target: "taint", "Applying taint to node: {:?}", node);
    debug!(target: "taint", "Taint: {:?}", taint);
    let mut out = taint.clone();

    let caller_func = node.enclosing_func.as_deref().unwrap_or("");

    match node.label {
        // A new untrusted value enters the program
        Some(DataLabel::Source(bits)) => {
            if let Some(v) = &node.defines {
                out.insert(v.clone(), bits);
            }
        }
        // Sanitizer: propagate input taint through the assignment FIRST,
        // then strip the sanitizer's capability bits.  This ensures that
        // `let y = sanitize_html(&x)` gives y the taint of x minus the
        // HTML_ESCAPE bit — rather than leaving y completely clean (which
        // would hide "wrong sanitiser for this sink" bugs).
        Some(DataLabel::Sanitizer(bits)) => {
            if let Some(v) = &node.defines {
                // 1. Propagate: union taint from all read variables
                let mut combined = Cap::empty();
                for u in &node.uses {
                    if let Some(b) = out.get(u) {
                        combined |= *b;
                    }
                }
                // 2. Strip the sanitiser's bits
                let new = combined & !bits;
                if new.is_empty() {
                    out.remove(v);
                } else {
                    out.insert(v.clone(), new);
                }
            }
        }

        // A function call — resolve against local + global summaries
        _ if node.kind == StmtKind::Call => {
            if let Some(callee) = &node.callee
                && let Some(resolved) = resolve_callee(
                    callee,
                    caller_lang,
                    caller_namespace,
                    caller_func,
                    node.call_ordinal,
                    local_summaries,
                    global_summaries,
                    interop_edges,
                )
            {
                // Build the return value's taint bits in stages, then
                // write once at the end.  Order matters:
                //
                //   1. Start with fresh source taint (if the callee is a source)
                //   2. Union with propagated arg taint (if the callee propagates)
                //   3. Strip sanitizer bits last (so sanitization always wins)

                let mut return_bits = Cap::empty();

                // ── 1. Source behaviour ──
                return_bits |= resolved.source_caps;

                // ── 2. Propagation ──
                if resolved.propagates_taint {
                    for u in &node.uses {
                        if let Some(bits) = out.get(u) {
                            return_bits |= *bits;
                        }
                    }
                }

                // ── 3. Sanitizer behaviour (applied last so it always wins) ──
                return_bits &= !resolved.sanitizer_caps;

                // ── Write the result ──
                if let Some(v) = &node.defines {
                    if return_bits.is_empty() {
                        out.remove(v);
                    } else {
                        out.insert(v.clone(), return_bits);
                    }
                }

                // ── Sink behaviour: handled in the main analysis loop
                //    (checked via node.label or resolved summary) ──

                return out;
            }

            // Unresolved call — fall through to default gen/kill below
        }

        // All other statements: classic gen/kill for assignments
        _ => {}
    }

    // Default gen/kill: propagate taint through variable assignments
    if !matches!(
        node.label,
        Some(DataLabel::Source(_)) | Some(DataLabel::Sanitizer(_))
    ) && let Some(d) = &node.defines
    {
        let mut combined = Cap::empty();
        for u in &node.uses {
            if let Some(bits) = out.get(u) {
                combined |= *bits;
            }
        }
        if combined.is_empty() {
            out.remove(d);
        } else {
            out.insert(d.clone(), combined);
        }
    }

    out
}

/// Run taint analysis on a single file's CFG.
///
/// `global_summaries` is `None` for pass‑1 / single‑file mode and
/// `Some(&map)` for pass‑2 cross‑file analysis.
pub fn analyse_file(
    cfg: &Cfg,
    entry: NodeIndex,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
) -> Vec<Finding> {
    use std::collections::{HashMap, HashSet, VecDeque};

    /// Queue item: current CFG node + taint map that holds here
    #[derive(Clone)]
    struct Item {
        node: NodeIndex,
        taint: HashMap<String, Cap>,
    }

    // (node, taint_hash)  →  predecessor key   (for path rebuild)
    type Key = (NodeIndex, u64);
    let mut pred: HashMap<Key, Key> = HashMap::new();

    // Seen states so we do not revisit them infinitely
    let mut seen: HashSet<Key> = HashSet::new();

    // Resulting findings: (sink_node, source_node, full_path)
    let mut findings: Vec<Finding> = Vec::new();

    let mut q = VecDeque::new();
    q.push_back(Item {
        node: entry,
        taint: HashMap::new(),
    });
    seen.insert((entry, 0));

    while let Some(Item { node, taint }) = q.pop_front() {
        let caller_func = cfg[node].enclosing_func.as_deref().unwrap_or("");
        let out = apply_taint(
            &cfg[node],
            &taint,
            local_summaries,
            global_summaries,
            caller_lang,
            caller_namespace,
            interop_edges,
        );

        // ── Sink check ──────────────────────────────────────────────────
        // Two ways a node can be a sink:
        //   1. Its AST label says Sink (existing inline labels)
        //   2. Its callee resolves to a function with sink_caps (cross-file)
        let sink_caps = match cfg[node].label {
            Some(DataLabel::Sink(caps)) => caps,
            _ => {
                // check if callee resolves to a sink
                cfg[node]
                    .callee
                    .as_ref()
                    .and_then(|c| {
                        resolve_callee(
                            c,
                            caller_lang,
                            caller_namespace,
                            caller_func,
                            cfg[node].call_ordinal,
                            local_summaries,
                            global_summaries,
                            interop_edges,
                        )
                    })
                    .filter(|r| !r.sink_caps.is_empty())
                    .map(|r| r.sink_caps)
                    .unwrap_or(Cap::empty())
            }
        };

        if !sink_caps.is_empty() {
            let bad = cfg[node]
                .uses
                .iter()
                .any(|u| out.get(u).is_some_and(|b| (*b & sink_caps) != Cap::empty()));
            if bad {
                // Reconstruct path backwards from sink to source.
                //
                // A node is considered a "source" if:
                //   1. It has an inline DataLabel::Source (same-file), OR
                //   2. It is a Call whose callee resolves to a source via
                //      local or global summaries (cross-file).
                let sink_node = node;
                let mut path = vec![node];
                let mut source_node = node; // fallback: sink itself
                let mut key = (node, taint_hash(&taint));

                while let Some(&(prev, prev_hash)) = pred.get(&key) {
                    path.push(prev);

                    // Check inline source label
                    if matches!(cfg[prev].label, Some(DataLabel::Source(_))) {
                        source_node = prev;
                        break;
                    }

                    // Check cross-file source via resolved callee summary
                    let prev_caller_func = cfg[prev].enclosing_func.as_deref().unwrap_or("");
                    if cfg[prev].kind == StmtKind::Call
                        && let Some(callee) = &cfg[prev].callee
                        && let Some(resolved) = resolve_callee(
                            callee,
                            caller_lang,
                            caller_namespace,
                            prev_caller_func,
                            cfg[prev].call_ordinal,
                            local_summaries,
                            global_summaries,
                            interop_edges,
                        )
                        && !resolved.source_caps.is_empty()
                    {
                        source_node = prev;
                        break;
                    }

                    key = (prev, prev_hash);
                }

                path.reverse();
                findings.push(Finding {
                    sink: sink_node,
                    source: source_node,
                    path,
                });
            }
        }

        // enqueue successors
        for succ in cfg.neighbors(node) {
            let h = taint_hash(&out);
            let key = (succ, h);
            if !seen.contains(&key) {
                seen.insert(key);
                pred.insert(key, (node, taint_hash(&taint)));
                let item = Item {
                    node: succ,
                    taint: out.clone(),
                };
                q.push_back(item);
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests;
