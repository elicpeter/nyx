pub mod path_state;

use crate::callgraph::normalize_callee_name;
use crate::cfg::{Cfg, EdgeKind, FuncSummaries, NodeInfo, StmtKind};
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, SourceKind};
use crate::summary::{CalleeResolution, GlobalSummaries};
use crate::symbol::Lang;
use path_state::{PathState, Predicate, PredicateKind, classify_condition};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use smallvec::SmallVec;
use std::collections::HashMap;
use tracing::debug;

// ─── Path-sensitivity bail-out thresholds ────────────────────────────────────

/// CFG node count above which path sensitivity is disabled.
const PATH_SENSITIVITY_NODE_LIMIT: usize = 500;

/// BFS queue size above which new predicate recording stops (existing
/// predicates on queued items are preserved).
const PATH_SENSITIVITY_QUEUE_LIMIT: usize = 10_000;

/// Maximum path-state variants per `(node, taint_hash)` key in the
/// seen-state map.  When this limit is reached, new variants are only
/// accepted if they have strictly better [`PathState::priority`] than
/// the worst existing entry.
const MAX_PATH_VARIANTS_PER_KEY: usize = 4;

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
    /// The kind of source that originated the taint.
    pub source_kind: SourceKind,
    /// Whether all tainted sink variables are guarded by a validation
    /// predicate on this path (metadata only — does not change severity).
    #[allow(dead_code)] // surfaced in Diag output (task 4)
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    #[allow(dead_code)] // surfaced in Diag output (task 4)
    pub guard_kind: Option<PredicateKind>,
}

/// Order-independent hash of a taint map.
///
/// Uses XOR of per-entry hashes so the result is the same regardless of
/// iteration order — no allocation or sorting required.
fn taint_hash(taint: &HashMap<String, Cap>) -> u64 {
    let mut h: u64 = 0;
    for (k, bits) in taint {
        // Per-entry hash: FNV-1a-style mixing of key bytes + cap bits.
        let mut entry_h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
        for b in k.as_bytes() {
            entry_h ^= *b as u64;
            entry_h = entry_h.wrapping_mul(0x0100_0000_01b3); // FNV prime
        }
        entry_h ^= bits.bits() as u64;
        entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
        h ^= entry_h;
    }
    h
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
    // Normalize qualified callee names (e.g. "env::var" → "var") so that
    // resolution matches the bare function `name` stored in summaries.
    let normalized = normalize_callee_name(callee);

    // 1) Local (same-file): scan local summaries for matching name + lang + namespace
    let local_matches: Vec<_> = local
        .iter()
        .filter(|(k, _)| {
            k.name == normalized && k.lang == caller_lang && k.namespace == caller_namespace
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

    // 2) Global same-language — delegate to shared resolution helper
    if let Some(gs) = global {
        match gs.resolve_callee_key(normalized, caller_lang, caller_namespace, None) {
            CalleeResolution::Resolved(target_key) => {
                if let Some(fs) = gs.get(&target_key) {
                    return Some(ResolvedSummary {
                        source_caps: fs.source_caps(),
                        sanitizer_caps: fs.sanitizer_caps(),
                        sink_caps: fs.sink_caps(),
                        propagates_taint: fs.propagates_taint,
                    });
                }
            }
            CalleeResolution::NotFound | CalleeResolution::Ambiguous(_) => {
                // Fall through to interop edges
            }
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

/// Apply taint transfer for a single node, mutating `out` in place.
///
/// Callers should clone the taint map before calling if they need
/// the original state preserved.
fn apply_taint(
    node: &NodeInfo,
    out: &mut HashMap<String, Cap>,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
) {
    debug!(target: "taint", "Applying taint to node: {:?}", node);
    debug!(target: "taint", "Taint: {:?}", out);

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

                return;
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
}

/// Run taint analysis on a single file's CFG.
///
/// `global_summaries` is `None` for pass‑1 / single‑file mode and
/// `Some(&map)` for pass‑2 cross‑file analysis.
///
/// When path sensitivity is enabled (CFG node count ≤
/// [`PATH_SENSITIVITY_NODE_LIMIT`]), the BFS carries a [`PathState`]
/// alongside the taint map.  This records branch predicates along each
/// path, prunes infeasible (contradictory) paths, and annotates findings
/// with `path_validated` metadata when the sink is guarded by a
/// validation check.
pub fn analyse_file(
    cfg: &Cfg,
    entry: NodeIndex,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
) -> Vec<Finding> {
    use std::collections::{HashMap, VecDeque};

    /// Queue item: current CFG node + taint map + path predicates.
    #[derive(Clone)]
    struct Item {
        node: NodeIndex,
        taint: HashMap<String, Cap>,
        path_state: PathState,
    }

    // ── Predecessor map for path reconstruction ──────────────────────────
    // Key: (node, taint_hash, path_hash)
    // Value: predecessor key
    type Key = (NodeIndex, u64, u64);
    let mut pred: HashMap<Key, Key> = HashMap::new();

    // ── Seen states ──────────────────────────────────────────────────────
    // Two-tier scheme: primary key = (node, taint_hash) maps to a bounded
    // list of (path_hash, priority) pairs.  This prevents state explosion
    // while preserving path sensitivity.
    type PathPriority = (bool, usize);
    type SeenVariants = SmallVec<[(u64, PathPriority); 2]>;
    let mut seen: HashMap<(NodeIndex, u64), SeenVariants> = HashMap::new();

    let path_sensitive = cfg.node_count() <= PATH_SENSITIVITY_NODE_LIMIT;

    let mut findings: Vec<Finding> = Vec::new();

    let mut q = VecDeque::new();
    let init_path = PathState::new();
    let init_path_h = init_path.state_hash();
    q.push_back(Item {
        node: entry,
        taint: HashMap::new(),
        path_state: init_path,
    });
    seen.entry((entry, 0))
        .or_default()
        .push((init_path_h, (true, path_state::MAX_PATH_PREDICATES)));

    while let Some(Item {
        node,
        taint,
        path_state,
    }) = q.pop_front()
    {
        let caller_func = cfg[node].enclosing_func.as_deref().unwrap_or("");
        let mut out = taint.clone();
        apply_taint(
            &cfg[node],
            &mut out,
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
            _ => cfg[node]
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
                .unwrap_or(Cap::empty()),
        };

        if !sink_caps.is_empty() {
            let tainted_sink_vars: Vec<&str> = cfg[node]
                .uses
                .iter()
                .filter(|u| {
                    out.get(*u)
                        .is_some_and(|b| (*b & sink_caps) != Cap::empty())
                })
                .map(|s| s.as_str())
                .collect();

            if !tainted_sink_vars.is_empty() {
                // ── Path validation metadata ─────────────────────────────
                let all_validated = tainted_sink_vars
                    .iter()
                    .all(|v| path_state.has_validation_for(v));

                let guard_kind = if all_validated {
                    tainted_sink_vars
                        .iter()
                        .find_map(|v| path_state.guard_kind_for(v))
                } else {
                    None
                };

                // ── Reconstruct path backwards to source ─────────────────
                let sink_node = node;
                let mut path = vec![node];
                let mut source_node = node;
                let mut key = (node, taint_hash(&taint), path_state.state_hash());

                while let Some(&(prev, prev_th, prev_ph)) = pred.get(&key) {
                    path.push(prev);

                    if matches!(cfg[prev].label, Some(DataLabel::Source(_))) {
                        source_node = prev;
                        break;
                    }

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

                    key = (prev, prev_th, prev_ph);
                }

                path.reverse();

                let source_kind = match cfg[source_node].label {
                    Some(DataLabel::Source(caps)) => {
                        let callee = cfg[source_node].callee.as_deref().unwrap_or("");
                        crate::labels::infer_source_kind(caps, callee)
                    }
                    _ => SourceKind::Unknown,
                };

                findings.push(Finding {
                    sink: sink_node,
                    source: source_node,
                    path,
                    source_kind,
                    path_validated: all_validated,
                    guard_kind,
                });
            }
        }

        // ── Enqueue successors (edge-aware) ──────────────────────────────
        let out_h = taint_hash(&out);
        let in_h = taint_hash(&taint);
        let in_ph = path_state.state_hash();
        let edges: Vec<_> = cfg.edges(node).collect();
        let edge_count = edges.len();

        for (i, edge_ref) in edges.into_iter().enumerate() {
            let succ = edge_ref.target();
            let edge_kind = *edge_ref.weight();

            // Clone or move the path state (move the last to avoid clone).
            let mut next_path = if i + 1 == edge_count {
                // Safety: we won't use path_state after this iteration.
                path_state.clone() // last edge — could use take but clone is fine for SmallVec
            } else {
                path_state.clone()
            };

            // ── Record predicate when leaving an If node via True/False ──
            if path_sensitive
                && q.len() < PATH_SENSITIVITY_QUEUE_LIMIT
                && cfg[node].kind == StmtKind::If
                && !cfg[node].condition_vars.is_empty()
                && matches!(edge_kind, EdgeKind::True | EdgeKind::False)
            {
                let cond_text = cfg[node].condition_text.as_deref().unwrap_or("");
                let kind = classify_condition(cond_text);
                let polarity = matches!(edge_kind, EdgeKind::True) ^ cfg[node].condition_negated;
                next_path.push(Predicate {
                    vars: cfg[node].condition_vars.iter().cloned().collect(),
                    kind,
                    polarity,
                    origin: node,
                });
            }

            // ── Prune infeasible (contradictory) paths ───────────────────
            if next_path.is_contradictory() {
                debug!(target: "taint", "Pruning infeasible path at node {}", succ.index());
                continue;
            }

            // ── Two-tier seen-state check with deterministic eviction ────
            let path_h = next_path.state_hash();
            let taint_key = (succ, out_h);
            let variants = seen.entry(taint_key).or_default();

            if variants.iter().any(|(h, _)| *h == path_h) {
                continue; // exact duplicate
            }

            let new_prio = next_path.priority();
            if variants.len() >= MAX_PATH_VARIANTS_PER_KEY {
                // Find the worst (lowest priority) existing entry.
                let worst_idx = variants
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, prio))| *prio)
                    .map(|(idx, _)| idx);
                if let Some(wi) = worst_idx {
                    if new_prio > variants[wi].1 {
                        variants.swap_remove(wi);
                    } else {
                        continue; // new state is not better — skip
                    }
                } else {
                    continue;
                }
            }

            variants.push((path_h, new_prio));
            pred.insert((succ, out_h, path_h), (node, in_h, in_ph));

            // Move the taint map into the last successor to avoid a clone.
            let taint_for_succ = if i + 1 == edge_count {
                std::mem::take(&mut out)
            } else {
                out.clone()
            };
            q.push_back(Item {
                node: succ,
                taint: taint_for_succ,
                path_state: next_path,
            });
        }
    }

    // ── Deduplicate findings ────────────────────────────────────────────
    // Path sensitivity may produce multiple findings at the same
    // (sink, source) pair via different path states.  Keep at most one
    // per (sink, source), preferring the one with `path_validated = true`
    // (provides the most useful metadata).
    findings.sort_by_key(|f| (f.sink.index(), f.source.index(), !f.path_validated));
    findings.dedup_by_key(|f| (f.sink, f.source));

    findings
}

#[cfg(test)]
mod tests;
