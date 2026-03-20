use crate::callgraph::normalize_callee_name;
use crate::cfg::{EdgeKind, FuncSummaries, NodeInfo, StmtKind};
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel};
use crate::state::engine::Transfer;
use crate::state::lattice::Lattice;
use crate::state::symbol::{SymbolId, SymbolInterner};
use crate::summary::{CalleeResolution, GlobalSummaries};
use crate::symbol::Lang;
use crate::taint::domain::{TaintOrigin, TaintState, VarTaint, predicate_kind_bit};
use crate::taint::path_state::{PredicateKind, classify_condition};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

/// Events emitted by the taint transfer function during Phase 2.
#[derive(Clone, Debug)]
pub enum TaintEvent {
    SinkReached {
        sink_node: NodeIndex,
        tainted_vars: Vec<(SymbolId, Cap, SmallVec<[TaintOrigin; 2]>)>,
        #[allow(dead_code)]
        sink_caps: Cap,
        all_validated: bool,
        guard_kind: Option<PredicateKind>,
    },
}

/// Taint transfer function for forward dataflow analysis.
pub struct TaintTransfer<'a> {
    pub lang: Lang,
    pub namespace: &'a str,
    pub interner: &'a SymbolInterner,
    pub local_summaries: &'a FuncSummaries,
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub interop_edges: &'a [InteropEdge],
    /// For JS two-level solve: top-level taint state seeded into function solves.
    pub global_seed: Option<&'a TaintState>,
    /// Optional scope filter: if set, only process nodes whose enclosing_func matches.
    /// None = process all nodes. Some(None) = top-level only. Some(Some(name)) = function only.
    pub scope_filter: Option<Option<&'a str>>,
}

impl Transfer<TaintState> for TaintTransfer<'_> {
    type Event = TaintEvent;

    fn apply(
        &self,
        node: NodeIndex,
        info: &NodeInfo,
        edge: Option<EdgeKind>,
        mut state: TaintState,
    ) -> (TaintState, Vec<TaintEvent>) {
        let mut events = Vec::new();

        // Scope filter: skip nodes outside our scope (return state unchanged)
        if let Some(ref filter) = self.scope_filter {
            let node_func = info.enclosing_func.as_deref();
            if node_func != *filter {
                return (state, events);
            }
        }

        let caller_func = info.enclosing_func.as_deref().unwrap_or("");

        // ── Apply taint transfer ────────────────────────────────────────
        match info.label {
            Some(DataLabel::Source(bits)) => {
                self.apply_source(node, info, bits, &mut state);
            }
            Some(DataLabel::Sanitizer(bits)) => {
                self.apply_sanitizer(info, bits, &mut state);
            }
            _ if info.kind == StmtKind::Call => {
                self.apply_call(node, info, caller_func, &mut state);
            }
            _ => {
                self.apply_assignment(info, &mut state);
            }
        }

        // ── If-node predicate handling (edge-aware) ─────────────────────
        if info.kind == StmtKind::If
            && !info.condition_vars.is_empty()
            && matches!(edge, Some(EdgeKind::True) | Some(EdgeKind::False))
        {
            let cond_text = info.condition_text.as_deref().unwrap_or("");
            let kind = classify_condition(cond_text);
            let polarity = matches!(edge, Some(EdgeKind::True)) ^ info.condition_negated;

            // ValidationCall handling
            if kind == PredicateKind::ValidationCall && polarity {
                for var in &info.condition_vars {
                    if let Some(sym) = self.interner.get(var) {
                        state.validated_may.insert(sym);
                        state.validated_must.insert(sym);
                    }
                }
            }

            // Predicate summary for whitelisted kinds (contradiction pruning)
            if let Some(bit_idx) = predicate_kind_bit(kind) {
                for var in &info.condition_vars {
                    if let Some(sym) = self.interner.get(var) {
                        let mut summary = state.get_predicate(sym);
                        if polarity {
                            summary.known_true |= 1 << bit_idx;
                        } else {
                            summary.known_false |= 1 << bit_idx;
                        }
                        state.set_predicate(sym, summary);
                    }
                }
            }

            // Contradiction pruning: if any variable has contradictory predicates,
            // this is an infeasible path → return bot (monotonically kills branch).
            if state.has_contradiction() {
                return (TaintState::bot(), events);
            }
        }

        // ── Sink check ──────────────────────────────────────────────────
        let sink_caps = self.resolve_sink_caps(info, caller_func);
        if !sink_caps.is_empty() {
            let tainted_vars = self.collect_tainted_sink_vars(info, &state, sink_caps);
            if !tainted_vars.is_empty() {
                let all_validated = tainted_vars
                    .iter()
                    .all(|(sym, _, _)| state.validated_may.contains(*sym));

                let guard_kind = if all_validated {
                    Some(PredicateKind::ValidationCall)
                } else {
                    None
                };

                events.push(TaintEvent::SinkReached {
                    sink_node: node,
                    tainted_vars,
                    sink_caps,
                    all_validated,
                    guard_kind,
                });
            }
        }

        (state, events)
    }

    fn iteration_budget(&self) -> usize {
        100_000
    }

    fn on_budget_exceeded(&self) -> bool {
        tracing::warn!("taint analysis: worklist budget exceeded, returning partial results");
        false
    }
}

impl TaintTransfer<'_> {
    /// Apply a Source label: insert taint for the defined variable.
    fn apply_source(&self, node: NodeIndex, info: &NodeInfo, bits: Cap, state: &mut TaintState) {
        if let Some(ref v) = info.defines
            && let Some(sym) = self.interner.get(v)
        {
            let callee = info.callee.as_deref().unwrap_or("");
            let source_kind = crate::labels::infer_source_kind(bits, callee);
            let origin = TaintOrigin { node, source_kind };

            match state.get(sym) {
                Some(existing) => {
                    let mut new_taint = existing.clone();
                    new_taint.caps |= bits;
                    if new_taint.origins.len() < 4
                        && !new_taint.origins.iter().any(|o| o.node == node)
                    {
                        new_taint.origins.push(origin);
                    }
                    state.set(sym, new_taint);
                }
                None => {
                    state.set(
                        sym,
                        VarTaint {
                            caps: bits,
                            origins: SmallVec::from_elem(origin, 1),
                        },
                    );
                }
            }
        }
    }

    /// Apply a Sanitizer label: propagate input taint, then strip sanitizer bits.
    fn apply_sanitizer(&self, info: &NodeInfo, bits: Cap, state: &mut TaintState) {
        if let Some(ref v) = info.defines
            && let Some(sym) = self.interner.get(v)
        {
            let (combined_caps, combined_origins) = self.collect_uses_taint(info, state);
            let new_caps = combined_caps & !bits;
            if new_caps.is_empty() {
                state.remove(sym);
            } else {
                state.set(
                    sym,
                    VarTaint {
                        caps: new_caps,
                        origins: combined_origins,
                    },
                );
            }
        }
    }

    /// Apply a function call: resolve callee and compute return taint.
    fn apply_call(
        &self,
        node: NodeIndex,
        info: &NodeInfo,
        caller_func: &str,
        state: &mut TaintState,
    ) {
        if let Some(ref callee) = info.callee
            && let Some(resolved) = self.resolve_callee(callee, caller_func, info.call_ordinal)
        {
            let mut return_bits = Cap::empty();
            let mut return_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

            // 1. Source behaviour
            if !resolved.source_caps.is_empty() {
                return_bits |= resolved.source_caps;
                let callee_str = info.callee.as_deref().unwrap_or("");
                let source_kind =
                    crate::labels::infer_source_kind(resolved.source_caps, callee_str);
                let origin = TaintOrigin { node, source_kind };
                if !return_origins.iter().any(|o| o.node == node) {
                    return_origins.push(origin);
                }
            }

            // 2. Propagation
            if resolved.propagates_taint {
                let (use_caps, use_origins) = self.collect_uses_taint(info, state);
                return_bits |= use_caps;
                for orig in &use_origins {
                    if return_origins.len() < 4
                        && !return_origins.iter().any(|o| o.node == orig.node)
                    {
                        return_origins.push(*orig);
                    }
                }
            }

            // 3. Sanitizer behaviour (applied last so it always wins)
            return_bits &= !resolved.sanitizer_caps;

            // Write result
            if let Some(ref v) = info.defines
                && let Some(sym) = self.interner.get(v)
            {
                if return_bits.is_empty() {
                    state.remove(sym);
                } else {
                    state.set(
                        sym,
                        VarTaint {
                            caps: return_bits,
                            origins: return_origins,
                        },
                    );
                }
            }

            return;
        }

        // Scoped libcurl special case: propagate URL taint to handle
        if self.try_curl_url_propagation(info, state) {
            return;
        }

        // Unresolved call — fall through to default gen/kill
        self.apply_assignment(info, state);
    }

    /// Default gen/kill: propagate taint through variable assignments.
    fn apply_assignment(&self, info: &NodeInfo, state: &mut TaintState) {
        if matches!(
            info.label,
            Some(DataLabel::Source(_)) | Some(DataLabel::Sanitizer(_))
        ) {
            return;
        }

        if let Some(ref d) = info.defines
            && let Some(sym) = self.interner.get(d)
        {
            let (combined_caps, combined_origins) = self.collect_uses_taint(info, state);
            if combined_caps.is_empty() {
                state.remove(sym);
            } else {
                state.set(
                    sym,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                    },
                );
            }
        }
    }

    /// Collect taint from all `uses` variables (union of caps + merge origins).
    fn collect_uses_taint(
        &self,
        info: &NodeInfo,
        state: &TaintState,
    ) -> (Cap, SmallVec<[TaintOrigin; 2]>) {
        let mut combined_caps = Cap::empty();
        let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

        for u in &info.uses {
            let taint = self.lookup_var(u, state);
            if let Some(t) = taint {
                combined_caps |= t.caps;
                for orig in &t.origins {
                    if combined_origins.len() < 4
                        && !combined_origins.iter().any(|o| o.node == orig.node)
                    {
                        combined_origins.push(*orig);
                    }
                }
            }
        }

        (combined_caps, combined_origins)
    }

    /// Look up a variable's taint, falling back to global_seed for JS two-level solve.
    fn lookup_var<'a>(&'a self, name: &str, state: &'a TaintState) -> Option<&'a VarTaint> {
        if let Some(sym) = self.interner.get(name) {
            if let Some(taint) = state.get(sym) {
                return Some(taint);
            }
            // Fall back to global seed (JS two-level solve)
            if let Some(seed) = self.global_seed {
                return seed.get(sym);
            }
        }
        None
    }

    /// Resolve sink caps from label or callee summary.
    fn resolve_sink_caps(&self, info: &NodeInfo, caller_func: &str) -> Cap {
        match info.label {
            Some(DataLabel::Sink(caps)) => caps,
            _ => info
                .callee
                .as_ref()
                .and_then(|c| self.resolve_callee(c, caller_func, info.call_ordinal))
                .filter(|r| !r.sink_caps.is_empty())
                .map(|r| r.sink_caps)
                .unwrap_or(Cap::empty()),
        }
    }

    /// Collect tainted variables at a sink node.
    fn collect_tainted_sink_vars(
        &self,
        info: &NodeInfo,
        state: &TaintState,
        sink_caps: Cap,
    ) -> Vec<(SymbolId, Cap, SmallVec<[TaintOrigin; 2]>)> {
        let mut result = Vec::new();
        for u in &info.uses {
            if let Some(taint) = self.lookup_var(u, state)
                && (taint.caps & sink_caps) != Cap::empty()
                && let Some(sym) = self.interner.get(u)
            {
                result.push((sym, taint.caps, taint.origins.clone()));
            }
        }
        result
    }

    /// Scoped libcurl special case: when `curl_easy_setopt(handle, CURLOPT_URL, value)`
    /// is called and `value` is tainted, propagate that taint to `handle`.
    ///
    /// Only fires when CURLOPT_URL is present in the arguments — other curl options
    /// (CURLOPT_TIMEOUT, CURLOPT_RETURNTRANSFER, etc.) do not taint the handle.
    ///
    /// Does NOT re-collect the handle's own taint — only the URL value's taint is
    /// propagated to avoid self-amplification.
    fn try_curl_url_propagation(&self, info: &NodeInfo, state: &mut TaintState) -> bool {
        if info.defines.is_some() {
            return false;
        }
        let callee = match info.callee.as_deref() {
            Some(c) if c.ends_with("curl_easy_setopt") => c,
            _ => return false,
        };
        // Require CURLOPT_URL in the arguments
        if !info.uses.iter().any(|u| u == "CURLOPT_URL") {
            return false;
        }
        // Handle = first uses entry that isn't the callee name
        let handle_name = match info.uses.iter().find(|u| u.as_str() != callee) {
            Some(h) => h.clone(),
            None => return false,
        };
        let handle_sym = match self.interner.get(&handle_name) {
            Some(s) => s,
            None => return false,
        };
        // Collect taint ONLY from the URL value — skip callee, handle, and CURLOPT_URL
        let mut url_caps = Cap::empty();
        let mut url_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        for u in &info.uses {
            if u == callee || u == &handle_name || u == "CURLOPT_URL" {
                continue;
            }
            if let Some(taint) = self.lookup_var(u, state) {
                url_caps |= taint.caps;
                for orig in &taint.origins {
                    if url_origins.len() < 4
                        && !url_origins.iter().any(|o| o.node == orig.node)
                    {
                        url_origins.push(*orig);
                    }
                }
            }
        }
        if url_caps.is_empty() {
            return false;
        }
        // Merge URL taint into handle (monotone: caps OR, origins union)
        match state.get(handle_sym) {
            Some(existing) => {
                let mut merged = existing.clone();
                merged.caps |= url_caps;
                for orig in &url_origins {
                    if merged.origins.len() < 4
                        && !merged.origins.iter().any(|o| o.node == orig.node)
                    {
                        merged.origins.push(*orig);
                    }
                }
                state.set(handle_sym, merged);
            }
            None => {
                state.set(
                    handle_sym,
                    VarTaint {
                        caps: url_caps,
                        origins: url_origins,
                    },
                );
            }
        }
        true
    }

    /// Resolve a callee name to its summary (local → global → interop).
    fn resolve_callee(
        &self,
        callee: &str,
        caller_func: &str,
        call_ordinal: u32,
    ) -> Option<ResolvedSummary> {
        let normalized = normalize_callee_name(callee);

        // 1) Local (same-file)
        let local_matches: Vec<_> = self
            .local_summaries
            .iter()
            .filter(|(k, _)| {
                k.name == normalized && k.lang == self.lang && k.namespace == self.namespace
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
        if local_matches.len() > 1 {
            return None;
        }

        // 2) Global same-language
        if let Some(gs) = self.global_summaries {
            match gs.resolve_callee_key(normalized, self.lang, self.namespace, None) {
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
                CalleeResolution::NotFound | CalleeResolution::Ambiguous(_) => {}
            }
        }

        // 3) Interop edges
        for edge in self.interop_edges {
            if edge.from.caller_lang == self.lang
                && edge.from.caller_namespace == self.namespace
                && edge.from.callee_symbol == callee
                && (edge.from.caller_func.is_empty() || edge.from.caller_func == caller_func)
                && (edge.from.ordinal == 0 || edge.from.ordinal == call_ordinal)
                && let Some(gs) = self.global_summaries
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

        None
    }
}

/// Resolved summary for a callee.
struct ResolvedSummary {
    source_caps: Cap,
    sanitizer_caps: Cap,
    sink_caps: Cap,
    propagates_taint: bool,
}
