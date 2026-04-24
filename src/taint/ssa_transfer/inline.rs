//! Context-sensitive inline analysis — cache, body, and attribution types.
//!
//! Extracted from the monolithic `ssa_transfer.rs`.  Contains:
//! * [`ArgTaintSig`] — compact per-arg cap signature used as a cache key.
//! * [`InlineResult`] / [`CachedInlineShape`] / [`ReturnShape`] — the
//!   callsite-adapted and callsite-agnostic inline-analysis result types.
//! * [`InlineCache`] — the shared cache map keyed by
//!   `(FuncKey, ArgTaintSig)`.
//! * [`CrossFileNodeMeta`] / [`CalleeSsaBody`] — the serde-able bodies
//!   persisted to SQLite for cross-file context-sensitive analysis.
//! * [`populate_node_meta`] / [`rebuild_body_graph`] — bookkeeping for
//!   cross-file body proxy CFGs.
//!
//! The implementation functions (`inline_analyse_callee`,
//! `apply_cached_shape`, `extract_inline_return_taint`) remain in the
//! parent `mod.rs` because they depend tightly on the block worklist, the
//! `run_ssa_taint_full` entry point, and the callee-resolution pipeline.
//!
//! # Cache key scope and origin attribution
//!
//! The inline-analysis cache below ([`InlineCache`]) is keyed by
//! `(FuncKey, ArgTaintSig)`, where [`ArgTaintSig`] encodes **per-arg
//! capability bits only** — not the identity of the source
//! [`crate::taint::domain::TaintOrigin`]s that produced those caps.  The
//! stored value ([`CachedInlineShape`]) captures **only the structural**
//! shape of the callee's return taint: return caps, callee-internal
//! origins (from `Source` ops inside the callee body), and per-parameter
//! provenance flags that record which formal parameters contributed to
//! the return.  Caller-specific origin identity is *not* stored — it is
//! re-attributed at cache-apply time from the current call site's
//! argument taint.

use crate::labels::Cap;
use crate::ssa::ir::{SsaBody, Terminator};
use crate::summary::ssa_summary::PathFactReturnEntry;
use crate::symbol::FuncKey;
use crate::taint::domain::{TaintOrigin, VarTaint};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::HashMap;

/// Maximum SSA blocks in a callee body before skipping inline analysis.
pub(super) const MAX_INLINE_BLOCKS: usize = 500;

/// Compact cache key: per-arg-position cap bits (sorted, non-empty only).
///
/// Two calls with identical `ArgTaintSig` produce identical inline results
/// for soundness purposes (return caps, callee-internal sink activations).
/// Origin identity is **not** part of the key — see the module-level note
/// above on origin-attribution non-determinism.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ArgTaintSig(pub(super) SmallVec<[(usize, u16); 4]>);

/// Call-site-adapted result of inline-analyzing a callee.
///
/// Constructed fresh per call site by `apply_cached_shape` from a stored
/// [`CachedInlineShape`]; carries origins that point to the *current*
/// caller's source chain, not to whichever caller first populated the
/// cache entry.
#[derive(Clone, Debug)]
pub(crate) struct InlineResult {
    /// Taint on the return value after inline analysis.
    pub(super) return_taint: Option<VarTaint>,
    /// PathFact on the return value after inline analysis.
    ///
    /// Non-top when the callee's body provably narrows the
    /// [`crate::abstract_interp::PathFact`] of the value it returns (for
    /// example, a `sanitize_path(s) -> Option<String>` helper that
    /// early-returns on `s.contains("..")` / `s.starts_with('/')`).  At
    /// apply time the caller sets its call-result SSA value's PathFact to
    /// this narrowed fact, so downstream FILE_IO sinks see the sanitised
    /// axis regardless of whether a named label-rule exists for the
    /// helper.  Top when the callee produces no narrowing — matches
    /// pre-PathFact behaviour exactly.
    pub(super) return_path_fact: crate::abstract_interp::PathFact,
    /// Per-return-path decomposition of [`Self::return_path_fact`].
    ///
    /// Non-empty when the callee has ≥2 distinct return blocks whose
    /// predicate gates differ.  Match-arm-sensitive callers pick the
    /// entry whose `variant_inner_fact` matches the arm binding's
    /// variant; path-resolvable callers may refuse infeasible entries.
    /// Callers unable to distinguish paths still consult
    /// [`Self::return_path_fact`] (the join of all entries) and see
    /// pre-decomposition behaviour.
    #[allow(dead_code)]
    pub(super) return_path_facts: SmallVec<[PathFactReturnEntry; 2]>,
}

/// Structural (callsite-agnostic) summary of an inline-analyzed callee.
///
/// Stored in [`InlineCache`] in place of a fully-attributed `InlineResult`.
/// Origin-identity information that depends on the caller's argument chain
/// is *not* kept here; instead, [`ReturnShape::param_provenance`]
/// records which callee parameter positions contributed seed taint to the
/// return, and the actual caller origins are re-unioned in at apply time.
///
/// `None` means "this callee produced no return taint for the given
/// argument shape".  A cached `None` is still a meaningful result — it
/// short-circuits re-analysis on subsequent calls with matching caps.
#[derive(Clone, Debug)]
pub(crate) struct CachedInlineShape(pub(super) Option<ReturnShape>);

/// Structural parts of a non-trivial inline-analysis result.
///
/// Split from the full [`VarTaint`] so that cached entries can be re-used
/// across call sites with matching arg-cap signatures but differing source
/// origins.  See the module-level note above on origin attribution.
#[derive(Clone, Debug)]
pub(crate) struct ReturnShape {
    /// Return value caps (cap bits only — structural).
    pub(super) caps: Cap,
    /// Origins produced **inside the callee body** (e.g. `Source` op fired
    /// in the callee).  `node` is set to a placeholder; at apply time the
    /// caller remaps it to its own call-site NodeIndex.  `source_span` is
    /// stable (from the callee CFG) and preserved as-is.
    pub(super) internal_origins: SmallVec<[TaintOrigin; 2]>,
    /// Bit i set = callee's `Param(i)` seed taint reached the return value.
    /// At apply time, caller's argument origins at matching positions are
    /// unioned into the applied `VarTaint`.  Params beyond index 63 are
    /// dropped (matching `SmallBitSet` semantics); the capped case is rare
    /// and still yields cap-correct results.
    pub(super) param_provenance: u64,
    /// Whether the receiver (`SelfParam`) seed taint flowed to the return.
    pub(super) receiver_provenance: bool,
    /// Whether the applied `VarTaint` should be tagged `uses_summary`.
    pub(super) uses_summary: bool,
    /// PathFact of the return value observed from the callee's exit
    /// abstract state.  Cache-safe because the callee is inline-analysed
    /// with [`crate::abstract_interp::PathFact::top`] Param seeds — the
    /// resulting fact describes the callee's intrinsic narrowing (e.g.
    /// the `Some` arm of a `sanitize(..) -> Option<String>` body
    /// proves `dotdot = No`) and does not depend on caller-side
    /// narrowing of the argument's PathFact.  Top when the callee does
    /// not narrow.
    pub(super) return_path_fact: crate::abstract_interp::PathFact,
    /// Per-return-path [`PathFact`] decomposition of the return value.
    ///
    /// Populated alongside [`Self::return_path_fact`] when the callee
    /// has ≥2 distinct return blocks with different predicate gates.
    /// Cache-safe for the same reason as `return_path_fact`: entries
    /// describe callee-intrinsic narrowing under Top-seeded Params.
    /// Empty when no per-path distinction was observed.
    pub(super) return_path_facts: SmallVec<[PathFactReturnEntry; 2]>,
}

impl CachedInlineShape {
    /// Cap bits of the return value, or zero if this shape records "no
    /// return taint".  Used by [`inline_cache_fingerprint`].
    fn return_caps_bits(&self) -> u16 {
        self.0.as_ref().map(|s| s.caps.bits()).unwrap_or(0)
    }
}

/// Cache for context-sensitive inline analysis results.
///
/// Keyed by the callee's canonical [`FuncKey`] rather than a bare function
/// name so that same-name definitions (e.g. two `process/1` methods on
/// different classes in the same file) never share or overwrite each
/// other's cache entries.  Values are stored as [`CachedInlineShape`]; see
/// the module-level note above for why origins are stripped from the
/// cache value and re-attributed at apply time.
pub(crate) type InlineCache = HashMap<(FuncKey, ArgTaintSig), CachedInlineShape>;

/// Drop every entry from an inline cache, marking the start of a new
/// convergence epoch.
///
/// Cross-file SCC fixed-point iteration runs pass 2 repeatedly until the
/// merged summaries stop changing.  Between iterations the callee-summary
/// inputs to inline analysis may have changed, so results cached under a
/// stale snapshot must not leak into the next iteration — otherwise the
/// engine could converge to a non-fixed-point (reporting a taint result
/// that would not reproduce on a fresh run of the same file order).
///
/// The per-file inline cache is already reconstructed fresh at the top of
/// each [`crate::taint::analyse_file`] call, so in the current code this
/// call is effectively a no-op plumbing hook.  Keeping the method (instead
/// of relying on ambient re-construction) makes the lifecycle explicit for
/// any future refactor that moves the cache up into the SCC orchestrator.
#[allow(dead_code)] // semantic hook; used by tests and future shared-cache refactor
pub(crate) fn inline_cache_clear_epoch(cache: &mut InlineCache) {
    cache.clear();
}

/// Set-equal fingerprint of an inline cache, used by the SCC orchestrator
/// to detect when cross-file inline analysis has reached a fixed point
/// alongside summary convergence.
///
/// Returns a `HashMap` mapping each `(FuncKey, ArgTaintSig)` cache key to
/// the return-value capability bits of its inline result.  `HashMap`
/// equality is set-equal (unordered), so two caches with the same entries
/// compare equal regardless of insertion order.
///
/// Origins are intentionally omitted — they are non-deterministic across
/// callers with identical caps (see the module-level note on origin
/// attribution) and would cause the fingerprint to oscillate without
/// reflecting a real precision change.
#[allow(dead_code)] // observability hook; used by tests and future shared-cache refactor
pub(crate) fn inline_cache_fingerprint(
    cache: &InlineCache,
) -> HashMap<(FuncKey, ArgTaintSig), u16> {
    cache
        .iter()
        .map(|(k, v)| (k.clone(), v.return_caps_bits()))
        .collect()
}

/// CFG node metadata embedded in cross-file callee bodies.
///
/// ## Why a full [`crate::cfg::NodeInfo`] lives here
///
/// An earlier variant carried only the two fields the symex executor reads
/// (`bin_op`, `labels`).  That was sufficient for symex but not for the
/// taint engine, which reads ~20 fields off `cfg[inst.cfg_node]` across
/// `transfer_inst`, `collect_block_events`, `compute_succ_states`, and
/// helpers (callee name, `arg_uses`, `arg_callees`, `call_ordinal`,
/// `outer_callee`, `kwargs`, `arg_string_literals`, `ast.span`,
/// `ast.enclosing_func`, `condition_*`, `all_args_literal`, `catch_param`,
/// `parameterized_query`, `in_defer`, `cast_target_type`, `string_prefix`,
/// `taint.uses`, `taint.defines`, `taint.extra_defines`,
/// `taint.const_text`, …).  Rather than shuttling each of those through a
/// `CfgView` accessor at every callsite, we store a full serde-able
/// [`crate::cfg::NodeInfo`] snapshot here so the indexed-scan path can
/// rehydrate an equivalent `Cfg` on load (see [`rebuild_body_graph`]).
/// Both scan paths then feed the same `&Cfg` into the taint engine, and
/// cross-file inline fires regardless of whether the body came from pass
/// 1 or from SQLite.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrossFileNodeMeta {
    /// Full `NodeInfo` snapshot for this body-local NodeIndex.
    pub info: crate::cfg::NodeInfo,
}

/// Pre-lowered and optimized SSA body for a function,
/// ready for context-sensitive re-analysis with different argument taint.
///
/// For intra-file use, `node_meta` is empty and the original CFG is used.
/// For cross-file persistence, `node_meta` carries the minimal CFG
/// metadata needed by the symex executor.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CalleeSsaBody {
    pub ssa: SsaBody,
    pub opt: crate::ssa::OptimizeResult,
    pub param_count: usize,
    /// Per-NodeIndex CFG metadata for cross-file bodies.
    /// Empty for intra-file bodies (the original CFG is used instead).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub node_meta: std::collections::HashMap<u32, CrossFileNodeMeta>,
    /// The body's own CFG graph.  Populated for intra-file bodies so that
    /// inline analysis can reference the correct graph (per-body CFGs have
    /// body-local NodeIndex spaces).  `None` for cross-file deserialized
    /// bodies.
    #[serde(skip)]
    pub body_graph: Option<crate::cfg::Cfg>,
}

/// Populate `node_meta` from the original CFG for cross-file persistence.
///
/// Returns `true` if all referenced NodeIndex values were resolved
/// successfully.  Returns `false` if any node was out of bounds (body is
/// ineligible for cross-file use).
pub fn populate_node_meta(body: &mut CalleeSsaBody, cfg: &crate::cfg::Cfg) -> bool {
    // Collect every NodeIndex this body references, then snapshot each one's
    // NodeInfo into `node_meta`.  Done in two passes so the inner loop can
    // mutate `body.node_meta` without borrow-checker conflicts on
    // `body.ssa.blocks`.
    //
    // `Terminator::Branch.cond` must be captured as well: it is consumed by
    // `compute_succ_states` via `cfg[*cond]`, so without it the synthesized
    // cross-file proxy CFG (`rebuild_body_graph`) ends up too small whenever
    // the callee body has any conditional branch whose `cond` index sits
    // past the maximum `inst.cfg_node` index — inline analysis then panics
    // with an out-of-bounds index.
    let mut referenced: Vec<NodeIndex> = Vec::new();
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            referenced.push(inst.cfg_node);
        }
        if let Terminator::Branch { cond, .. } = &block.terminator {
            referenced.push(*cond);
        }
    }
    for node in referenced {
        let idx = node.index() as u32;
        if body.node_meta.contains_key(&idx) {
            continue;
        }
        if node.index() >= cfg.node_count() {
            return false;
        }
        let info = cfg[node].clone();
        body.node_meta.insert(idx, CrossFileNodeMeta { info });
    }
    true
}

/// Synthesize a proxy [`crate::cfg::Cfg`] from `node_meta` so the taint
/// engine can index `cfg[inst.cfg_node]` uniformly on the indexed-scan
/// path.
///
/// When the callee body was loaded from SQLite, `body_graph` is `None`
/// (it is `#[serde(skip)]`), but `node_meta` carries a full
/// [`crate::cfg::NodeInfo`] for every referenced NodeIndex (see
/// [`populate_node_meta`]).  This helper rebuilds a petgraph `Cfg` with
/// nodes at exactly the right NodeIndex positions so the taint engine's
/// existing indexing works without change.
///
/// Returns `true` if a proxy graph was freshly installed.  Idempotent:
/// subsequent calls are cheap no-ops once `body_graph` is `Some`.  No-op
/// for intra-file bodies (which arrive with `body_graph` already set and
/// `node_meta` empty).
pub fn rebuild_body_graph(body: &mut CalleeSsaBody) -> bool {
    if body.body_graph.is_some() {
        return false;
    }
    if body.node_meta.is_empty() {
        return false;
    }
    // Determine the maximum NodeIndex referenced by the SSA so the
    // synthesized graph has an entry at every position the engine may
    // index.  We fill any unreferenced intermediate indices with
    // `NodeInfo::default()`.
    //
    // Walks both instruction `cfg_node`s and `Terminator::Branch.cond` —
    // the latter is read by `compute_succ_states` via `cfg[*cond]`, so
    // missing it produces an OOB panic when a conditional branch's cond
    // node has a higher index than any `inst.cfg_node` in the body.
    let mut max_idx: u32 = 0;
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let idx = inst.cfg_node.index() as u32;
            if idx > max_idx {
                max_idx = idx;
            }
        }
        if let Terminator::Branch { cond, .. } = &block.terminator {
            let idx = cond.index() as u32;
            if idx > max_idx {
                max_idx = idx;
            }
        }
    }
    // Also consider node_meta keys — they should be a subset of the
    // SSA-referenced indices, but be defensive.
    for &k in body.node_meta.keys() {
        if k > max_idx {
            max_idx = k;
        }
    }

    use petgraph::graph::Graph;
    let mut graph: crate::cfg::Cfg = Graph::new();
    // petgraph allocates sequential NodeIndex values.  Insert placeholders
    // up to and including max_idx.
    for i in 0..=max_idx {
        let info = body
            .node_meta
            .get(&i)
            .map(|m| m.info.clone())
            .unwrap_or_default();
        graph.add_node(info);
    }
    // Edges are not consulted by the taint engine during inline analysis
    // (control flow comes from `SsaBlock::preds`/`succs` and
    // `SsaBlock::terminator`), so we leave the graph edge-free.
    body.body_graph = Some(graph);
    true
}
