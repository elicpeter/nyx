//! Formal points-to / heap analysis for SSA-based taint propagation.
//!
//! Provides bounded intra-procedural points-to analysis: each container
//! allocation creates an abstract `HeapObjectId`, assignments and phi nodes
//! propagate points-to sets, and the taint engine uses heap state to track
//! taint through container store/load operations with proper aliasing.
//!
//! Key design:
//! - HeapObjectId is keyed by allocation-site SsaValue (deterministic, zero-cost)
//! - PointsToSet is bounded to MAX_POINTSTO entries (widening on overflow)
//! - HeapState tracks per-(heap-object, slot) taint (monotone lattice)
//!   - HeapSlot::Index(u64) for constant-index container access (proven by const propagation)
//!   - HeapSlot::Elements for coarse element access (push/pop, dynamic index, overflow)
//!   - Intraprocedural: constant-index sensitivity is guaranteed when const propagation proves it
//!   - Interprocedural: best-effort — relies on correct const_values threading (already handled)
//!   - Unknown/unproven indices fall back to Elements (conservative)
//! - Analysis runs as a pre-pass in optimize_ssa(), like type_facts

use crate::cfg::Cfg;
use crate::labels::Cap;
use crate::ssa::ir::*;
use crate::ssa::pointsto::{classify_container_op, ContainerOp};
use crate::symbol::Lang;
use crate::taint::domain::TaintOrigin;
use smallvec::SmallVec;
use std::collections::HashMap;

/// Maximum heap objects tracked per SSA value's points-to set.
pub const MAX_POINTSTO: usize = 8;

/// Maximum origins tracked per heap object (matches MAX_ORIGINS in ssa_transfer).
const MAX_HEAP_ORIGINS: usize = 4;

/// Maximum distinct `Index(n)` slots tracked per heap object.
/// When exceeded, all indexed entries for that object collapse into `Elements`.
pub const MAX_TRACKED_INDICES: usize = 8;

// ── HeapSlot ────────────────────────────────────────────────────────────

/// Distinguishes constant-index container access from coarse element access.
///
/// `Elements` is the conservative default — all container elements merge into
/// a single taint.  `Index(n)` provides per-index precision when the index is
/// provably a non-negative integer constant (via the function's own const
/// propagation pass).
///
/// Ordering: `Elements < Index(0) < Index(1) < …` so that sorted merge-join
/// in `HeapState` groups all slots for the same `HeapObjectId` together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapSlot {
    /// Coarse union of all elements (push/pop, dynamic index, overflow).
    Elements,
    /// Constant-index slot, proven by the current function's const propagation.
    Index(u64),
}

// ── HeapObjectId ─────────────────────────────────────────────────────────

/// Abstract heap object identity, keyed by the SSA value of the allocation site.
///
/// When `items = []` creates SsaValue(5), the heap object is HeapObjectId(SsaValue(5)).
/// SSA guarantees each definition is unique, so heap identity is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeapObjectId(pub SsaValue);

// ── PointsToSet ──────────────────────────────────────────────────────────

/// Bounded set of heap objects that an SSA value may reference.
///
/// Stored as a sorted, deduped SmallVec for O(n) merge-join, matching the
/// pattern used by SsaTaintState.values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PointsToSet {
    ids: SmallVec<[HeapObjectId; 4]>,
}

impl PointsToSet {
    /// Empty points-to set.
    pub fn empty() -> Self {
        Self { ids: SmallVec::new() }
    }

    /// Points-to set containing a single heap object.
    pub fn singleton(id: HeapObjectId) -> Self {
        let mut ids = SmallVec::new();
        ids.push(id);
        Self { ids }
    }

    /// Bounded union of two points-to sets. Truncates to MAX_POINTSTO.
    pub fn union(&self, other: &Self) -> Self {
        let mut result = SmallVec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.ids.len() && j < other.ids.len() && result.len() < MAX_POINTSTO {
            match self.ids[i].cmp(&other.ids[j]) {
                std::cmp::Ordering::Less => {
                    result.push(self.ids[i]);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    result.push(other.ids[j]);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    result.push(self.ids[i]);
                    i += 1;
                    j += 1;
                }
            }
        }
        while i < self.ids.len() && result.len() < MAX_POINTSTO {
            result.push(self.ids[i]);
            i += 1;
        }
        while j < other.ids.len() && result.len() < MAX_POINTSTO {
            result.push(other.ids[j]);
            j += 1;
        }
        Self { ids: result }
    }

    /// Insert a single HeapObjectId, maintaining sorted order and bound.
    pub fn insert(&mut self, id: HeapObjectId) {
        match self.ids.binary_search(&id) {
            Ok(_) => {} // already present
            Err(pos) => {
                if self.ids.len() < MAX_POINTSTO {
                    self.ids.insert(pos, id);
                }
                // else: overflow — drop (widening)
            }
        }
    }

    pub fn contains(&self, id: HeapObjectId) -> bool {
        self.ids.binary_search(&id).is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &HeapObjectId> {
        self.ids.iter()
    }
}

// ── HeapTaint ────────────────────────────────────────────────────────────

/// Taint stored inside an abstract heap object (container contents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeapTaint {
    pub caps: Cap,
    pub origins: SmallVec<[TaintOrigin; 2]>,
}

impl HeapTaint {
    /// Monotone merge: OR caps, union origins (bounded).
    fn merge(&mut self, caps: Cap, origins: &[TaintOrigin]) {
        self.caps |= caps;
        for orig in origins {
            if self.origins.len() < MAX_HEAP_ORIGINS
                && !self.origins.iter().any(|o| o.node == orig.node)
            {
                self.origins.push(*orig);
            }
        }
    }

    /// Union two HeapTaint values (for load_set).
    fn union(&self, other: &HeapTaint) -> HeapTaint {
        let mut result = self.clone();
        result.merge(other.caps, &other.origins);
        result
    }
}

// ── HeapState ────────────────────────────────────────────────────────────

/// Per-(heap-object, slot) taint state: abstract contents of all tracked
/// containers with optional per-index precision.
///
/// Sorted by `(HeapObjectId, HeapSlot)` for O(n) merge-join (lattice join =
/// union of per-slot taint), matching the `SsaTaintState` pattern.
///
/// Load semantics:
/// - `load(id, Index(n))`: union of `(id, Index(n))` and `(id, Elements)` —
///   indexed reads also see taint from dynamic/push operations.
/// - `load(id, Elements)`: union of `(id, Elements)` and ALL `(id, Index(*))`
///   entries — dynamic reads conservatively see all indexed taint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeapState {
    entries: SmallVec<[((HeapObjectId, HeapSlot), HeapTaint); 4]>,
}

impl HeapState {
    pub fn empty() -> Self {
        Self { entries: SmallVec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Store taint into a specific (object, slot) pair (monotone merge).
    ///
    /// If storing to `Index(n)` would exceed `MAX_TRACKED_INDICES` distinct
    /// indices for this object, all `Index(*)` entries for the object are
    /// collapsed into `Elements` and the new taint is merged there instead.
    pub fn store(
        &mut self,
        id: HeapObjectId,
        slot: HeapSlot,
        caps: Cap,
        origins: &[TaintOrigin],
    ) {
        if caps.is_empty() {
            return;
        }

        // Check index overflow before inserting a new Index slot.
        if let HeapSlot::Index(_) = slot {
            let key = (id, slot);
            let already_present = self.entries.binary_search_by_key(&key, |(k, _)| *k).is_ok();
            if !already_present {
                let index_count = self.count_indices_for(id);
                if index_count >= MAX_TRACKED_INDICES {
                    // Collapse: merge all Index(*) entries into Elements,
                    // then store the new taint into Elements too.
                    self.collapse_indices_to_elements(id);
                    self.store_raw(id, HeapSlot::Elements, caps, origins);
                    return;
                }
            }
        }

        self.store_raw(id, slot, caps, origins);
    }

    /// Raw store without overflow checking.
    fn store_raw(
        &mut self,
        id: HeapObjectId,
        slot: HeapSlot,
        caps: Cap,
        origins: &[TaintOrigin],
    ) {
        let key = (id, slot);
        match self.entries.binary_search_by_key(&key, |(k, _)| *k) {
            Ok(idx) => {
                self.entries[idx].1.merge(caps, origins);
            }
            Err(idx) => {
                self.entries.insert(
                    idx,
                    (
                        key,
                        HeapTaint {
                            caps,
                            origins: {
                                let mut o = SmallVec::new();
                                for orig in origins.iter().take(MAX_HEAP_ORIGINS) {
                                    o.push(*orig);
                                }
                                o
                            },
                        },
                    ),
                );
            }
        }
    }

    /// Store taint into all heap objects in a points-to set.
    pub fn store_set(
        &mut self,
        pts: &PointsToSet,
        slot: HeapSlot,
        caps: Cap,
        origins: &[TaintOrigin],
    ) {
        for &id in pts.iter() {
            self.store(id, slot, caps, origins);
        }
    }

    /// Load taint from a specific (object, slot) pair.
    ///
    /// - `Index(n)`: returns union of `(id, Index(n))` ∪ `(id, Elements)`.
    /// - `Elements`: returns union of `(id, Elements)` ∪ all `(id, Index(*))`.
    pub fn load(&self, id: HeapObjectId, slot: HeapSlot) -> Option<HeapTaint> {
        match slot {
            HeapSlot::Index(n) => {
                // Union specific index with Elements.
                let idx_taint = self.load_raw(id, HeapSlot::Index(n));
                let elem_taint = self.load_raw(id, HeapSlot::Elements);
                match (idx_taint, elem_taint) {
                    (Some(a), Some(b)) => Some(a.union(b)),
                    (Some(a), None) => Some(a.clone()),
                    (None, Some(b)) => Some(b.clone()),
                    (None, None) => None,
                }
            }
            HeapSlot::Elements => {
                // Union Elements with ALL Index(*) entries for this object.
                let mut result: Option<HeapTaint> = None;
                for ((eid, _slot), taint) in &self.entries {
                    if *eid == id {
                        result = Some(match result {
                            Some(r) => r.union(taint),
                            None => taint.clone(),
                        });
                    }
                }
                result
            }
        }
    }

    /// Direct lookup of a single (id, slot) entry without cross-slot unioning.
    fn load_raw(&self, id: HeapObjectId, slot: HeapSlot) -> Option<&HeapTaint> {
        let key = (id, slot);
        self.entries
            .binary_search_by_key(&key, |(k, _)| *k)
            .ok()
            .map(|idx| &self.entries[idx].1)
    }

    /// Load and union taint from all heap objects in a points-to set.
    pub fn load_set(&self, pts: &PointsToSet, slot: HeapSlot) -> Option<HeapTaint> {
        let mut result: Option<HeapTaint> = None;
        for &id in pts.iter() {
            if let Some(ht) = self.load(id, slot) {
                result = Some(match result {
                    Some(r) => r.union(&ht),
                    None => ht,
                });
            }
        }
        result
    }

    /// Lattice join: merge-join by (HeapObjectId, HeapSlot), union per-slot taint.
    pub fn join(&self, other: &Self) -> Self {
        let mut result = SmallVec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.entries.len() && j < other.entries.len() {
            let (ka, ta) = &self.entries[i];
            let (kb, tb) = &other.entries[j];
            match ka.cmp(kb) {
                std::cmp::Ordering::Less => {
                    result.push((*ka, ta.clone()));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    result.push((*kb, tb.clone()));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    result.push((*ka, ta.union(tb)));
                    i += 1;
                    j += 1;
                }
            }
        }
        while i < self.entries.len() {
            result.push(self.entries[i].clone());
            i += 1;
        }
        while j < other.entries.len() {
            result.push(other.entries[j].clone());
            j += 1;
        }
        Self { entries: result }
    }

    /// Lattice ordering: every entry in self must be present in other with subset caps.
    pub fn leq(&self, other: &Self) -> bool {
        let mut j = 0;
        for (ka, ta) in &self.entries {
            loop {
                if j >= other.entries.len() {
                    return false;
                }
                let (kb, _) = &other.entries[j];
                match ka.cmp(kb) {
                    std::cmp::Ordering::Equal => break,
                    std::cmp::Ordering::Greater => j += 1,
                    std::cmp::Ordering::Less => return false,
                }
            }
            let (_, tb) = &other.entries[j];
            if (ta.caps & !tb.caps) != Cap::empty() {
                return false;
            }
            j += 1;
        }
        true
    }

    /// Count distinct `Index(*)` slots for a given object.
    fn count_indices_for(&self, id: HeapObjectId) -> usize {
        self.entries
            .iter()
            .filter(|((eid, slot), _)| *eid == id && matches!(slot, HeapSlot::Index(_)))
            .count()
    }

    /// Collapse all `Index(*)` entries for `id` into `Elements`.
    fn collapse_indices_to_elements(&mut self, id: HeapObjectId) {
        // Collect taint from all Index entries for this object.
        let mut merged_caps = Cap::empty();
        let mut merged_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        self.entries.retain(|((eid, slot), taint)| {
            if *eid == id && matches!(slot, HeapSlot::Index(_)) {
                merged_caps |= taint.caps;
                for orig in &taint.origins {
                    if merged_origins.len() < MAX_HEAP_ORIGINS
                        && !merged_origins.iter().any(|o| o.node == orig.node)
                    {
                        merged_origins.push(*orig);
                    }
                }
                false // remove this entry
            } else {
                true // keep
            }
        });
        // Merge into Elements.
        if !merged_caps.is_empty() {
            self.store_raw(id, HeapSlot::Elements, merged_caps, &merged_origins);
        }
    }
}

// ── PointsToResult ───────────────────────────────────────────────────────

/// Result of intra-procedural points-to analysis.
pub struct PointsToResult {
    pts: HashMap<SsaValue, PointsToSet>,
}

impl PointsToResult {
    pub fn empty() -> Self {
        Self { pts: HashMap::new() }
    }

    /// Look up the points-to set for an SSA value.
    pub fn get(&self, v: SsaValue) -> Option<&PointsToSet> {
        self.pts.get(&v)
    }

    pub fn is_empty(&self) -> bool {
        self.pts.is_empty()
    }
}

// ── Allocation site detection ────────────────────────────────────────────

/// Check if a const literal text represents a container/collection literal.
fn is_container_literal(text: &str) -> bool {
    let t = text.trim();
    // Empty or non-empty array/list literals
    if t.starts_with('[') && t.ends_with(']') {
        return true;
    }
    // Empty or non-empty object/dict/map/set literals
    if t.starts_with('{') && t.ends_with('}') {
        return true;
    }
    // `new Array(...)`, `new Map(...)`, etc.
    if t.starts_with("new ") {
        return true;
    }
    // Python dict()/list()/set() as literals
    if t == "dict()" || t == "list()" || t == "set()" {
        return true;
    }
    false
}

/// Check if a callee creates a new container (constructor/factory).
pub fn is_container_constructor(callee: &str, lang: Lang) -> bool {
    // Extract last segment after '.' or '::' (whichever comes last)
    let after_dot = callee.rsplit('.').next().unwrap_or(callee);
    let suffix = after_dot.rsplit("::").next().unwrap_or(after_dot);
    let suffix_lower = suffix.to_ascii_lowercase();

    match lang {
        Lang::JavaScript | Lang::TypeScript => matches!(
            suffix,
            "Array" | "Map" | "Set" | "WeakMap" | "WeakSet"
        ),
        Lang::Python => matches!(
            suffix,
            "list" | "dict" | "set" | "frozenset" | "defaultdict"
                | "OrderedDict" | "deque" | "Counter"
        ),
        Lang::Java => matches!(
            suffix,
            "ArrayList"
                | "LinkedList"
                | "HashMap"
                | "TreeMap"
                | "HashSet"
                | "TreeSet"
                | "Vector"
                | "Stack"
                | "ArrayDeque"
                | "PriorityQueue"
                | "ConcurrentHashMap"
                | "LinkedHashMap"
                | "LinkedHashSet"
                | "CopyOnWriteArrayList"
        ),
        Lang::Go => callee == "make",
        Lang::Ruby => matches!(suffix, "new") && {
            // Only for known container types
            let prefix = callee.rsplit('.').nth(1).unwrap_or("");
            matches!(prefix, "Array" | "Hash" | "Set")
        },
        Lang::Php => matches!(suffix, "array"),
        Lang::C | Lang::Cpp => matches!(
            suffix_lower.as_str(),
            "vector" | "map" | "set" | "unordered_map" | "unordered_set"
                | "list" | "deque" | "queue" | "stack" | "multimap"
                | "multiset" | "priority_queue"
        ),
        Lang::Rust => {
            // Vec::new, HashMap::new, etc.
            suffix == "new"
                && callee.contains("::")
                && {
                    let type_part = callee.rsplit("::").nth(1).unwrap_or("");
                    matches!(
                        type_part,
                        "Vec" | "HashMap" | "HashSet" | "BTreeMap" | "BTreeSet"
                            | "VecDeque" | "LinkedList" | "BinaryHeap"
                    )
                }
        }
    }
}

// ── Points-to analysis ───────────────────────────────────────────────────

/// Run intra-procedural points-to analysis on an SSA body.
///
/// Identifies allocation sites, propagates points-to sets through assignments
/// and phi nodes, and returns a result that the taint engine can query.
///
/// Runs as a pre-pass in optimize_ssa(), after type_facts.
pub fn analyze_points_to(body: &SsaBody, _cfg: &Cfg, lang: Option<Lang>) -> PointsToResult {
    let mut pts: HashMap<SsaValue, PointsToSet> = HashMap::new();

    // Pass 1: identify allocation sites and seed points-to sets
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                SsaOp::Const(Some(text)) if is_container_literal(text) => {
                    pts.insert(inst.value, PointsToSet::singleton(HeapObjectId(inst.value)));
                }
                SsaOp::Call { callee, .. } => {
                    if let Some(l) = lang {
                        if is_container_constructor(callee, l) {
                            pts.insert(
                                inst.value,
                                PointsToSet::singleton(HeapObjectId(inst.value)),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if pts.is_empty() {
        return PointsToResult::empty();
    }

    // Pass 2: forward propagation with fixed-point for phis (max 10 rounds)
    let max_rounds = 10;
    for _ in 0..max_rounds {
        let mut changed = false;
        for block in &body.blocks {
            // Process phis
            for inst in &block.phis {
                if let SsaOp::Phi(operands) = &inst.op {
                    let mut merged = PointsToSet::empty();
                    for (_, v) in operands {
                        if let Some(p) = pts.get(v) {
                            merged = merged.union(p);
                        }
                    }
                    if !merged.is_empty() {
                        let old = pts.get(&inst.value);
                        if old.map_or(true, |o| o != &merged) {
                            let existing = pts.entry(inst.value).or_insert_with(PointsToSet::empty);
                            let new = existing.union(&merged);
                            if &new != existing {
                                *existing = new;
                                changed = true;
                            }
                        }
                    }
                }
            }
            // Process body
            for inst in &block.body {
                match &inst.op {
                    SsaOp::Assign(uses) => {
                        let mut merged = PointsToSet::empty();
                        for &u in uses {
                            if let Some(p) = pts.get(&u) {
                                merged = merged.union(p);
                            }
                        }
                        if !merged.is_empty() {
                            let old = pts.get(&inst.value);
                            if old.map_or(true, |o| o != &merged) {
                                pts.insert(inst.value, merged);
                                changed = true;
                            }
                        }
                    }
                    SsaOp::Call { callee, args, receiver, .. } => {
                        // For container Store ops that return the container (Go append),
                        // propagate receiver pts to result.
                        if let Some(l) = lang {
                            if let Some(ContainerOp::Store { .. }) =
                                classify_container_op(callee, l)
                            {
                                // Find receiver pts
                                let recv_pts = receiver
                                    .and_then(|rv| pts.get(&rv).cloned())
                                    .or_else(|| {
                                        // Go append: arg 0 is the slice
                                        if l == Lang::Go {
                                            args.first()
                                                .and_then(|a| a.first())
                                                .and_then(|&v| pts.get(&v).cloned())
                                        } else {
                                            // JS-style: find receiver from dotted callee
                                            let dot_pos = callee.rfind('.')?;
                                            let recv_name = &callee[..dot_pos];
                                            for arg_group in args {
                                                for &v in arg_group {
                                                    if let Some(def) =
                                                        body.value_defs.get(v.0 as usize)
                                                    {
                                                        if def.var_name.as_deref()
                                                            == Some(recv_name)
                                                        {
                                                            return pts.get(&v).cloned();
                                                        }
                                                    }
                                                }
                                            }
                                            None
                                        }
                                    });
                                // For Go append, result gets receiver pts
                                if l == Lang::Go && receiver.is_none() {
                                    if let Some(rp) = recv_pts {
                                        let old = pts.get(&inst.value);
                                        if old.map_or(true, |o| o != &rp) {
                                            pts.insert(inst.value, rp);
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }

    PointsToResult { pts }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::SourceKind;
    use petgraph::graph::NodeIndex;

    fn origin(idx: u32) -> TaintOrigin {
        TaintOrigin {
            node: NodeIndex::new(idx as usize),
            source_kind: SourceKind::UserInput,
        }
    }

    // ── PointsToSet tests ────────────────────────────────────────────

    #[test]
    fn pts_singleton() {
        let s = PointsToSet::singleton(HeapObjectId(SsaValue(0)));
        assert_eq!(s.len(), 1);
        assert!(s.contains(HeapObjectId(SsaValue(0))));
        assert!(!s.contains(HeapObjectId(SsaValue(1))));
    }

    #[test]
    fn pts_union() {
        let a = PointsToSet::singleton(HeapObjectId(SsaValue(1)));
        let b = PointsToSet::singleton(HeapObjectId(SsaValue(3)));
        let c = a.union(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(HeapObjectId(SsaValue(1))));
        assert!(c.contains(HeapObjectId(SsaValue(3))));
    }

    #[test]
    fn pts_union_dedup() {
        let a = PointsToSet::singleton(HeapObjectId(SsaValue(1)));
        let b = PointsToSet::singleton(HeapObjectId(SsaValue(1)));
        let c = a.union(&b);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn pts_union_overflow() {
        // Build a set with MAX_POINTSTO entries
        let mut big = PointsToSet::empty();
        for i in 0..MAX_POINTSTO as u32 {
            big.insert(HeapObjectId(SsaValue(i)));
        }
        assert_eq!(big.len(), MAX_POINTSTO);

        // Union with one more should not grow
        let extra = PointsToSet::singleton(HeapObjectId(SsaValue(100)));
        let result = big.union(&extra);
        assert_eq!(result.len(), MAX_POINTSTO);
    }

    #[test]
    fn pts_empty() {
        let e = PointsToSet::empty();
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
    }

    #[test]
    fn pts_insert() {
        let mut s = PointsToSet::empty();
        s.insert(HeapObjectId(SsaValue(5)));
        s.insert(HeapObjectId(SsaValue(2)));
        s.insert(HeapObjectId(SsaValue(5))); // dup
        assert_eq!(s.len(), 2);
        // Sorted order
        let ids: Vec<_> = s.iter().collect();
        assert_eq!(ids[0].0, SsaValue(2));
        assert_eq!(ids[1].0, SsaValue(5));
    }

    // ── HeapState tests ──────────────────────────────────────────────

    #[test]
    fn heap_store_and_load() {
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);

        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE);
        assert_eq!(t.origins.len(), 1);
    }

    #[test]
    fn heap_store_monotone_merge() {
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(id, HeapSlot::Elements, Cap::SQL_QUERY, &[origin(1)]);

        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
        assert_eq!(t.origins.len(), 2);
    }

    #[test]
    fn heap_store_empty_caps_noop() {
        let mut h = HeapState::empty();
        h.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::empty(), &[origin(0)]);
        assert!(h.is_empty());
    }

    #[test]
    fn heap_load_missing() {
        let h = HeapState::empty();
        assert!(h.load(HeapObjectId(SsaValue(0)), HeapSlot::Elements).is_none());
    }

    #[test]
    fn heap_load_set_unions() {
        let mut h = HeapState::empty();
        h.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(HeapObjectId(SsaValue(1)), HeapSlot::Elements, Cap::SQL_QUERY, &[origin(1)]);

        let mut pts = PointsToSet::empty();
        pts.insert(HeapObjectId(SsaValue(0)));
        pts.insert(HeapObjectId(SsaValue(1)));

        let t = h.load_set(&pts, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
        assert_eq!(t.origins.len(), 2);
    }

    #[test]
    fn heap_load_set_empty_pts() {
        let mut h = HeapState::empty();
        h.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);
        let pts = PointsToSet::empty();
        assert!(h.load_set(&pts, HeapSlot::Elements).is_none());
    }

    #[test]
    fn heap_store_set() {
        let mut h = HeapState::empty();
        let mut pts = PointsToSet::empty();
        pts.insert(HeapObjectId(SsaValue(0)));
        pts.insert(HeapObjectId(SsaValue(1)));

        h.store_set(&pts, HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);

        assert_eq!(h.load(HeapObjectId(SsaValue(0)), HeapSlot::Elements).unwrap().caps, Cap::HTML_ESCAPE);
        assert_eq!(h.load(HeapObjectId(SsaValue(1)), HeapSlot::Elements).unwrap().caps, Cap::HTML_ESCAPE);
    }

    #[test]
    fn heap_join() {
        let mut a = HeapState::empty();
        a.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);

        let mut b = HeapState::empty();
        b.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::SQL_QUERY, &[origin(1)]);
        b.store(HeapObjectId(SsaValue(1)), HeapSlot::Elements, Cap::FILE_IO, &[origin(2)]);

        let c = a.join(&b);
        let t0 = c.load(HeapObjectId(SsaValue(0)), HeapSlot::Elements).unwrap();
        assert_eq!(t0.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
        let t1 = c.load(HeapObjectId(SsaValue(1)), HeapSlot::Elements).unwrap();
        assert_eq!(t1.caps, Cap::FILE_IO);
    }

    #[test]
    fn heap_leq() {
        let mut a = HeapState::empty();
        a.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);

        let mut b = HeapState::empty();
        b.store(HeapObjectId(SsaValue(0)), HeapSlot::Elements, Cap::HTML_ESCAPE | Cap::SQL_QUERY, &[origin(0)]);

        assert!(a.leq(&b)); // a ⊆ b
        assert!(!b.leq(&a)); // b ⊄ a
    }

    #[test]
    fn heap_leq_missing_entry() {
        let mut a = HeapState::empty();
        a.store(HeapObjectId(SsaValue(5)), HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);
        let b = HeapState::empty();
        assert!(!a.leq(&b)); // a has entry, b doesn't
        assert!(b.leq(&a)); // b empty is always ⊆
    }

    // ── HeapSlot indexed tests ──────────────────────────────────────

    #[test]
    fn heap_indexed_store_load_isolation() {
        // Store to Index(0), load from Index(1) → no taint
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::HTML_ESCAPE, &[origin(0)]);

        // Index(0) should have taint
        let t0 = h.load(id, HeapSlot::Index(0)).unwrap();
        assert_eq!(t0.caps, Cap::HTML_ESCAPE);

        // Index(1) should NOT have taint (no Elements, no Index(1) entry)
        assert!(h.load(id, HeapSlot::Index(1)).is_none());
    }

    #[test]
    fn heap_indexed_load_unions_with_elements() {
        // Store to Elements → indexed load should see it
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::SQL_QUERY, &[origin(0)]);

        // Index(1) load should union with Elements
        let t = h.load(id, HeapSlot::Index(1)).unwrap();
        assert_eq!(t.caps, Cap::SQL_QUERY);
    }

    #[test]
    fn heap_elements_load_unions_all_indices() {
        // Store to Index(0) and Index(2) — Elements load should see both
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(id, HeapSlot::Index(2), Cap::SQL_QUERY, &[origin(1)]);

        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
    }

    #[test]
    fn heap_indexed_and_elements_combined() {
        // Index(0) = tainted, Elements = tainted with different cap
        // Index(0) load should see both; Index(1) should see only Elements
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(id, HeapSlot::Elements, Cap::FILE_IO, &[origin(1)]);

        let t0 = h.load(id, HeapSlot::Index(0)).unwrap();
        assert_eq!(t0.caps, Cap::HTML_ESCAPE | Cap::FILE_IO);

        let t1 = h.load(id, HeapSlot::Index(1)).unwrap();
        assert_eq!(t1.caps, Cap::FILE_IO); // only Elements taint
    }

    #[test]
    fn heap_max_tracked_indices_collapse() {
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));

        // Fill MAX_TRACKED_INDICES index slots
        for i in 0..MAX_TRACKED_INDICES as u64 {
            h.store(id, HeapSlot::Index(i), Cap::HTML_ESCAPE, &[origin(i as u32)]);
        }

        // One more should trigger collapse into Elements
        h.store(id, HeapSlot::Index(MAX_TRACKED_INDICES as u64), Cap::SQL_QUERY, &[origin(99)]);

        // All Index entries should be collapsed into Elements.
        // There should be no Index entries left.
        assert_eq!(h.count_indices_for(id), 0);

        // Elements load should see all taint
        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert!(t.caps.contains(Cap::HTML_ESCAPE));
        assert!(t.caps.contains(Cap::SQL_QUERY));
    }

    // ── is_container_literal tests ───────────────────────────────────

    #[test]
    fn container_literal_detection() {
        assert!(is_container_literal("[]"));
        assert!(is_container_literal("[1, 2, 3]"));
        assert!(is_container_literal("{}"));
        assert!(is_container_literal("{a: 1}"));
        assert!(is_container_literal("new Map()"));
        assert!(is_container_literal("new ArrayList<>()"));
        assert!(is_container_literal("dict()"));
        assert!(is_container_literal("list()"));
        assert!(is_container_literal("set()"));
        assert!(!is_container_literal("42"));
        assert!(!is_container_literal("\"hello\""));
        assert!(!is_container_literal("true"));
    }

    // ── is_container_constructor tests ───────────────────────────────

    #[test]
    fn container_constructor_js() {
        assert!(is_container_constructor("Array", Lang::JavaScript));
        assert!(is_container_constructor("Map", Lang::JavaScript));
        assert!(is_container_constructor("Set", Lang::JavaScript));
        assert!(!is_container_constructor("Object", Lang::JavaScript));
    }

    #[test]
    fn container_constructor_python() {
        assert!(is_container_constructor("list", Lang::Python));
        assert!(is_container_constructor("dict", Lang::Python));
        assert!(is_container_constructor("defaultdict", Lang::Python));
        assert!(!is_container_constructor("str", Lang::Python));
    }

    #[test]
    fn container_constructor_java() {
        assert!(is_container_constructor("ArrayList", Lang::Java));
        assert!(is_container_constructor("HashMap", Lang::Java));
        assert!(is_container_constructor("ConcurrentHashMap", Lang::Java));
        assert!(!is_container_constructor("String", Lang::Java));
    }

    #[test]
    fn container_constructor_go() {
        assert!(is_container_constructor("make", Lang::Go));
        assert!(!is_container_constructor("new", Lang::Go));
    }

    #[test]
    fn container_constructor_rust() {
        assert!(is_container_constructor("Vec::new", Lang::Rust));
        assert!(is_container_constructor("HashMap::new", Lang::Rust));
        assert!(!is_container_constructor("String::new", Lang::Rust));
        assert!(!is_container_constructor("new", Lang::Rust));
    }

    #[test]
    fn container_constructor_cpp() {
        assert!(is_container_constructor("vector", Lang::Cpp));
        assert!(is_container_constructor("std::map", Lang::Cpp));
        assert!(is_container_constructor("unordered_set", Lang::Cpp));
    }

    // ── PointsToResult tests ─────────────────────────────────────────

    #[test]
    fn pts_result_empty() {
        let r = PointsToResult::empty();
        assert!(r.is_empty());
        assert!(r.get(SsaValue(0)).is_none());
    }
}
