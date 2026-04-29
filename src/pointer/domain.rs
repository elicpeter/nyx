//! Abstract domain for field-sensitive Steensgaard points-to.
//!
//! Locations are interned to compact `LocId(u32)` handles so the
//! union-find resolver can operate on dense integer keys.  Field
//! locations are keyed structurally by `(parent_loc_id, field_id)` —
//! interning a `Field(parent, f)` always returns the same `LocId` no
//! matter how many times the same `(parent, f)` pair is requested.

use crate::cfg::BodyId;
use crate::ssa::ir::FieldId;
use smallvec::SmallVec;
use std::collections::HashMap;

/// Maximum nesting depth for `Field(...)` chains before folding to `Top`.
///
/// Bounds the per-body work for pathological recursive walks like
/// `a.next.next.next.…` and matches the bound called out in the
/// pointer-analysis prompt.
pub const MAX_FIELD_DEPTH: u8 = 3;

/// Maximum members per [`PointsToSet`] before we collapse the set to
/// the over-approximation `{Top}`.  Keeps both the set and downstream
/// constraint propagation bounded; mirrors the spirit of
/// [`crate::ssa::heap::effective_max_pointsto`] without sharing the
/// exact value (this analysis runs flow-insensitively across the body
/// so its sets are typically smaller).
pub const MAX_POINTSTO_MEMBERS: usize = 16;

/// Compact handle for an interned [`AbsLoc`].
///
/// All abstract locations referenced by a single body share one
/// [`LocInterner`] — `LocId`s are only meaningful relative to that
/// interner.  IDs are assigned densely from 0 and are stable for the
/// lifetime of the interner so the union-find can index parent / rank
/// arrays directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocId(pub u32);

/// Sentinel "anywhere" location.  Always `LocId(0)` — the interner
/// reserves the first slot at construction so callers can compare
/// against it cheaply.
pub const LOC_TOP: LocId = LocId(0);

/// Abstract heap location in the points-to lattice.
///
/// A pointer-targets-this kind of fact.  Cyclic field chains (e.g.
/// `a.next.next.…`) are bounded by [`MAX_FIELD_DEPTH`]; once the cap
/// is exceeded the chain folds to [`AbsLoc::Top`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AbsLoc {
    /// "Anywhere" — the over-approximation used when precision is
    /// unrecoverable (e.g. a value sourced from outside the analysed
    /// body, or a points-to set that exceeded the cap).
    Top,
    /// Allocation site within a body, identified by the SSA value of
    /// the defining instruction.  SSA guarantees a single definition
    /// per value, so the SSA value uniquely names the allocation site.
    ///
    /// `body` disambiguates allocations across bodies in the same
    /// file.  The interned `u32` is the `SsaValue.0` of the call /
    /// constructor instruction.
    Alloc(BodyId, u32),
    /// Function parameter — the abstract identity of the value
    /// supplied by the caller for parameter `index`.  The receiver
    /// (`self` / `this`) uses [`AbsLoc::SelfParam`] instead.
    Param(BodyId, usize),
    /// Implicit method receiver (`self` / `this`).  Distinct from
    /// `Param(_, _)` so callers don't have to encode an "is the
    /// receiver" sentinel index.
    SelfParam(BodyId),
    /// Heap field of a parent location: `parent.f`.  `parent` is
    /// itself a [`LocId`] — chains of field accesses produce nested
    /// `Field` locations.  Depth is bounded by [`MAX_FIELD_DEPTH`].
    Field { parent: LocId, field: FieldId },
}

/// Per-body interner mapping [`AbsLoc`] → dense [`LocId`].
///
/// Owns the canonical store: callers only hold [`LocId`]s and resolve
/// them through the interner.  The first slot ([`LOC_TOP`]) is always
/// `Top`, so the union-find resolver can short-circuit "is this Top?"
/// queries with a single integer compare.
#[derive(Clone, Debug)]
pub struct LocInterner {
    /// Locations indexed by `LocId.0`.
    locs: Vec<AbsLoc>,
    /// Reverse lookup: `(BodyId, alloc-ssa-value)` → `LocId`.
    alloc_lookup: HashMap<(BodyId, u32), LocId>,
    /// Reverse lookup: `(BodyId, param-index)` → `LocId`.
    param_lookup: HashMap<(BodyId, usize), LocId>,
    /// Reverse lookup for `SelfParam`.
    self_param_lookup: HashMap<BodyId, LocId>,
    /// Reverse lookup for `Field { parent, field }`.
    field_lookup: HashMap<(LocId, FieldId), LocId>,
    /// Interned depth of each location (0 for non-Field).  Used to
    /// fold deeply-nested `Field` chains to [`AbsLoc::Top`].
    depths: Vec<u8>,
}

impl Default for LocInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl LocInterner {
    /// Create a fresh interner with [`LOC_TOP`] pre-installed.
    pub fn new() -> Self {
        Self {
            locs: vec![AbsLoc::Top],
            alloc_lookup: HashMap::new(),
            param_lookup: HashMap::new(),
            self_param_lookup: HashMap::new(),
            field_lookup: HashMap::new(),
            depths: vec![0],
        }
    }

    /// Total number of interned locations (including the reserved
    /// [`LOC_TOP`] slot).
    #[inline]
    pub fn len(&self) -> usize {
        self.locs.len()
    }

    /// Whether the interner only holds the reserved [`LOC_TOP`] slot.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.locs.len() <= 1
    }

    /// Resolve a [`LocId`] back to its [`AbsLoc`].  Panics on out-of-
    /// range ids — only ids the interner produced are valid.
    #[inline]
    pub fn resolve(&self, id: LocId) -> &AbsLoc {
        &self.locs[id.0 as usize]
    }

    /// Depth of an interned location.  `0` for non-`Field` locations;
    /// `1 + depth(parent)` for `Field { parent, .. }`.
    #[inline]
    pub fn depth(&self, id: LocId) -> u8 {
        self.depths[id.0 as usize]
    }

    /// Intern an `Alloc` location.
    pub fn intern_alloc(&mut self, body: BodyId, ssa_value: u32) -> LocId {
        if let Some(&id) = self.alloc_lookup.get(&(body, ssa_value)) {
            return id;
        }
        let id = self.push(AbsLoc::Alloc(body, ssa_value), 0);
        self.alloc_lookup.insert((body, ssa_value), id);
        id
    }

    /// Intern a positional `Param` location.
    pub fn intern_param(&mut self, body: BodyId, index: usize) -> LocId {
        if let Some(&id) = self.param_lookup.get(&(body, index)) {
            return id;
        }
        let id = self.push(AbsLoc::Param(body, index), 0);
        self.param_lookup.insert((body, index), id);
        id
    }

    /// Intern a `SelfParam` location for the given body.
    pub fn intern_self_param(&mut self, body: BodyId) -> LocId {
        if let Some(&id) = self.self_param_lookup.get(&body) {
            return id;
        }
        let id = self.push(AbsLoc::SelfParam(body), 0);
        self.self_param_lookup.insert(body, id);
        id
    }

    /// Intern a `Field { parent, field }` location.  Returns
    /// [`LOC_TOP`] when `parent` is `Top` or when the resulting depth
    /// would exceed [`MAX_FIELD_DEPTH`].
    pub fn intern_field(&mut self, parent: LocId, field: FieldId) -> LocId {
        if parent == LOC_TOP {
            return LOC_TOP;
        }
        let parent_depth = self.depth(parent);
        if parent_depth >= MAX_FIELD_DEPTH {
            return LOC_TOP;
        }
        let key = (parent, field);
        if let Some(&id) = self.field_lookup.get(&key) {
            return id;
        }
        let id = self.push(AbsLoc::Field { parent, field }, parent_depth + 1);
        self.field_lookup.insert(key, id);
        id
    }

    fn push(&mut self, loc: AbsLoc, depth: u8) -> LocId {
        let id = LocId(self.locs.len() as u32);
        self.locs.push(loc);
        self.depths.push(depth);
        id
    }
}

/// Coarse classification of a value's points-to set, used by consumers
/// (Phase 2: resource lifecycle) that don't need full set membership but
/// do need to know "is this value's heap identity a *field* of some
/// other value, or does it stand on its own?".
///
/// The classifier is intentionally narrow: only [`PtrProxyHint::FieldOnly`]
/// is interesting to today's consumers, every other shape (empty, root,
/// `Top`, mixed) collapses to [`PtrProxyHint::Other`] so the consumer
/// keeps its existing behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtrProxyHint {
    /// Every member of the points-to set is an [`AbsLoc::Field`].  The
    /// value is a sub-object alias — e.g. `m` in `m := c.mu`.
    FieldOnly,
    /// Anything else: the set is empty, contains a root location
    /// ([`AbsLoc::SelfParam`] / [`AbsLoc::Param`] / [`AbsLoc::Alloc`]),
    /// contains [`AbsLoc::Top`], or mixes fields with roots.  Consumers
    /// fall back to their default behaviour.
    Other,
}

/// Bounded points-to set: a small sorted vector of [`LocId`]s.
///
/// "Bounded" means the set silently collapses to `{Top}` on overflow;
/// downstream consumers treat `Top`-containing sets as
/// over-approximations exactly the same way [`AbsLoc::Top`] is treated
/// at the singleton level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PointsToSet {
    /// Sorted, deduped list of locations.  When the cap is exceeded
    /// the set is replaced by `[LOC_TOP]`.
    ids: SmallVec<[LocId; 4]>,
}

impl Default for PointsToSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl PointsToSet {
    /// Empty set — the value points to nothing tracked by the
    /// analysis (e.g. a scalar constant).
    pub fn empty() -> Self {
        Self {
            ids: SmallVec::new(),
        }
    }

    /// Singleton set wrapping `id`.
    pub fn singleton(id: LocId) -> Self {
        let mut ids = SmallVec::new();
        ids.push(id);
        Self { ids }
    }

    /// `{Top}` — the universal over-approximation.
    pub fn top() -> Self {
        Self::singleton(LOC_TOP)
    }

    /// True when the set contains [`LOC_TOP`] (i.e. has saturated to
    /// the over-approximation).
    pub fn is_top(&self) -> bool {
        self.ids.contains(&LOC_TOP)
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Iterate over members in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = LocId> + '_ {
        self.ids.iter().copied()
    }

    /// Whether `id` is one of the set members (or the set is `Top`).
    pub fn contains(&self, id: LocId) -> bool {
        if self.is_top() {
            return true;
        }
        self.ids.binary_search(&id).is_ok()
    }

    /// Insert `id`, maintaining sort/dedup.  Saturates to `{Top}`
    /// when the set would exceed [`MAX_POINTSTO_MEMBERS`].
    pub fn insert(&mut self, id: LocId) {
        if self.is_top() {
            return;
        }
        if id == LOC_TOP {
            self.ids.clear();
            self.ids.push(LOC_TOP);
            return;
        }
        match self.ids.binary_search(&id) {
            Ok(_) => {}
            Err(pos) => {
                if self.ids.len() >= MAX_POINTSTO_MEMBERS {
                    self.ids.clear();
                    self.ids.push(LOC_TOP);
                } else {
                    self.ids.insert(pos, id);
                }
            }
        }
    }

    /// Set-union, in place.  Returns `true` when `self` changed —
    /// the constraint solver uses the bit to decide whether the
    /// containing equivalence class needs another pass.
    pub fn union_in_place(&mut self, other: &PointsToSet) -> bool {
        if self.is_top() {
            return false;
        }
        if other.is_top() {
            let was_top = self.is_top();
            self.ids.clear();
            self.ids.push(LOC_TOP);
            return !was_top;
        }
        let mut changed = false;
        for id in other.iter() {
            if id == LOC_TOP {
                let was_top = self.is_top();
                self.ids.clear();
                self.ids.push(LOC_TOP);
                return !was_top;
            }
            match self.ids.binary_search(&id) {
                Ok(_) => {}
                Err(pos) => {
                    if self.ids.len() >= MAX_POINTSTO_MEMBERS {
                        self.ids.clear();
                        self.ids.push(LOC_TOP);
                        return true;
                    }
                    self.ids.insert(pos, id);
                    changed = true;
                }
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> BodyId {
        BodyId(0)
    }

    #[test]
    fn loc_top_is_zero() {
        let interner = LocInterner::new();
        assert_eq!(interner.len(), 1);
        assert_eq!(interner.resolve(LOC_TOP), &AbsLoc::Top);
    }

    #[test]
    fn alloc_intern_dedupes() {
        let mut interner = LocInterner::new();
        let a = interner.intern_alloc(body(), 7);
        let b = interner.intern_alloc(body(), 7);
        let c = interner.intern_alloc(body(), 8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn param_intern_dedupes_by_index() {
        let mut interner = LocInterner::new();
        let p0 = interner.intern_param(body(), 0);
        let p1 = interner.intern_param(body(), 1);
        let p0_again = interner.intern_param(body(), 0);
        assert_eq!(p0, p0_again);
        assert_ne!(p0, p1);
    }

    #[test]
    fn field_intern_dedupes_structurally() {
        let mut interner = LocInterner::new();
        let parent = interner.intern_self_param(body());
        let f = FieldId(7);
        let a = interner.intern_field(parent, f);
        let b = interner.intern_field(parent, f);
        assert_eq!(a, b, "same parent + same field id ⇒ same loc id");
    }

    #[test]
    fn field_chain_depth_bounded() {
        let mut interner = LocInterner::new();
        let mut cur = interner.intern_self_param(body());
        let f = FieldId(1);
        for _ in 0..MAX_FIELD_DEPTH {
            cur = interner.intern_field(cur, f);
            assert_ne!(cur, LOC_TOP, "depth ≤ MAX should not fold");
        }
        let folded = interner.intern_field(cur, f);
        assert_eq!(folded, LOC_TOP, "exceeding MAX_FIELD_DEPTH folds to Top");
    }

    #[test]
    fn field_of_top_is_top() {
        let mut interner = LocInterner::new();
        let folded = interner.intern_field(LOC_TOP, FieldId(0));
        assert_eq!(folded, LOC_TOP);
    }

    #[test]
    fn pointsto_set_empty_singleton_top() {
        assert!(PointsToSet::empty().is_empty());
        assert!(PointsToSet::top().is_top());
        let mut interner = LocInterner::new();
        let p = interner.intern_self_param(body());
        let s = PointsToSet::singleton(p);
        assert!(s.contains(p));
        assert!(!s.is_top());
    }

    #[test]
    fn pointsto_set_insert_and_union() {
        let mut interner = LocInterner::new();
        let p0 = interner.intern_param(body(), 0);
        let p1 = interner.intern_param(body(), 1);
        let mut a = PointsToSet::singleton(p0);
        let b = PointsToSet::singleton(p1);
        let changed = a.union_in_place(&b);
        assert!(changed);
        assert_eq!(a.len(), 2);
        assert!(a.contains(p0));
        assert!(a.contains(p1));
        // Re-union is idempotent.
        let changed2 = a.union_in_place(&b);
        assert!(!changed2);
    }

    #[test]
    fn pointsto_set_saturates_to_top_on_overflow() {
        let mut interner = LocInterner::new();
        let mut s = PointsToSet::empty();
        for i in 0..(MAX_POINTSTO_MEMBERS as u32 + 4) {
            s.insert(interner.intern_alloc(body(), i));
        }
        assert!(s.is_top(), "set should collapse to {{Top}} on overflow");
    }

    #[test]
    fn pointsto_set_union_with_top_is_top() {
        let mut interner = LocInterner::new();
        let p = interner.intern_param(body(), 0);
        let mut a = PointsToSet::singleton(p);
        let changed = a.union_in_place(&PointsToSet::top());
        assert!(changed);
        assert!(a.is_top());
    }
}
