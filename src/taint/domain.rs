use crate::labels::{Cap, SourceKind};
use crate::state::lattice::Lattice;
use crate::state::symbol::SymbolId;
use crate::taint::path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

/// Maximum origins tracked per variable (bounded to prevent growth).
const MAX_ORIGINS_PER_VAR: usize = 4;

/// Per-variable taint information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarTaint {
    pub caps: Cap,
    /// Up to N origins that contributed taint (bounded).
    pub origins: SmallVec<[TaintOrigin; 2]>,
}

/// A single taint origin — the node and classification of where taint came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaintOrigin {
    pub node: NodeIndex,
    pub source_kind: SourceKind,
}

/// Compact bitset for up to 64 variables (indexed by SymbolId ordinal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallBitSet(u64);

impl SmallBitSet {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn insert(&mut self, id: SymbolId) {
        let idx = id.0;
        if idx < 64 {
            self.0 |= 1u64 << idx;
        }
    }

    pub fn contains(&self, id: SymbolId) -> bool {
        let idx = id.0;
        if idx < 64 {
            self.0 & (1u64 << idx) != 0
        } else {
            false
        }
    }

    /// Union: self | other
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection: self & other
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[allow(dead_code)]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether self is a subset of other.
    #[allow(dead_code)] // used by Lattice::leq
    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & other.0 == self.0
    }

    /// Whether self is a superset of other.
    #[allow(dead_code)] // used by Lattice::leq
    pub fn is_superset_of(self, other: Self) -> bool {
        other.is_subset_of(self)
    }
}

/// Monotone predicate summary per variable.
///
/// Tracks which whitelisted predicate kinds are known true/false on ALL paths.
/// join = intersection of bits (must-hold semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PredicateSummary {
    /// Bitmask: bit 0=NullCheck, 1=EmptyCheck, 2=ErrorCheck
    pub known_true: u8,
    pub known_false: u8,
}

impl PredicateSummary {
    pub fn empty() -> Self {
        Self {
            known_true: 0,
            known_false: 0,
        }
    }

    /// Join = intersection (only predicates true on ALL paths).
    pub fn join(self, other: Self) -> Self {
        Self {
            known_true: self.known_true & other.known_true,
            known_false: self.known_false & other.known_false,
        }
    }

    /// Check for contradiction: same kind known both true and false.
    pub fn has_contradiction(self) -> bool {
        self.known_true & self.known_false != 0
    }

    pub fn is_empty(self) -> bool {
        self.known_true == 0 && self.known_false == 0
    }
}

/// Map a whitelisted PredicateKind to its bit index (0-2).
/// Returns None for non-whitelisted kinds.
pub fn predicate_kind_bit(kind: PredicateKind) -> Option<u8> {
    match kind {
        PredicateKind::NullCheck => Some(0),
        PredicateKind::EmptyCheck => Some(1),
        PredicateKind::ErrorCheck => Some(2),
        _ => None,
    }
}

/// The abstract taint state at a program point.
///
/// Uses sorted SmallVec keyed by SymbolId for O(n) merge-join.
/// Variables beyond the interner's capacity are naturally excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintState {
    /// Per-variable taint, sorted by SymbolId.
    pub vars: SmallVec<[(SymbolId, VarTaint); 16]>,

    /// Variables validated on ALL paths (intersection on join).
    pub validated_must: SmallBitSet,

    /// Variables validated on ANY path (union on join).
    pub validated_may: SmallBitSet,

    /// Per-variable predicate summary (sorted by SymbolId).
    pub predicates: SmallVec<[(SymbolId, PredicateSummary); 4]>,
}

impl TaintState {
    /// Create the initial state (no taint, no validation, no predicates).
    pub fn initial() -> Self {
        Self {
            vars: SmallVec::new(),
            validated_must: SmallBitSet::empty(),
            validated_may: SmallBitSet::empty(),
            predicates: SmallVec::new(),
        }
    }

    /// Look up taint for a variable.
    pub fn get(&self, sym: SymbolId) -> Option<&VarTaint> {
        self.vars
            .binary_search_by_key(&sym, |(id, _)| *id)
            .ok()
            .map(|idx| &self.vars[idx].1)
    }

    /// Insert or update taint for a variable.
    pub fn set(&mut self, sym: SymbolId, taint: VarTaint) {
        match self.vars.binary_search_by_key(&sym, |(id, _)| *id) {
            Ok(idx) => self.vars[idx].1 = taint,
            Err(idx) => self.vars.insert(idx, (sym, taint)),
        }
    }

    /// Remove taint for a variable.
    pub fn remove(&mut self, sym: SymbolId) {
        if let Ok(idx) = self.vars.binary_search_by_key(&sym, |(id, _)| *id) {
            self.vars.remove(idx);
        }
    }

    /// Set a predicate summary for a variable.
    pub fn set_predicate(&mut self, sym: SymbolId, summary: PredicateSummary) {
        match self
            .predicates
            .binary_search_by_key(&sym, |(id, _)| *id)
        {
            Ok(idx) => self.predicates[idx].1 = summary,
            Err(idx) => self.predicates.insert(idx, (sym, summary)),
        }
    }

    /// Get predicate summary for a variable.
    pub fn get_predicate(&self, sym: SymbolId) -> PredicateSummary {
        self.predicates
            .binary_search_by_key(&sym, |(id, _)| *id)
            .ok()
            .map(|idx| self.predicates[idx].1)
            .unwrap_or_else(PredicateSummary::empty)
    }

    /// Check if any variable has contradictory predicates.
    pub fn has_contradiction(&self) -> bool {
        self.predicates.iter().any(|(_, s)| s.has_contradiction())
    }
}

impl Lattice for TaintState {
    fn bot() -> Self {
        Self::initial()
    }

    fn join(&self, other: &Self) -> Self {
        // Merge-join vars (sorted by SymbolId)
        let vars = merge_join_vars(&self.vars, &other.vars);

        // validated_must = intersection (must hold on ALL paths)
        let validated_must = self.validated_must.intersection(other.validated_must);

        // validated_may = union (holds on ANY path)
        let validated_may = self.validated_may.union(other.validated_may);

        // predicates = per-key intersection of known_true/known_false bits
        let predicates = merge_join_predicates(&self.predicates, &other.predicates);

        TaintState {
            vars,
            validated_must,
            validated_may,
            predicates,
        }
    }

    fn leq(&self, other: &Self) -> bool {
        // Per-key Cap subset + origins subset
        if !vars_leq(&self.vars, &other.vars) {
            return false;
        }

        // validated_must: self ⊇ other (superset = less info = lower)
        if !self.validated_must.is_superset_of(other.validated_must) {
            return false;
        }

        // validated_may: self ⊆ other
        if !self.validated_may.is_subset_of(other.validated_may) {
            return false;
        }

        // predicates: self.known_true ⊇ other.known_true (more precise = lower)
        predicates_leq(&self.predicates, &other.predicates)
    }
}

/// Merge-join two sorted var lists: per-key Cap OR + origins merge (bounded).
fn merge_join_vars(
    a: &[(SymbolId, VarTaint)],
    b: &[(SymbolId, VarTaint)],
) -> SmallVec<[(SymbolId, VarTaint); 16]> {
    let mut result = SmallVec::with_capacity(a.len().max(b.len()));
    let (mut i, mut j) = (0, 0);

    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                result.push(a[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                result.push(b[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let caps = a[i].1.caps | b[j].1.caps;
                let origins = merge_origins(&a[i].1.origins, &b[j].1.origins);
                result.push((a[i].0, VarTaint { caps, origins }));
                i += 1;
                j += 1;
            }
        }
    }

    // Remaining from either side
    while i < a.len() {
        result.push(a[i].clone());
        i += 1;
    }
    while j < b.len() {
        result.push(b[j].clone());
        j += 1;
    }

    result
}

/// Merge two origin lists, deduplicating by node and bounding at MAX_ORIGINS_PER_VAR.
fn merge_origins(
    a: &SmallVec<[TaintOrigin; 2]>,
    b: &SmallVec<[TaintOrigin; 2]>,
) -> SmallVec<[TaintOrigin; 2]> {
    let mut merged = a.clone();
    for origin in b {
        if merged.len() >= MAX_ORIGINS_PER_VAR {
            break;
        }
        if !merged.iter().any(|o| o.node == origin.node) {
            merged.push(*origin);
        }
    }
    merged
}

/// Check if a.vars ⊑ b.vars (per-key Cap subset + origins subset).
#[allow(dead_code)] // called by Lattice::leq
fn vars_leq(a: &[(SymbolId, VarTaint)], b: &[(SymbolId, VarTaint)]) -> bool {
    let (mut i, mut j) = (0, 0);

    while i < a.len() {
        if j >= b.len() {
            return false; // a has keys not in b → not ⊑
        }
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => return false, // key in a but not b
            std::cmp::Ordering::Greater => {
                j += 1; // key only in b, skip
            }
            std::cmp::Ordering::Equal => {
                // Cap subset check
                if a[i].1.caps & b[j].1.caps != a[i].1.caps {
                    return false;
                }
                // Origins subset check (by node)
                for orig in &a[i].1.origins {
                    if !b[j].1.origins.iter().any(|o| o.node == orig.node) {
                        return false;
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    true
}

/// Merge-join predicate summaries with intersection semantics.
fn merge_join_predicates(
    a: &[(SymbolId, PredicateSummary)],
    b: &[(SymbolId, PredicateSummary)],
) -> SmallVec<[(SymbolId, PredicateSummary); 4]> {
    let mut result = SmallVec::new();
    let (mut i, mut j) = (0, 0);

    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                // Key only in a — intersection with empty = empty → drop
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let joined = a[i].1.join(b[j].1);
                if !joined.is_empty() {
                    result.push((a[i].0, joined));
                }
                i += 1;
                j += 1;
            }
        }
    }
    // Keys only in one side → intersection with empty = drop

    result
}

/// Check if a.predicates ⊑ b.predicates.
/// More precise (more known_true bits) = lower in the lattice.
/// So a ⊑ b means a.known_true ⊇ b.known_true for each key.
#[allow(dead_code)] // called by Lattice::leq
fn predicates_leq(
    a: &[(SymbolId, PredicateSummary)],
    b: &[(SymbolId, PredicateSummary)],
) -> bool {
    let (mut i, mut j) = (0, 0);

    // For each key in b, a must have at least as many bits
    while j < b.len() {
        if i >= a.len() {
            // b has keys that a doesn't — a is missing info = not lower
            return false;
        }
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                // a has extra keys (more info) — OK for leq
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                // b has a key that a doesn't → a has fewer bits → not ⊑
                return false;
            }
            std::cmp::Ordering::Equal => {
                // a.known_true must be a superset of b.known_true
                if a[i].1.known_true & b[j].1.known_true != b[j].1.known_true {
                    return false;
                }
                if a[i].1.known_false & b[j].1.known_false != b[j].1.known_false {
                    return false;
                }
                i += 1;
                j += 1;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_taint(sym: u32, caps: Cap) -> (SymbolId, VarTaint) {
        (
            SymbolId(sym),
            VarTaint {
                caps,
                origins: SmallVec::new(),
            },
        )
    }

    fn make_taint_with_origin(
        sym: u32,
        caps: Cap,
        node: usize,
    ) -> (SymbolId, VarTaint) {
        (
            SymbolId(sym),
            VarTaint {
                caps,
                origins: smallvec::smallvec![TaintOrigin {
                    node: NodeIndex::new(node),
                    source_kind: SourceKind::Unknown,
                }],
            },
        )
    }

    fn state_with_vars(vars: Vec<(SymbolId, VarTaint)>) -> TaintState {
        let mut s = TaintState::initial();
        s.vars = SmallVec::from_vec(vars);
        s
    }

    // ── Lattice property tests ──────────────────────────────────────────

    #[test]
    fn bot_identity() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR)]);
        assert_eq!(a.join(&TaintState::bot()), a);
        assert_eq!(TaintState::bot().join(&a), a);
    }

    #[test]
    fn join_commutativity() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR)]);
        let b = state_with_vars(vec![make_taint(1, Cap::SHELL_ESCAPE)]);
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_associativity() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR)]);
        let b = state_with_vars(vec![make_taint(0, Cap::SHELL_ESCAPE)]);
        let c = state_with_vars(vec![make_taint(1, Cap::HTML_ESCAPE)]);
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn join_idempotency() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR | Cap::SHELL_ESCAPE)]);
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn leq_reflexive() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR)]);
        assert!(a.leq(&a));
    }

    #[test]
    fn leq_consistent_with_join() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR)]);
        let b = state_with_vars(vec![
            make_taint(0, Cap::ENV_VAR | Cap::SHELL_ESCAPE),
        ]);
        assert!(a.leq(&b));
        assert_eq!(a.join(&b), b);
    }

    #[test]
    fn join_merges_caps() {
        let a = state_with_vars(vec![make_taint(0, Cap::ENV_VAR)]);
        let b = state_with_vars(vec![make_taint(0, Cap::SHELL_ESCAPE)]);
        let joined = a.join(&b);
        assert_eq!(
            joined.get(SymbolId(0)).unwrap().caps,
            Cap::ENV_VAR | Cap::SHELL_ESCAPE
        );
    }

    #[test]
    fn join_merges_origins() {
        let a = state_with_vars(vec![make_taint_with_origin(0, Cap::ENV_VAR, 1)]);
        let b = state_with_vars(vec![make_taint_with_origin(0, Cap::ENV_VAR, 2)]);
        let joined = a.join(&b);
        assert_eq!(joined.get(SymbolId(0)).unwrap().origins.len(), 2);
    }

    #[test]
    fn validated_must_intersection() {
        let mut a = TaintState::initial();
        a.validated_must.insert(SymbolId(0));
        a.validated_must.insert(SymbolId(1));

        let mut b = TaintState::initial();
        b.validated_must.insert(SymbolId(1));
        b.validated_must.insert(SymbolId(2));

        let joined = a.join(&b);
        assert!(!joined.validated_must.contains(SymbolId(0)));
        assert!(joined.validated_must.contains(SymbolId(1)));
        assert!(!joined.validated_must.contains(SymbolId(2)));
    }

    #[test]
    fn validated_may_union() {
        let mut a = TaintState::initial();
        a.validated_may.insert(SymbolId(0));

        let mut b = TaintState::initial();
        b.validated_may.insert(SymbolId(1));

        let joined = a.join(&b);
        assert!(joined.validated_may.contains(SymbolId(0)));
        assert!(joined.validated_may.contains(SymbolId(1)));
    }

    #[test]
    fn predicate_contradiction() {
        let mut state = TaintState::initial();
        state.set_predicate(
            SymbolId(0),
            PredicateSummary {
                known_true: 1,  // NullCheck true
                known_false: 1, // NullCheck false
            },
        );
        assert!(state.has_contradiction());
    }

    #[test]
    fn predicate_no_contradiction() {
        let mut state = TaintState::initial();
        state.set_predicate(
            SymbolId(0),
            PredicateSummary {
                known_true: 1,  // NullCheck true
                known_false: 2, // EmptyCheck false (different kind)
            },
        );
        assert!(!state.has_contradiction());
    }

    #[test]
    fn predicate_join_intersection() {
        let mut a = TaintState::initial();
        a.set_predicate(
            SymbolId(0),
            PredicateSummary {
                known_true: 0b011, // NullCheck + EmptyCheck
                known_false: 0,
            },
        );

        let mut b = TaintState::initial();
        b.set_predicate(
            SymbolId(0),
            PredicateSummary {
                known_true: 0b010, // EmptyCheck only
                known_false: 0,
            },
        );

        let joined = a.join(&b);
        let pred = joined.get_predicate(SymbolId(0));
        assert_eq!(pred.known_true, 0b010); // only EmptyCheck on both paths
    }

    // ── SmallBitSet tests ───────────────────────────────────────────────

    #[test]
    fn small_bitset_basic() {
        let mut bs = SmallBitSet::empty();
        assert!(bs.is_empty());

        bs.insert(SymbolId(0));
        assert!(bs.contains(SymbolId(0)));
        assert!(!bs.contains(SymbolId(1)));
        assert!(!bs.is_empty());
    }

    #[test]
    fn small_bitset_union_intersection() {
        let mut a = SmallBitSet::empty();
        a.insert(SymbolId(0));
        a.insert(SymbolId(2));

        let mut b = SmallBitSet::empty();
        b.insert(SymbolId(1));
        b.insert(SymbolId(2));

        let u = a.union(b);
        assert!(u.contains(SymbolId(0)));
        assert!(u.contains(SymbolId(1)));
        assert!(u.contains(SymbolId(2)));

        let i = a.intersection(b);
        assert!(!i.contains(SymbolId(0)));
        assert!(!i.contains(SymbolId(1)));
        assert!(i.contains(SymbolId(2)));
    }
}
