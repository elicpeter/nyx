use super::lattice::Lattice;
use super::symbol::SymbolId;
use bitflags::bitflags;
use std::collections::{HashMap, HashSet};

// ── ResourceLifecycle ────────────────────────────────────────────────────

bitflags! {
    /// Bitset of possible lifecycle states for a single resource handle.
    ///
    /// Join = bitwise OR (a variable may be in multiple states across paths).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ResourceLifecycle: u8 {
        const UNINIT = 0b0001;
        const OPEN   = 0b0010;
        const CLOSED = 0b0100;
        const MOVED  = 0b1000;
    }
}

impl Lattice for ResourceLifecycle {
    fn bot() -> Self {
        ResourceLifecycle::empty()
    }

    fn join(&self, other: &Self) -> Self {
        *self | *other
    }

    fn leq(&self, other: &Self) -> bool {
        self.intersection(*other) == *self
    }
}

// ── ResourceDomainState ──────────────────────────────────────────────────

/// Maps interned variable IDs to their lifecycle bitsets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceDomainState {
    pub vars: HashMap<SymbolId, ResourceLifecycle>,
}

impl ResourceDomainState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, sym: SymbolId) -> ResourceLifecycle {
        self.vars
            .get(&sym)
            .copied()
            .unwrap_or(ResourceLifecycle::empty())
    }

    pub fn set(&mut self, sym: SymbolId, state: ResourceLifecycle) {
        self.vars.insert(sym, state);
    }
}

impl Lattice for ResourceDomainState {
    fn bot() -> Self {
        Self::new()
    }

    fn join(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        for (&sym, &other_lc) in &other.vars {
            let entry = merged.vars.entry(sym).or_insert(ResourceLifecycle::empty());
            *entry = entry.join(&other_lc);
        }
        merged
    }

    fn leq(&self, other: &Self) -> bool {
        for (&sym, &self_lc) in &self.vars {
            let other_lc = other.get(sym);
            if !self_lc.leq(&other_lc) {
                return false;
            }
        }
        true
    }
}

// ── AuthLevel ────────────────────────────────────────────────────────────

/// Simple ordered lattice for path authentication state.
///
/// Bot = `Unauthed`. Join = `min` (conservative: if any path is unauthed,
/// the joined state is unauthed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthLevel {
    Unauthed,
    Authed,
    Admin,
}

impl Lattice for AuthLevel {
    fn bot() -> Self {
        AuthLevel::Unauthed
    }

    fn join(&self, other: &Self) -> Self {
        // Conservative: take the minimum (least privileged)
        (*self).min(*other)
    }

    fn leq(&self, other: &Self) -> bool {
        // Higher auth subsumes lower: Unauthed ⊑ Authed ⊑ Admin
        // In our lattice, join = min, so leq means self >= other
        *self >= *other
    }
}

// ── AuthDomainState ──────────────────────────────────────────────────────

/// Path auth level + per-variable validation bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthDomainState {
    pub auth_level: AuthLevel,
    pub validated: HashSet<SymbolId>,
}

impl Default for AuthDomainState {
    fn default() -> Self {
        Self {
            auth_level: AuthLevel::Unauthed,
            validated: HashSet::new(),
        }
    }
}

impl AuthDomainState {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Lattice for AuthDomainState {
    fn bot() -> Self {
        Self::new()
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            auth_level: self.auth_level.join(&other.auth_level),
            // Only validated on ALL paths counts
            validated: self.validated.intersection(&other.validated).copied().collect(),
        }
    }

    fn leq(&self, other: &Self) -> bool {
        self.auth_level.leq(&other.auth_level)
            && self.validated.is_superset(&other.validated)
    }
}

// ── ProductState ─────────────────────────────────────────────────────────

/// Composable product of resource and auth domains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductState {
    pub resource: ResourceDomainState,
    pub auth: AuthDomainState,
}

impl ProductState {
    pub fn initial() -> Self {
        Self {
            resource: ResourceDomainState::new(),
            auth: AuthDomainState::new(),
        }
    }
}

impl Lattice for ProductState {
    fn bot() -> Self {
        Self {
            resource: ResourceDomainState::bot(),
            auth: AuthDomainState::bot(),
        }
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            resource: self.resource.join(&other.resource),
            auth: self.auth.join(&other.auth),
        }
    }

    fn leq(&self, other: &Self) -> bool {
        self.resource.leq(&other.resource) && self.auth.leq(&other.auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_lifecycle_join_is_or() {
        let a = ResourceLifecycle::OPEN;
        let b = ResourceLifecycle::CLOSED;
        assert_eq!(a.join(&b), ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED);
    }

    #[test]
    fn resource_lifecycle_bot_identity() {
        let a = ResourceLifecycle::OPEN;
        assert_eq!(a.join(&ResourceLifecycle::bot()), a);
    }

    #[test]
    fn resource_lifecycle_leq() {
        let a = ResourceLifecycle::OPEN;
        let b = ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED;
        assert!(a.leq(&b));
        assert!(!b.leq(&a));
    }

    #[test]
    fn resource_domain_join_merges_keys() {
        let mut a = ResourceDomainState::new();
        let mut b = ResourceDomainState::new();
        let sym_x = SymbolId(0);
        let sym_y = SymbolId(1);

        a.set(sym_x, ResourceLifecycle::OPEN);
        b.set(sym_x, ResourceLifecycle::CLOSED);
        b.set(sym_y, ResourceLifecycle::OPEN);

        let joined = a.join(&b);
        assert_eq!(
            joined.get(sym_x),
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED
        );
        assert_eq!(joined.get(sym_y), ResourceLifecycle::OPEN);
    }

    #[test]
    fn auth_level_join_is_min() {
        assert_eq!(AuthLevel::Admin.join(&AuthLevel::Unauthed), AuthLevel::Unauthed);
        assert_eq!(AuthLevel::Authed.join(&AuthLevel::Admin), AuthLevel::Authed);
        assert_eq!(AuthLevel::Authed.join(&AuthLevel::Authed), AuthLevel::Authed);
    }

    #[test]
    fn auth_domain_join_intersects_validated() {
        let sym_a = SymbolId(0);
        let sym_b = SymbolId(1);
        let sym_c = SymbolId(2);

        let a = AuthDomainState {
            auth_level: AuthLevel::Authed,
            validated: [sym_a, sym_b].into_iter().collect(),
        };
        let b = AuthDomainState {
            auth_level: AuthLevel::Admin,
            validated: [sym_b, sym_c].into_iter().collect(),
        };

        let joined = a.join(&b);
        assert_eq!(joined.auth_level, AuthLevel::Authed);
        assert_eq!(joined.validated, [sym_b].into_iter().collect());
    }

    #[test]
    fn product_state_join() {
        let a = ProductState::initial();
        let b = ProductState::initial();
        let joined = a.join(&b);
        assert_eq!(joined, ProductState::initial());
    }

    #[test]
    fn may_must_leak_semantics() {
        // Must-leak: OPEN only
        let must_leak = ResourceLifecycle::OPEN;
        assert!(must_leak.contains(ResourceLifecycle::OPEN));
        assert!(!must_leak.contains(ResourceLifecycle::CLOSED));
        assert!(!must_leak.contains(ResourceLifecycle::MOVED));

        // May-leak: OPEN | CLOSED (some paths close, some don't)
        let may_leak = ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED;
        assert!(may_leak.contains(ResourceLifecycle::OPEN));
        assert!(may_leak.contains(ResourceLifecycle::CLOSED));

        // No leak: CLOSED only
        let no_leak = ResourceLifecycle::CLOSED;
        assert!(!no_leak.contains(ResourceLifecycle::OPEN));
        assert!(no_leak.contains(ResourceLifecycle::CLOSED));
    }

    // SymbolId is a newtype used in domain tests; ensure it's Copy
    #[test]
    fn symbol_id_is_copy() {
        let s = SymbolId(0);
        let s2 = s;
        assert_eq!(s, s2);
    }
}
