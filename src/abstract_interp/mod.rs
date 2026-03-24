//! Phase 17: Abstract interpretation framework.
//!
//! Provides a product abstract domain ([`AbstractValue`]) composing independent
//! subdomains:
//! - [`IntervalFact`]: numeric interval `[lo, hi]` with arithmetic transfer
//! - [`StringFact`]: string prefix + suffix with concatenation transfer
//! - [`BitFact`]: known-zero/known-one bit masks for bitwise transfer
//!
//! Abstract values are stored per-SSA-value in [`AbstractState`], which is
//! carried through the taint analysis worklist in `SsaTaintState`. The framework
//! propagates abstract values forward through SSA operations, joins at CFG
//! merges, and widens at loop heads to ensure termination.
//!
//! ## Feature gate
//!
//! Enabled by default. Set `NYX_ABSTRACT_INTERP=0` to disable.

pub mod bit_domain;
pub mod interval;
pub mod string_domain;

pub use bit_domain::BitFact;
pub use interval::IntervalFact;
pub use string_domain::StringFact;

use crate::ssa::ir::SsaValue;
use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Feature gate: check if abstract interpretation is enabled.
///
/// Enabled by default. Set `NYX_ABSTRACT_INTERP=0` or
/// `NYX_ABSTRACT_INTERP=false` to disable.
pub fn is_enabled() -> bool {
    std::env::var("NYX_ABSTRACT_INTERP")
        .map(|v| v != "0" && v.to_ascii_lowercase() != "false")
        .unwrap_or(true)
}

// ── AbstractValue ───────────────────────────────────────────────────────

/// Per-SSA-value abstract element: product of all subdomains.
///
/// Each subdomain is independent — join, meet, widen, and leq are applied
/// component-wise. Adding a new subdomain requires adding a field here
/// and updating the component-wise implementations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractValue {
    pub interval: IntervalFact,
    pub string: StringFact,
    pub bits: BitFact,
}

impl AbstractValue {
    pub fn top() -> Self {
        Self {
            interval: IntervalFact::top(),
            string: StringFact::top(),
            bits: BitFact::top(),
        }
    }

    pub fn bottom() -> Self {
        Self {
            interval: IntervalFact::bottom(),
            string: StringFact::bottom(),
            bits: BitFact::bottom(),
        }
    }

    pub fn is_top(&self) -> bool {
        self.interval.is_top() && self.string.is_top() && self.bits.is_top()
    }

    pub fn is_bottom(&self) -> bool {
        self.interval.is_bottom() && self.string.is_bottom() && self.bits.is_bottom()
    }

    pub fn join(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.join(&other.interval),
            string: self.string.join(&other.string),
            bits: self.bits.join(&other.bits),
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.meet(&other.interval),
            string: self.string.meet(&other.string),
            bits: <BitFact as AbstractDomain>::meet(&self.bits, &other.bits),
        }
    }

    pub fn widen(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.widen(&other.interval),
            string: self.string.widen(&other.string),
            bits: self.bits.widen(&other.bits),
        }
    }

    pub fn leq(&self, other: &Self) -> bool {
        self.interval.leq(&other.interval)
            && self.string.leq(&other.string)
            && self.bits.leq(&other.bits)
    }
}

impl Lattice for AbstractValue {
    fn bot() -> Self {
        Self::bottom()
    }

    fn join(&self, other: &Self) -> Self {
        self.join(other)
    }

    fn leq(&self, other: &Self) -> bool {
        self.leq(other)
    }
}

impl AbstractDomain for AbstractValue {
    fn top() -> Self {
        Self::top()
    }

    fn meet(&self, other: &Self) -> Self {
        self.meet(other)
    }

    fn widen(&self, other: &Self) -> Self {
        self.widen(other)
    }
}

// ── AbstractState ───────────────────────────────────────────────────────

/// Maximum abstract values tracked per block (performance bound).
const MAX_ABSTRACT_VALUES: usize = 64;

/// Per-block abstract state: sorted map from SsaValue → AbstractValue.
///
/// Values not in the map are implicitly Top (no knowledge). Sorted by
/// SsaValue for O(n) merge-join, matching the pattern used by
/// `SsaTaintState.values`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbstractState {
    values: SmallVec<[(SsaValue, AbstractValue); 8]>,
}

impl AbstractState {
    pub fn empty() -> Self {
        Self {
            values: SmallVec::new(),
        }
    }

    /// Get abstract value for an SSA value. Returns Top if absent.
    pub fn get(&self, v: SsaValue) -> AbstractValue {
        self.values
            .binary_search_by_key(&v, |(id, _)| *id)
            .ok()
            .map(|idx| self.values[idx].1.clone())
            .unwrap_or_else(AbstractValue::top)
    }

    /// Set abstract value for an SSA value. Drops Top values to save space.
    pub fn set(&mut self, v: SsaValue, val: AbstractValue) {
        if val.is_top() {
            // Don't store Top — it's the default
            if let Ok(idx) = self.values.binary_search_by_key(&v, |(id, _)| *id) {
                self.values.remove(idx);
            }
            return;
        }
        match self.values.binary_search_by_key(&v, |(id, _)| *id) {
            Ok(idx) => self.values[idx].1 = val,
            Err(idx) => {
                if self.values.len() < MAX_ABSTRACT_VALUES {
                    self.values.insert(idx, (v, val));
                }
                // Over budget: silently drop (conservative — defaults to Top)
            }
        }
    }

    /// Merge-join two abstract states. Values present in both are joined;
    /// values present in only one side are dropped (absent = Top, join with
    /// Top = Top).
    pub fn join(&self, other: &Self) -> Self {
        let mut result = SmallVec::with_capacity(self.values.len().min(other.values.len()));
        let (mut i, mut j) = (0, 0);

        while i < self.values.len() && j < other.values.len() {
            match self.values[i].0.cmp(&other.values[j].0) {
                std::cmp::Ordering::Less => {
                    // Only in self → join with Top = Top → drop
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    // Only in other → drop
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let joined = self.values[i].1.join(&other.values[j].1);
                    if !joined.is_top() {
                        result.push((self.values[i].0, joined));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        Self { values: result }
    }

    /// Merge-widen: for values present in both states, apply widening.
    /// Values present in only one side are dropped (Top).
    pub fn widen(&self, other: &Self) -> Self {
        let mut result = SmallVec::with_capacity(self.values.len().min(other.values.len()));
        let (mut i, mut j) = (0, 0);

        while i < self.values.len() && j < other.values.len() {
            match self.values[i].0.cmp(&other.values[j].0) {
                std::cmp::Ordering::Less => {
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let widened = self.values[i].1.widen(&other.values[j].1);
                    if !widened.is_top() {
                        result.push((self.values[i].0, widened));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        Self { values: result }
    }

    /// Partial order: self ⊑ other.
    pub fn leq(&self, other: &Self) -> bool {
        // Every non-Top entry in self must have a corresponding entry in other
        // with self[v] ⊑ other[v]. Entries only in other are fine (Top ⊑ anything
        // is false, but absent self entries are Top which is handled).
        for (v, val) in &self.values {
            let other_val = other.get(*v);
            if !val.leq(&other_val) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_value_top_bottom() {
        assert!(AbstractValue::top().is_top());
        assert!(AbstractValue::bottom().is_bottom());
        assert!(!AbstractValue::top().is_bottom());
        assert!(!AbstractValue::bottom().is_top());
    }

    #[test]
    fn abstract_value_join_componentwise() {
        let a = AbstractValue {
            interval: IntervalFact::exact(1),
            string: StringFact::from_prefix("https://a.com/"),
            bits: BitFact::top(),
        };
        let b = AbstractValue {
            interval: IntervalFact::exact(5),
            string: StringFact::from_prefix("https://b.com/"),
            bits: BitFact::top(),
        };
        let j = a.join(&b);
        assert_eq!(j.interval.lo, Some(1));
        assert_eq!(j.interval.hi, Some(5));
        assert_eq!(j.string.prefix.as_deref(), Some("https://"));
    }

    #[test]
    fn abstract_value_widen_componentwise() {
        let old = AbstractValue {
            interval: IntervalFact {
                lo: Some(0),
                hi: Some(5),
            },
            string: StringFact::from_prefix("hello"),
            bits: BitFact::top(),
        };
        let new = AbstractValue {
            interval: IntervalFact {
                lo: Some(0),
                hi: Some(10),
            },
            string: StringFact::from_prefix("hello"),
            bits: BitFact::top(),
        };
        let w = old.widen(&new);
        assert_eq!(w.interval.lo, Some(0)); // stable
        assert_eq!(w.interval.hi, None); // grew → widened
        assert_eq!(w.string.prefix.as_deref(), Some("hello")); // stable
    }

    #[test]
    fn abstract_state_get_default_top() {
        let state = AbstractState::empty();
        assert!(state.get(SsaValue(42)).is_top());
    }

    #[test]
    fn abstract_state_set_get() {
        let mut state = AbstractState::empty();
        let val = AbstractValue {
            interval: IntervalFact::exact(10),
            string: StringFact::top(),
            bits: BitFact::top(),
        };
        state.set(SsaValue(1), val.clone());
        assert_eq!(state.get(SsaValue(1)), val);
    }

    #[test]
    fn abstract_state_set_top_removes() {
        let mut state = AbstractState::empty();
        state.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact::exact(5),
                string: StringFact::top(),
                bits: BitFact::top(),
            },
        );
        assert!(!state.get(SsaValue(1)).is_top());
        state.set(SsaValue(1), AbstractValue::top());
        assert!(state.get(SsaValue(1)).is_top());
        assert!(state.values.is_empty());
    }

    #[test]
    fn abstract_state_join() {
        let mut a = AbstractState::empty();
        a.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact::exact(3),
                string: StringFact::top(),
                bits: BitFact::top(),
            },
        );
        a.set(
            SsaValue(2),
            AbstractValue {
                interval: IntervalFact::exact(10),
                string: StringFact::top(),
                bits: BitFact::top(),
            },
        );

        let mut b = AbstractState::empty();
        b.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact::exact(7),
                string: StringFact::top(),
                bits: BitFact::top(),
            },
        );
        // SsaValue(2) not in b → join drops it (Top)

        let j = a.join(&b);
        // SsaValue(1): join [3,3] and [7,7] = [3,7]
        let v1 = j.get(SsaValue(1));
        assert_eq!(v1.interval.lo, Some(3));
        assert_eq!(v1.interval.hi, Some(7));
        // SsaValue(2): only in a → dropped to Top
        assert!(j.get(SsaValue(2)).is_top());
    }

    #[test]
    fn abstract_state_widen() {
        let mut old = AbstractState::empty();
        old.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact {
                    lo: Some(0),
                    hi: Some(5),
                },
                string: StringFact::top(),
                bits: BitFact::top(),
            },
        );

        let mut new = AbstractState::empty();
        new.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact {
                    lo: Some(0),
                    hi: Some(10),
                },
                string: StringFact::top(),
                bits: BitFact::top(),
            },
        );

        let w = old.widen(&new);
        let v1 = w.get(SsaValue(1));
        assert_eq!(v1.interval.lo, Some(0)); // stable
        assert_eq!(v1.interval.hi, None); // grew → widened
    }

    #[test]
    fn loop_carried_phi_join_and_widen() {
        // Simulate: x = 0; loop { x = phi(0, x+1) }
        // Iteration 1: join([0,0], [1,1]) = [0,1]
        let init = IntervalFact::exact(0);
        let inc1 = IntervalFact::exact(1);
        let phi1 = init.join(&inc1);
        assert_eq!(phi1.lo, Some(0));
        assert_eq!(phi1.hi, Some(1));

        // Iteration 2: join([0,1], [1,2]) = [0,2]
        let inc2 = IntervalFact {
            lo: Some(1),
            hi: Some(2),
        };
        let phi2 = phi1.join(&inc2);
        assert_eq!(phi2.lo, Some(0));
        assert_eq!(phi2.hi, Some(2));

        // Widen: [0,1] vs [0,2] → upper bound grew → [0, None]
        let widened = phi1.widen(&phi2);
        assert_eq!(widened.lo, Some(0));
        assert_eq!(widened.hi, None);

        // Iteration 3: join([0,None], [1,None]) = [0,None] (stable!)
        let inc3 = IntervalFact {
            lo: Some(1),
            hi: None,
        };
        let phi3 = widened.join(&inc3);
        assert_eq!(phi3.lo, Some(0));
        assert_eq!(phi3.hi, None);
        assert_eq!(phi3, widened); // converged
    }
}
