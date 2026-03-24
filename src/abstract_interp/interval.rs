//! Numeric interval domain for abstract interpretation.
//!
//! Tracks inclusive `[lo, hi]` integer bounds. `None` = unbounded (−∞ or +∞).
//! Both `None` = Top (any integer). Provides arithmetic transfer functions
//! (add, sub, mul, div, mod) with overflow-safe semantics.

use crate::state::lattice::{AbstractDomain, Lattice};

/// Numeric interval: `[lo, hi]` inclusive bounds.
///
/// - `top()` = `[None, None]` — any integer
/// - `bottom()` = `[1, 0]` — empty / unsatisfiable (lo > hi)
/// - `exact(n)` = `[n, n]` — singleton
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalFact {
    pub lo: Option<i64>,
    pub hi: Option<i64>,
}

impl IntervalFact {
    pub fn top() -> Self {
        Self { lo: None, hi: None }
    }

    pub fn bottom() -> Self {
        Self {
            lo: Some(1),
            hi: Some(0),
        }
    }

    pub fn exact(n: i64) -> Self {
        Self {
            lo: Some(n),
            hi: Some(n),
        }
    }

    pub fn is_top(&self) -> bool {
        self.lo.is_none() && self.hi.is_none()
    }

    pub fn is_bottom(&self) -> bool {
        matches!((self.lo, self.hi), (Some(l), Some(h)) if l > h)
    }

    /// True when both bounds are known finite values: the value is a proven
    /// integer within `[lo, hi]`.
    pub fn is_proven_bounded(&self) -> bool {
        self.lo.is_some() && self.hi.is_some() && !self.is_bottom()
    }

    // ── Lattice operations ──────────────────────────────────────────────

    /// Join (hull): `[min(lo), max(hi)]`.
    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        Self {
            lo: match (self.lo, other.lo) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None, // unbounded wins
            },
            hi: match (self.hi, other.hi) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            },
        }
    }

    /// Meet (intersection): `[max(lo), min(hi)]`.
    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        let lo = match (self.lo, other.lo) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let hi = match (self.hi, other.hi) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let result = Self { lo, hi };
        if result.is_bottom() {
            Self::bottom()
        } else {
            result
        }
    }

    /// Widen: drop bounds that changed between iterations.
    ///
    /// Guarantees finite ascending chains: each bound can transition
    /// `Some(n) → None` at most once, then stabilizes. Height = 3 per bound.
    pub fn widen(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        let lo = if self.lo == other.lo {
            self.lo
        } else {
            None // lower bound changed → drop to −∞
        };
        let hi = if self.hi == other.hi {
            self.hi
        } else {
            None // upper bound changed → drop to +∞
        };
        Self { lo, hi }
    }

    pub fn leq(&self, other: &Self) -> bool {
        if self.is_bottom() {
            return true;
        }
        if other.is_bottom() {
            return false;
        }
        // self ⊑ other iff other.lo ≤ self.lo and self.hi ≤ other.hi
        // (other is at least as wide as self)
        let lo_ok = match (self.lo, other.lo) {
            (_, None) => true,        // other unbounded below → ok
            (None, Some(_)) => false, // self unbounded, other bounded → not ⊑
            (Some(a), Some(b)) => a >= b,
        };
        let hi_ok = match (self.hi, other.hi) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a <= b,
        };
        lo_ok && hi_ok
    }

    // ── Arithmetic transfer functions ───────────────────────────────────

    /// Addition: `[a.lo + b.lo, a.hi + b.hi]`.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            lo: checked_add_opt(self.lo, other.lo),
            hi: checked_add_opt(self.hi, other.hi),
        }
    }

    /// Subtraction: `[a.lo - b.hi, a.hi - b.lo]`.
    pub fn sub(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            lo: checked_sub_opt(self.lo, other.hi),
            hi: checked_sub_opt(self.hi, other.lo),
        }
    }

    /// Multiplication: min/max of all 4 endpoint products.
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        // If any bound is None, result is Top for that direction
        if self.is_top() || other.is_top() {
            return Self::top();
        }
        match (self.lo, self.hi, other.lo, other.hi) {
            (Some(a_lo), Some(a_hi), Some(b_lo), Some(b_hi)) => {
                let products = [
                    a_lo.checked_mul(b_lo),
                    a_lo.checked_mul(b_hi),
                    a_hi.checked_mul(b_lo),
                    a_hi.checked_mul(b_hi),
                ];
                let lo = products.iter().filter_map(|p| *p).min();
                let hi = products.iter().filter_map(|p| *p).max();
                // If any product overflowed, the corresponding bound is None
                if products.iter().any(|p| p.is_none()) {
                    Self {
                        lo: if lo.is_some() && products[..2].iter().all(|p| p.is_some()) {
                            lo
                        } else {
                            None
                        },
                        hi: if hi.is_some() && products[2..].iter().all(|p| p.is_some()) {
                            hi
                        } else {
                            None
                        },
                    }
                } else {
                    Self { lo, hi }
                }
            }
            _ => Self::top(),
        }
    }

    /// Division: conservative. If divisor range spans 0, result is Top.
    pub fn div(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        match (self.lo, self.hi, other.lo, other.hi) {
            (Some(a_lo), Some(a_hi), Some(b_lo), Some(b_hi)) => {
                // Division by zero possible → Top
                if b_lo <= 0 && b_hi >= 0 {
                    return Self::top();
                }
                let quotients = [
                    a_lo.checked_div(b_lo),
                    a_lo.checked_div(b_hi),
                    a_hi.checked_div(b_lo),
                    a_hi.checked_div(b_hi),
                ];
                let lo = quotients.iter().filter_map(|q| *q).min();
                let hi = quotients.iter().filter_map(|q| *q).max();
                Self { lo, hi }
            }
            _ => Self::top(),
        }
    }

    /// Modulo: `[0, max(|b.lo|, |b.hi|) - 1]` when divisor is fully known
    /// and non-zero. Otherwise Top.
    pub fn modulo(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        match (other.lo, other.hi) {
            (Some(b_lo), Some(b_hi)) => {
                if b_lo <= 0 && b_hi >= 0 {
                    return Self::top(); // modulo by zero possible
                }
                let abs_max = b_lo.unsigned_abs().max(b_hi.unsigned_abs());
                if abs_max == 0 {
                    return Self::top();
                }
                // Result of a % b is in [0, |b|-1] for non-negative a,
                // or [-(|b|-1), |b|-1] in general. Conservative: use wider.
                let bound = (abs_max - 1) as i64;
                if self.lo.is_some_and(|l| l >= 0) {
                    Self {
                        lo: Some(0),
                        hi: Some(bound),
                    }
                } else {
                    Self {
                        lo: Some(-bound),
                        hi: Some(bound),
                    }
                }
            }
            _ => Self::top(),
        }
    }
}

impl Lattice for IntervalFact {
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

impl AbstractDomain for IntervalFact {
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

// ── Overflow-safe helpers ───────────────────────────────────────────────

fn checked_add_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => x.checked_add(y), // None on overflow
        _ => None,                               // unbounded
    }
}

fn checked_sub_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => x.checked_sub(y),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_values() {
        let a = IntervalFact::exact(5);
        assert_eq!(a.lo, Some(5));
        assert_eq!(a.hi, Some(5));
        assert!(a.is_proven_bounded());
        assert!(!a.is_top());
        assert!(!a.is_bottom());
    }

    #[test]
    fn top_and_bottom() {
        let t = IntervalFact::top();
        assert!(t.is_top());
        assert!(!t.is_bottom());
        assert!(!t.is_proven_bounded());

        let b = IntervalFact::bottom();
        assert!(b.is_bottom());
        assert!(!b.is_top());
        assert!(!b.is_proven_bounded());
    }

    // ── Lattice properties ──────────────────────────────────────────

    #[test]
    fn join_commutative() {
        let a = IntervalFact::exact(3);
        let b = IntervalFact::exact(7);
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_associative() {
        let a = IntervalFact::exact(1);
        let b = IntervalFact::exact(5);
        let c = IntervalFact::exact(3);
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn join_idempotent() {
        let a = IntervalFact {
            lo: Some(2),
            hi: Some(8),
        };
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn join_hull() {
        let a = IntervalFact {
            lo: Some(2),
            hi: Some(5),
        };
        let b = IntervalFact {
            lo: Some(3),
            hi: Some(9),
        };
        let j = a.join(&b);
        assert_eq!(j.lo, Some(2));
        assert_eq!(j.hi, Some(9));
    }

    #[test]
    fn join_with_bottom_identity() {
        let a = IntervalFact::exact(5);
        assert_eq!(a.join(&IntervalFact::bottom()), a);
        assert_eq!(IntervalFact::bottom().join(&a), a);
    }

    #[test]
    fn meet_intersection() {
        let a = IntervalFact {
            lo: Some(1),
            hi: Some(10),
        };
        let b = IntervalFact {
            lo: Some(5),
            hi: Some(15),
        };
        let m = a.meet(&b);
        assert_eq!(m.lo, Some(5));
        assert_eq!(m.hi, Some(10));
    }

    #[test]
    fn meet_disjoint_is_bottom() {
        let a = IntervalFact {
            lo: Some(1),
            hi: Some(3),
        };
        let b = IntervalFact {
            lo: Some(5),
            hi: Some(7),
        };
        assert!(a.meet(&b).is_bottom());
    }

    #[test]
    fn leq_subset() {
        let narrow = IntervalFact {
            lo: Some(3),
            hi: Some(5),
        };
        let wide = IntervalFact {
            lo: Some(1),
            hi: Some(10),
        };
        assert!(narrow.leq(&wide));
        assert!(!wide.leq(&narrow));
    }

    #[test]
    fn leq_top_greatest() {
        let a = IntervalFact::exact(42);
        assert!(a.leq(&IntervalFact::top()));
        assert!(!IntervalFact::top().leq(&a));
    }

    #[test]
    fn leq_bottom_least() {
        assert!(IntervalFact::bottom().leq(&IntervalFact::exact(0)));
        assert!(IntervalFact::bottom().leq(&IntervalFact::top()));
    }

    // ── Widening ────────────────────────────────────────────────────

    #[test]
    fn widen_stable_bounds() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        assert_eq!(a.widen(&a), a);
    }

    #[test]
    fn widen_growing_upper() {
        let old = IntervalFact {
            lo: Some(0),
            hi: Some(5),
        };
        let new = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let w = old.widen(&new);
        assert_eq!(w.lo, Some(0)); // stable
        assert_eq!(w.hi, None); // grew → dropped
    }

    #[test]
    fn widen_growing_lower() {
        let old = IntervalFact {
            lo: Some(5),
            hi: Some(10),
        };
        let new = IntervalFact {
            lo: Some(2),
            hi: Some(10),
        };
        let w = old.widen(&new);
        assert_eq!(w.lo, None); // changed → dropped
        assert_eq!(w.hi, Some(10));
    }

    // ── Arithmetic transfer ─────────────────────────────────────────

    #[test]
    fn add_exact() {
        assert_eq!(IntervalFact::exact(5).add(&IntervalFact::exact(3)), IntervalFact::exact(8));
    }

    #[test]
    fn add_ranges() {
        let a = IntervalFact {
            lo: Some(1),
            hi: Some(5),
        };
        let b = IntervalFact {
            lo: Some(2),
            hi: Some(4),
        };
        let r = a.add(&b);
        assert_eq!(r.lo, Some(3));
        assert_eq!(r.hi, Some(9));
    }

    #[test]
    fn sub_ranges() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let b = IntervalFact {
            lo: Some(1),
            hi: Some(3),
        };
        let r = a.sub(&b);
        assert_eq!(r.lo, Some(-3)); // 0 - 3
        assert_eq!(r.hi, Some(9)); // 10 - 1
    }

    #[test]
    fn mul_ranges() {
        let a = IntervalFact {
            lo: Some(2),
            hi: Some(5),
        };
        let b = IntervalFact {
            lo: Some(3),
            hi: Some(4),
        };
        let r = a.mul(&b);
        assert_eq!(r.lo, Some(6)); // 2*3
        assert_eq!(r.hi, Some(20)); // 5*4
    }

    #[test]
    fn mul_negative() {
        let a = IntervalFact {
            lo: Some(-3),
            hi: Some(2),
        };
        let b = IntervalFact {
            lo: Some(1),
            hi: Some(4),
        };
        let r = a.mul(&b);
        assert_eq!(r.lo, Some(-12)); // -3*4
        assert_eq!(r.hi, Some(8)); // 2*4
    }

    #[test]
    fn div_no_zero() {
        let a = IntervalFact {
            lo: Some(10),
            hi: Some(20),
        };
        let b = IntervalFact {
            lo: Some(2),
            hi: Some(5),
        };
        let r = a.div(&b);
        assert_eq!(r.lo, Some(2)); // 10/5
        assert_eq!(r.hi, Some(10)); // 20/2
    }

    #[test]
    fn div_spans_zero_is_top() {
        let a = IntervalFact::exact(10);
        let b = IntervalFact {
            lo: Some(-1),
            hi: Some(1),
        };
        assert!(a.div(&b).is_top());
    }

    #[test]
    fn modulo_positive() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(100),
        };
        let b = IntervalFact {
            lo: Some(7),
            hi: Some(7),
        };
        let r = a.modulo(&b);
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(6));
    }

    #[test]
    fn overflow_add() {
        let a = IntervalFact::exact(i64::MAX);
        let b = IntervalFact::exact(1);
        let r = a.add(&b);
        // Overflow → bound becomes None
        assert_eq!(r.hi, None);
    }

    #[test]
    fn overflow_mul() {
        let a = IntervalFact::exact(i64::MAX);
        let b = IntervalFact::exact(2);
        let r = a.mul(&b);
        // At least one bound should be None due to overflow
        assert!(r.lo.is_none() || r.hi.is_none());
    }
}
