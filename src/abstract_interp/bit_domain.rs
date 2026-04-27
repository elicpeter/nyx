//! Bit-level abstract domain for abstract interpretation.
//!
//! Tracks known-zero and known-one bit masks over the 64-bit two's complement
//! representation of `i64` values. This enables precise reasoning about bitwise
//! operations (`&`, `|`, `^`, `<<`, `>>`) that interval analysis alone cannot
//! capture.
//!
//! ## Integer model
//!
//! Operates on signed `i64` two's complement:
//! - Bit positions 0-62 are value bits, bit 63 is the sign bit.
//! - `known_zero & known_one == 0` invariant (a bit cannot be both).
//! - `from_const(n)` sets all 64 bits as known.
//! - `is_non_negative()` checks sign bit (63) is `known_zero`.

use crate::abstract_interp::IntervalFact;
use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};

/// Bit-level abstract fact: known-zero and known-one masks.
///
/// - `top()` = `{known_zero: 0, known_one: 0}` — no bits known
/// - `bottom()` = `{known_zero: MAX, known_one: MAX}` — contradictory
/// - `from_const(n)` = all 64 bits known
///
/// Invariant: `known_zero & known_one == 0` for non-bottom values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitFact {
    /// Bitmask of bit positions provably zero.
    pub known_zero: u64,
    /// Bitmask of bit positions provably one.
    pub known_one: u64,
}

impl BitFact {
    /// Top: no bits known.
    pub fn top() -> Self {
        Self {
            known_zero: 0,
            known_one: 0,
        }
    }

    /// Bottom: contradictory (all bits both zero and one).
    pub fn bottom() -> Self {
        Self {
            known_zero: u64::MAX,
            known_one: u64::MAX,
        }
    }

    /// All bits known from a concrete constant.
    pub fn from_const(n: i64) -> Self {
        let bits = n as u64;
        Self {
            known_zero: !bits,
            known_one: bits,
        }
    }

    pub fn is_top(&self) -> bool {
        self.known_zero == 0 && self.known_one == 0
    }

    pub fn is_bottom(&self) -> bool {
        self.known_zero & self.known_one != 0
    }

    /// True if the sign bit (63) is provably zero → value is non-negative.
    pub fn is_non_negative(&self) -> bool {
        self.known_zero & (1u64 << 63) != 0
    }

    // ── Bitwise transfer functions ──────────────────────────────────────

    /// Bitwise AND transfer: `result[i] = a[i] & b[i]`.
    ///
    /// - A bit is known-zero if EITHER input is known-zero.
    /// - A bit is known-one if BOTH inputs are known-one.
    pub fn bit_and(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            known_zero: self.known_zero | other.known_zero,
            known_one: self.known_one & other.known_one,
        }
    }

    /// Bitwise OR transfer: `result[i] = a[i] | b[i]`.
    ///
    /// - A bit is known-one if EITHER input is known-one.
    /// - A bit is known-zero if BOTH inputs are known-zero.
    pub fn bit_or(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            known_zero: self.known_zero & other.known_zero,
            known_one: self.known_one | other.known_one,
        }
    }

    /// Bitwise XOR transfer: `result[i] = a[i] ^ b[i]`.
    ///
    /// - A bit is known-one if one input is known-one and the other known-zero.
    /// - A bit is known-zero if both inputs are same (both known-one or both known-zero).
    pub fn bit_xor(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            known_zero: (self.known_zero & other.known_zero) | (self.known_one & other.known_one),
            known_one: (self.known_one & other.known_zero) | (self.known_zero & other.known_one),
        }
    }

    /// Left shift transfer: `result = self << shift_amount`.
    ///
    /// Precise when shift amount is a singleton in `0..63`. The low `k` bits
    /// of the result are provably zero (vacated by the shift). Known bits
    /// from the input are shifted up.
    pub fn left_shift(&self, shift: &IntervalFact) -> Self {
        if self.is_bottom() || shift.is_bottom() {
            return Self::bottom();
        }
        // Only precise for singleton shift amounts
        match (shift.lo, shift.hi) {
            (Some(lo), Some(hi)) if lo == hi && (0..=63).contains(&lo) => {
                let k = lo as u32;
                Self {
                    // Known-zero bits shift up; low k bits are vacated (known zero)
                    known_zero: (self.known_zero << k) | ((1u64 << k) - 1),
                    // Known-one bits shift up
                    known_one: self.known_one << k,
                }
            }
            _ => Self::top(),
        }
    }

    /// Right shift transfer: `result = self >> shift_amount` (arithmetic).
    ///
    /// Precise when shift amount is a singleton in `0..63`. For non-negative
    /// values (sign bit known-zero), the high `k` bits are provably zero.
    /// For negative values (sign bit known-one), high bits are provably one.
    /// When sign is unknown, high bits become unknown.
    pub fn right_shift(&self, shift: &IntervalFact) -> Self {
        if self.is_bottom() || shift.is_bottom() {
            return Self::bottom();
        }
        match (shift.lo, shift.hi) {
            (Some(lo), Some(hi)) if lo == hi && (0..=63).contains(&lo) => {
                let k = lo as u32;
                let high_mask = if k == 0 { 0u64 } else { u64::MAX << (64 - k) };

                if self.is_non_negative() {
                    // Non-negative: arithmetic right shift fills with 0
                    Self {
                        known_zero: (self.known_zero >> k) | high_mask,
                        known_one: self.known_one >> k,
                    }
                } else if self.known_one & (1u64 << 63) != 0 {
                    // Known negative: arithmetic right shift fills with 1
                    Self {
                        known_zero: self.known_zero >> k,
                        known_one: (self.known_one >> k) | high_mask,
                    }
                } else {
                    // Sign unknown: shift known bits, high bits become unknown
                    Self {
                        known_zero: self.known_zero >> k,
                        known_one: self.known_one >> k,
                    }
                }
            }
            _ => Self::top(),
        }
    }

    /// Compute an upper bound hint from known-zero bits.
    ///
    /// When the value is non-negative and has high known-zero bits, returns
    /// the tightest upper bound implied by those bits: the highest possible
    /// value given the known-zero constraints.
    ///
    /// Returns `None` if no useful bound can be derived.
    pub fn upper_bound_hint(&self) -> Option<i64> {
        if !self.is_non_negative() || self.is_bottom() {
            return None;
        }
        // The highest possible value is: all unknown bits set to 1, known-one
        // bits set to 1, known-zero bits set to 0.
        // That's: !known_zero & 0x7FFF_FFFF_FFFF_FFFF (non-negative)
        let max_val = !self.known_zero & 0x7FFF_FFFF_FFFF_FFFFu64;
        Some(max_val as i64)
    }
}

impl Lattice for BitFact {
    fn bot() -> Self {
        Self::bottom()
    }

    /// Join: keep only bits known in BOTH operands.
    fn join(&self, other: &Self) -> Self {
        // Special case: bottom joined with anything is the other
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        Self {
            known_zero: self.known_zero & other.known_zero,
            known_one: self.known_one & other.known_one,
        }
    }

    /// Partial order: `self ⊑ other` iff self knows at least as many bits as other.
    fn leq(&self, other: &Self) -> bool {
        if self.is_bottom() {
            return true;
        }
        if other.is_bottom() {
            return false;
        }
        // self ⊑ other: self is more precise (has more known bits)
        // Every known bit in other must also be known in self
        (other.known_zero & !self.known_zero) == 0 && (other.known_one & !self.known_one) == 0
    }
}

impl AbstractDomain for BitFact {
    fn top() -> Self {
        Self::top()
    }

    /// Meet: combine knowledge from both operands.
    fn meet(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        let kz = self.known_zero | other.known_zero;
        let ko = self.known_one | other.known_one;
        // Check consistency: a bit can't be both known-zero and known-one
        if kz & ko != 0 {
            return Self::bottom();
        }
        Self {
            known_zero: kz,
            known_one: ko,
        }
    }

    /// Widen: same as join (finite lattice height — 64 bits × 3 states).
    fn widen(&self, other: &Self) -> Self {
        self.join(other)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructors ────────────────────────────────────────────────────

    #[test]
    fn from_const_positive() {
        let f = BitFact::from_const(0x0F);
        assert_eq!(f.known_one, 0x0F);
        assert_eq!(f.known_zero, !0x0Fu64);
        assert!(f.is_non_negative());
    }

    #[test]
    fn from_const_negative() {
        let f = BitFact::from_const(-1);
        assert_eq!(f.known_one, u64::MAX);
        assert_eq!(f.known_zero, 0);
        assert!(!f.is_non_negative());
    }

    #[test]
    fn from_const_zero() {
        let f = BitFact::from_const(0);
        assert_eq!(f.known_one, 0);
        assert_eq!(f.known_zero, u64::MAX);
        assert!(f.is_non_negative());
    }

    #[test]
    fn top_and_bottom() {
        assert!(BitFact::top().is_top());
        assert!(!BitFact::top().is_bottom());
        assert!(BitFact::bottom().is_bottom());
        assert!(!BitFact::bottom().is_top());
    }

    // ── Lattice properties ──────────────────────────────────────────────

    #[test]
    fn join_commutative() {
        let a = BitFact::from_const(0xFF);
        let b = BitFact::from_const(0x0F);
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_idempotent() {
        let a = BitFact::from_const(42);
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn join_relaxes_bits() {
        // 0xFF and 0x0F share bits 0-3 as known-one
        let a = BitFact::from_const(0xFF);
        let b = BitFact::from_const(0x0F);
        let j = a.join(&b);
        // Bits 0-3 are one in both, so known_one should have those
        assert_eq!(j.known_one & 0xFF, 0x0F);
        // Bits 4-7 differ (one in a, zero in b), so unknown
        assert_eq!(j.known_zero & 0xF0, 0);
        assert_eq!(j.known_one & 0xF0, 0);
    }

    #[test]
    fn meet_commutative() {
        let a = BitFact {
            known_zero: 0xF0,
            known_one: 0x0F,
        };
        let b = BitFact {
            known_zero: 0x0F00,
            known_one: 0,
        };
        assert_eq!(
            <BitFact as AbstractDomain>::meet(&a, &b),
            <BitFact as AbstractDomain>::meet(&b, &a)
        );
    }

    #[test]
    fn meet_contradiction_is_bottom() {
        let a = BitFact {
            known_zero: 0,
            known_one: 0x01,
        };
        let b = BitFact {
            known_zero: 0x01,
            known_one: 0,
        };
        assert!(<BitFact as AbstractDomain>::meet(&a, &b).is_bottom());
    }

    #[test]
    fn leq_reflexive() {
        let a = BitFact::from_const(42);
        assert!(a.leq(&a));
    }

    #[test]
    fn leq_bottom_is_least() {
        assert!(BitFact::bottom().leq(&BitFact::top()));
        assert!(BitFact::bottom().leq(&BitFact::from_const(0)));
    }

    #[test]
    fn leq_more_precise_is_lower() {
        let precise = BitFact::from_const(0xFF);
        let vague = BitFact::top();
        assert!(precise.leq(&vague));
        assert!(!vague.leq(&precise));
    }

    // ── Bitwise AND transfer ────────────────────────────────────────────

    #[test]
    fn bit_and_transfer() {
        let a = BitFact::from_const(0xFF);
        let b = BitFact::from_const(0x0F);
        let result = a.bit_and(&b);
        // 0xFF & 0x0F = 0x0F
        assert_eq!(result.known_one, 0x0F);
        // All bits not in 0x0F are known-zero
        assert_eq!(result.known_zero, !0x0Fu64);
    }

    #[test]
    fn bit_and_with_mask_bounds() {
        // Unknown value AND'd with constant mask 0x07
        let unknown = BitFact::top();
        let mask = BitFact::from_const(0x07);
        let result = unknown.bit_and(&mask);
        // Bits above bit 2 are known-zero (from mask)
        assert_eq!(result.known_zero & !0x07u64, !0x07u64);
        // Low 3 bits are unknown (input was unknown)
        assert_eq!(result.known_one & 0x07, 0);
    }

    // ── Bitwise OR transfer ─────────────────────────────────────────────

    #[test]
    fn bit_or_transfer() {
        let a = BitFact::from_const(0xF0);
        let b = BitFact::from_const(0x0F);
        let result = a.bit_or(&b);
        assert_eq!(result.known_one, 0xFF);
        assert_eq!(result.known_zero, !0xFFu64);
    }

    #[test]
    fn bit_or_with_unknown() {
        let unknown = BitFact::top();
        let bits = BitFact::from_const(0x01);
        let result = unknown.bit_or(&bits);
        // Bit 0 is known-one (from OR with 1)
        assert_ne!(result.known_one & 0x01, 0);
        // Other bits unknown
        assert_eq!(result.known_zero & 0x01, 0);
    }

    // ── Bitwise XOR transfer ────────────────────────────────────────────

    #[test]
    fn bit_xor_transfer() {
        let a = BitFact::from_const(0xFF);
        let b = BitFact::from_const(0x0F);
        let result = a.bit_xor(&b);
        // 0xFF ^ 0x0F = 0xF0
        assert_eq!(result.known_one, 0xF0);
        assert_eq!(result.known_zero, !0xF0u64);
    }

    #[test]
    fn bit_xor_self_is_zero() {
        let a = BitFact::from_const(42);
        let result = a.bit_xor(&a);
        // x ^ x = 0
        assert_eq!(result.known_one, 0);
        assert_eq!(result.known_zero, u64::MAX);
    }

    #[test]
    fn bit_xor_with_zero_is_identity() {
        let a = BitFact::from_const(0xFF);
        let zero = BitFact::from_const(0);
        let result = a.bit_xor(&zero);
        assert_eq!(result, a);
    }

    // ── Left shift transfer ─────────────────────────────────────────────

    #[test]
    fn left_shift_known_bits() {
        let a = BitFact::from_const(0x0F);
        let shift = IntervalFact::exact(4);
        let result = a.left_shift(&shift);
        // 0x0F << 4 = 0xF0
        assert_eq!(result.known_one, 0xF0);
        // Low 4 bits are known-zero (vacated)
        assert_ne!(result.known_zero & 0x0F, 0);
    }

    #[test]
    fn left_shift_range_is_top() {
        let a = BitFact::from_const(0x0F);
        let shift = IntervalFact {
            lo: Some(1),
            hi: Some(3),
        };
        let result = a.left_shift(&shift);
        assert!(result.is_top());
    }

    #[test]
    fn left_shift_invalid_is_top() {
        let a = BitFact::from_const(0x0F);
        let shift = IntervalFact::exact(64);
        assert!(a.left_shift(&shift).is_top());
        let neg_shift = IntervalFact::exact(-1);
        assert!(a.left_shift(&neg_shift).is_top());
    }

    // ── Right shift transfer ────────────────────────────────────────────

    #[test]
    fn right_shift_known_bits_non_negative() {
        let a = BitFact::from_const(0xF0);
        let shift = IntervalFact::exact(4);
        let result = a.right_shift(&shift);
        // 0xF0 >> 4 = 0x0F (non-negative, high bits zero)
        assert_eq!(result.known_one, 0x0F);
        // High 4 bits should be known-zero
        assert_ne!(result.known_zero & (0xFu64 << 60), 0);
    }

    #[test]
    fn right_shift_negative_fills_ones() {
        // -16 = ...1111_0000 in two's complement
        let a = BitFact::from_const(-16);
        let shift = IntervalFact::exact(4);
        let result = a.right_shift(&shift);
        // -16 >> 4 = -1 (arithmetic shift fills with 1)
        assert_eq!(result.known_one, u64::MAX);
        assert_eq!(result.known_zero, 0);
    }

    #[test]
    fn right_shift_unknown_sign() {
        // Sign bit unknown — high bits after shift should be unknown
        let a = BitFact {
            known_zero: 0x0F,
            known_one: 0,
        };
        let shift = IntervalFact::exact(4);
        let result = a.right_shift(&shift);
        // Can't determine high bits → they should NOT be in known_zero or known_one
        let high_mask = 0xFu64 << 60;
        assert_eq!(result.known_zero & high_mask, 0);
        assert_eq!(result.known_one & high_mask, 0);
    }

    // ── Upper bound hint ────────────────────────────────────────────────

    #[test]
    fn upper_bound_hint_constant() {
        let f = BitFact::from_const(7);
        assert_eq!(f.upper_bound_hint(), Some(7));
    }

    #[test]
    fn upper_bound_hint_masked() {
        // Unknown value masked with 0x07 → high bits known zero → max = 7
        let unknown = BitFact::top();
        let mask = BitFact::from_const(0x07);
        let result = unknown.bit_and(&mask);
        assert_eq!(result.upper_bound_hint(), Some(7));
    }

    #[test]
    fn upper_bound_hint_negative_is_none() {
        let f = BitFact::from_const(-1);
        assert_eq!(f.upper_bound_hint(), None);
    }

    #[test]
    fn upper_bound_hint_top_is_none() {
        assert_eq!(BitFact::top().upper_bound_hint(), None);
    }

    // ── is_non_negative ─────────────────────────────────────────────────

    #[test]
    fn is_non_negative_positive() {
        assert!(BitFact::from_const(42).is_non_negative());
        assert!(BitFact::from_const(0).is_non_negative());
    }

    #[test]
    fn is_non_negative_negative() {
        assert!(!BitFact::from_const(-1).is_non_negative());
        assert!(!BitFact::from_const(i64::MIN).is_non_negative());
    }

    #[test]
    fn is_non_negative_unknown() {
        assert!(!BitFact::top().is_non_negative());
    }

    // ── Additional lattice algebra laws ──────────────────────────────

    fn sample_bits() -> Vec<BitFact> {
        vec![
            BitFact::bottom(),
            BitFact::top(),
            BitFact::from_const(0),
            BitFact::from_const(1),
            BitFact::from_const(-1),
            BitFact::from_const(0xFF),
            BitFact::from_const(i64::MIN),
            BitFact::from_const(i64::MAX),
        ]
    }

    #[test]
    fn join_associative_bit() {
        let xs = sample_bits();
        for a in &xs {
            for b in &xs {
                for c in &xs {
                    let lhs = a.join(b).join(c);
                    let rhs = a.join(&b.join(c));
                    assert_eq!(
                        lhs, rhs,
                        "join not associative for {:?}, {:?}, {:?}",
                        a, b, c
                    );
                }
            }
        }
    }

    #[test]
    fn meet_idempotent_bit() {
        for a in sample_bits() {
            assert_eq!(a.meet(&a), a, "meet not idempotent for {:?}", a);
        }
    }

    #[test]
    fn meet_associative_bit() {
        let xs = sample_bits();
        for a in &xs {
            for b in &xs {
                for c in &xs {
                    let lhs = a.meet(b).meet(c);
                    let rhs = a.meet(&b.meet(c));
                    assert_eq!(
                        lhs, rhs,
                        "meet not associative for {:?}, {:?}, {:?}",
                        a, b, c
                    );
                }
            }
        }
    }

    #[test]
    fn meet_top_identity_bit() {
        for a in sample_bits() {
            assert_eq!(a.meet(&BitFact::top()), a, "x ⊓ ⊤ failed for {:?}", a);
        }
    }

    #[test]
    fn meet_bottom_absorbing_bit() {
        for a in sample_bits() {
            assert_eq!(
                a.meet(&BitFact::bottom()),
                BitFact::bottom(),
                "x ⊓ ⊥ failed for {:?}",
                a
            );
        }
    }

    #[test]
    fn join_top_absorbing_bit() {
        for a in sample_bits() {
            assert_eq!(
                a.join(&BitFact::top()),
                BitFact::top(),
                "x ⊔ ⊤ failed for {:?}",
                a
            );
        }
    }

    #[test]
    fn widen_idempotent_bit() {
        for a in sample_bits() {
            assert_eq!(a.widen(&a), a, "widen(x, x) failed for {:?}", a);
        }
    }

    /// **Soundness**: `widen(a, b) ⊒ join(a, b)` for the bit lattice.
    #[test]
    fn widen_over_approximates_join_bit() {
        let xs = sample_bits();
        for a in &xs {
            for b in &xs {
                let j = a.join(b);
                let w = a.widen(b);
                assert!(
                    j.leq(&w),
                    "widen({:?}, {:?}) = {:?} does not over-approx join = {:?}",
                    a, b, w, j
                );
            }
        }
    }

    /// `a ⊓ b ⊑ a` and `a ⊓ b ⊑ b` — meet is the greatest lower bound.
    #[test]
    fn meet_is_lower_bound_bit() {
        let xs = sample_bits();
        for a in &xs {
            for b in &xs {
                let m = a.meet(b);
                assert!(m.leq(a), "a ⊓ b ⊑ a failed for {:?}, {:?}", a, b);
                assert!(m.leq(b), "a ⊓ b ⊑ b failed for {:?}, {:?}", a, b);
            }
        }
    }

    /// `a ⊑ a ⊔ b` and `b ⊑ a ⊔ b` — join is the least upper bound.
    #[test]
    fn join_is_upper_bound_bit() {
        let xs = sample_bits();
        for a in &xs {
            for b in &xs {
                let j = a.join(b);
                assert!(a.leq(&j), "a ⊑ a ⊔ b failed for {:?}, {:?}", a, b);
                assert!(b.leq(&j), "b ⊑ a ⊔ b failed for {:?}, {:?}", a, b);
            }
        }
    }

    /// Joining `i64::MIN` and `i64::MAX` (extreme sign-bit-different
    /// constants) must not panic and must produce a valid Top-or-bottom
    /// bit fact (used in path-merging).
    #[test]
    fn join_min_max_signbit_safe() {
        let a = BitFact::from_const(i64::MIN);
        let b = BitFact::from_const(i64::MAX);
        let _ = a.join(&b); // must not panic
        let _ = a.meet(&b);
        let _ = a.widen(&b);
    }
}
