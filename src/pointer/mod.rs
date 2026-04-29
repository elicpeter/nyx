//! Field-sensitive Steensgaard alias / points-to analysis.
//!
//! Sibling pass to [`crate::ssa::heap`].  Where `heap.rs` tracks per-value
//! container identity for taint propagation through container element
//! abstractions, this module tracks **field-sensitive** points-to so the
//! engine can distinguish a receiver from one of its sub-fields:
//!
//! - `c.mu.Lock()` — the lock is acquired on `Field(c, mu)`, not on `c`
//!   itself.  Without this distinction the resource-lifecycle pass
//!   mis-attributes the acquire to the receiver and emits a spurious
//!   "leakable resource" finding (the gin / `context.go` FP class).
//! - Cross-method field flow — method A writes `this.cache`, method B
//!   reads `this.cache`; both observe a shared abstract location
//!   `Field(SelfParam, cache)` only when fields have a stable identity
//!   independent of the parent value.
//!
//! Phase 1 of the rollout (this commit) ships the analysis but no
//! consumer.  Behaviour is unchanged whether `NYX_POINTER_ANALYSIS=1` is
//! set or not — the analysis is opt-in and only computed when callers
//! ask for it.  Phase 2 (resource lifecycle) and Phase 3 (taint engine)
//! will start consuming the resulting facts.

pub mod analysis;
pub mod domain;

pub use analysis::{
    PointsToFacts, analyse_body, extract_field_points_to, is_container_read_callee_pub,
    is_container_write_callee,
};
pub use domain::{AbsLoc, LocId, LocInterner, PointsToSet, PtrProxyHint};

/// Returns whether the field-sensitive pointer analysis is enabled at runtime.
///
/// Default: enabled (post-Phase-6 flip on 2026-04-26).  Set
/// `NYX_POINTER_ANALYSIS=0` (or `false`) to disable for one release
/// cycle so customer scans can compare baselines.  The env-var
/// override is removed entirely in the next release.
#[inline]
pub fn is_enabled() -> bool {
    match std::env::var("NYX_POINTER_ANALYSIS").ok().as_deref() {
        Some("0") | Some("false") | Some("FALSE") => false,
        _ => true,
    }
}
