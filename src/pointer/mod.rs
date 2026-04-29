//! Field-sensitive Steensgaard alias / points-to analysis.
//!
//! Sibling to [`crate::ssa::heap`]: where heap tracks per-value
//! container identity for element abstractions, this module tracks
//! field-sensitive points-to so the engine can distinguish a receiver
//! from a sub-field. `c.mu.Lock()` acquires on `Field(c, mu)`, not `c`,
//! so the resource-lifecycle pass doesn't mis-attribute the acquire.
//! Cross-method field flow (method A writes `this.cache`, method B
//! reads it) observes the shared `Field(SelfParam, cache)` location.

pub mod analysis;
pub mod domain;

pub use analysis::{
    PointsToFacts, analyse_body, extract_field_points_to, is_container_read_callee_pub,
    is_container_write_callee,
};
pub use domain::{AbsLoc, LocId, LocInterner, PointsToSet, PtrProxyHint};

/// Returns whether the field-sensitive pointer analysis is enabled.
/// Set `NYX_POINTER_ANALYSIS=0` (or `false`) to disable.
#[inline]
pub fn is_enabled() -> bool {
    !matches!(
        std::env::var("NYX_POINTER_ANALYSIS").ok().as_deref(),
        Some("0") | Some("false") | Some("FALSE")
    )
}
