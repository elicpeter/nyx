//! Phase 15: Path constraint solving for infeasible path pruning.
//!
//! This module implements a per-value abstract domain ([`ValueFact`]) with
//! canonical lattice operations (meet/join/widen), SSA-aware condition
//! lowering, and incremental unsatisfiability detection via a [`PathEnv`]
//! constraint environment.
//!
//! ## Architecture
//!
//! - [`domain`]: Abstract domain types (ValueFact, PathEnv, UnionFind)
//! - [`lower`]: Condition lowering from CFG/SSA to structured ConditionExpr
//! - [`solver`]: Constraint refinement and satisfiability checking
//!
//! ## Known limitations (V1)
//!
//! - **No full disjunctive reasoning.** OR-heavy true branches lose
//!   constraints at join. Disjunctive PathState deferred to V2.
//! - **Comparison operators parsed from condition_text.** The CFG/SSA IR
//!   does not decompose individual comparisons into structured operations;
//!   condition_text parsing is the only way to extract operator and literal.
//!   This is isolated in [`lower`].
//! - **Bounded transitive cycle detection.** Relational constraint cycle
//!   detection walks at most 4 hops. Longer chains are missed (conservative).
//! - **No cast/conversion modeling.** `parseInt`, `int()`, `parseFloat`
//!   etc. yield Top for the result's ValueFact.
//! - **BoolTest is conservative.** Does not infer NonNull from truthiness
//!   unless value is known boolean-typed.
//! - **Variable resolution approximation.** Reaching definitions resolved
//!   via value_defs scan; may be imprecise in complex CFG shapes without
//!   full dominator tree walk.
//! - **No language-specific truthiness model.** All languages share the
//!   same conservative BoolTest behavior.
//! - **Floats not modeled in ConstValue.** Float literals fall through
//!   to Unknown.

pub mod domain;
pub mod lower;
pub mod solver;

#[cfg(test)]
mod tests;

pub use domain::{
    BoolState, ConstValue, Nullability, PathEnv, RelOp, TypeSet, ValueFact,
    MAX_DISEQUALITY_EDGES, MAX_EQUALITY_EDGES, MAX_PATH_ENV_ENTRIES,
    MAX_REFINE_PER_BLOCK, MAX_RELATIONAL, WIDEN_THRESHOLD,
};
pub use lower::{lower_condition, CompOp, ConditionExpr, Operand};
pub use solver::{is_satisfiable, refine_env};

/// Feature gate: check if constraint solving is enabled.
///
/// Enabled by default. Set `NYX_CONSTRAINT=0` or `NYX_CONSTRAINT=false`
/// to disable.
pub fn is_enabled() -> bool {
    std::env::var("NYX_CONSTRAINT")
        .map(|v| v != "0" && v.to_ascii_lowercase() != "false")
        .unwrap_or(true)
}
