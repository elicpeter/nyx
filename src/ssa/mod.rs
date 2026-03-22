#[allow(dead_code)] // IR types — fields used by Display impl, tests, and Phase 2+
pub mod display;
#[allow(dead_code)]
pub mod ir;
pub mod lower;

#[allow(unused_imports)]
pub use ir::*;
pub use lower::lower_to_ssa;
