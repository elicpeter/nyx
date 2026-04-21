#[allow(dead_code)] // IR types — fields used by Display impl, tests, and Phase 2+
pub mod alias;
pub mod const_prop;
pub mod copy_prop;
pub mod dce;
pub mod display;
pub mod heap;
pub mod invariants;
#[allow(dead_code)]
pub mod ir;
pub mod lower;
pub mod pointsto;
pub mod static_map;
pub mod type_facts;

#[allow(unused_imports)]
pub use ir::*;
pub use lower::lower_to_ssa;
pub use lower::lower_to_ssa_scoped_nop;
pub use lower::lower_to_ssa_with_params;

use crate::cfg::Cfg;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of SSA optimization passes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptimizeResult {
    /// Per-SSA-value constant lattice values.
    pub const_values: HashMap<SsaValue, const_prop::ConstLattice>,
    /// Type fact analysis results.
    pub type_facts: type_facts::TypeFactResult,
    /// Base-variable alias groups from copy propagation.
    pub alias_result: alias::BaseAliasResult,
    /// Points-to analysis: per-SSA-value abstract heap object sets.
    pub points_to: heap::PointsToResult,
    /// Module aliases from `require()` calls: SSA value → possible module names.
    /// Used to resolve dynamic dispatch like `lib.request()` where `lib = require("http")`.
    pub module_aliases: HashMap<SsaValue, smallvec::SmallVec<[String; 2]>>,
    /// Number of branches pruned by constant propagation.
    pub branches_pruned: usize,
    /// Number of copies eliminated.
    pub copies_eliminated: usize,
    /// Number of dead definitions removed.
    pub dead_defs_removed: usize,
}

/// Run all SSA optimization passes on a body.
///
/// Pipeline: const propagation → branch pruning → copy propagation → DCE → type facts.
pub fn optimize_ssa(body: &mut SsaBody, cfg: &Cfg, lang: Option<Lang>) -> OptimizeResult {
    // 1. Constant propagation (SCCP)
    let cp = const_prop::const_propagate(body);
    let branches_pruned = const_prop::apply_const_prop(body, &cp);

    // 2. Copy propagation
    let (copies_eliminated, copy_map) = copy_prop::copy_propagate(body, cfg);

    // 3. Alias analysis (uses copy_map before DCE removes dead defs)
    let alias_result = alias::compute_base_aliases(&copy_map, body);

    // 4. Dead code elimination
    let dead_defs_removed = dce::eliminate_dead_defs(body, cfg);

    // 5. Type fact analysis (uses const prop results + language for constructor inference)
    let type_facts = type_facts::analyze_types(body, cfg, &cp.values, lang);

    // 6. Points-to analysis (uses allocation site detection + SSA def-use)
    let points_to = heap::analyze_points_to(body, cfg, lang);

    // 7. Module alias analysis (require() tracking for JS/TS)
    let module_aliases = if matches!(lang, Some(Lang::JavaScript) | Some(Lang::TypeScript)) {
        const_prop::collect_module_aliases(body, &cp.values)
    } else {
        HashMap::new()
    };

    OptimizeResult {
        const_values: cp.values,
        type_facts,
        alias_result,
        points_to,
        module_aliases,
        branches_pruned,
        copies_eliminated,
        dead_defs_removed,
    }
}
