pub mod domain;
pub mod engine;
pub mod facts;
pub mod lattice;
pub mod symbol;
pub mod transfer;

use crate::cfg::{Cfg, FuncSummaries};
use crate::cfg_analysis::rules;
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use domain::ProductState;
use engine::MAX_TRACKED_VARS;
use facts::StateFinding;
use petgraph::graph::NodeIndex;
use symbol::SymbolInterner;
use transfer::DefaultTransfer;

/// Run state-model dataflow analysis on a single function's CFG.
///
/// Returns findings for use-after-close, double-close, resource leaks,
/// and unauthenticated access to sensitive sinks.
pub fn run_state_analysis(
    cfg: &Cfg,
    entry: NodeIndex,
    lang: Lang,
    _source_bytes: &[u8],
    func_summaries: &FuncSummaries,
    _global_summaries: Option<&GlobalSummaries>,
    enable_auth: bool,
) -> Vec<StateFinding> {
    let _span = tracing::debug_span!("run_state_analysis").entered();

    // 1. Build symbol interner from CFG
    //
    // Safety: SymbolInterner, ProductState, and DataflowResult are all
    // built fresh per call.  No resource state leaks across analyses.
    // Variables from unreachable functions may be interned but are never
    // set in ResourceDomainState (the forward engine only reaches nodes
    // connected from `entry`).
    let interner = SymbolInterner::from_cfg_scoped(cfg);

    // Guarded degradation: cap tracked variables
    if interner.len() > MAX_TRACKED_VARS {
        tracing::warn!(
            symbols = interner.len(),
            max = MAX_TRACKED_VARS,
            "state analysis: too many variables, capping tracking"
        );
        // Still run — the interner has all symbols, but transfer will only
        // track the first MAX_TRACKED_VARS due to HashMap insertion order.
        // This is conservative but safe.
    }

    // 2. Construct transfer function
    let resource_pairs = rules::resource_pairs(lang);
    let transfer = DefaultTransfer {
        lang,
        resource_pairs,
        interner: &interner,
    };

    // 3. Run forward dataflow engine
    let initial = ProductState::initial();
    let result = engine::run_forward(cfg, entry, &transfer, initial);

    // 4. Extract findings
    facts::extract_findings(&result, cfg, &interner, lang, func_summaries, enable_auth)
}
