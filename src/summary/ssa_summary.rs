use crate::labels::Cap;

/// Per-parameter taint transform describing how taint flows through a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintTransform {
    /// Parameter flows to return value unchanged.
    Identity,
    /// Parameter flows to return minus sanitizer bits.
    StripBits(Cap),
    /// Return value gains additional source bits regardless of input.
    AddBits(Cap),
}

/// Precise per-parameter SSA-derived function summary.
///
/// Produced by running SSA taint analysis with each parameter individually
/// seeded, then observing which caps survive to return/sink positions.
/// This is more precise than the legacy `FuncSummary` bitmask approach
/// because it can express per-parameter transforms (e.g., "param 0 flows
/// to return but loses HTML_ESCAPE bits").
#[derive(Debug, Clone)]
pub struct SsaFuncSummary {
    /// Per-parameter flows to return value: (param_index, transform).
    pub param_to_return: Vec<(usize, TaintTransform)>,
    /// Per-parameter flows to internal sinks: (param_index, sink_caps).
    pub param_to_sink: Vec<(usize, Cap)>,
    /// Source caps introduced regardless of parameters (e.g., function reads env).
    pub source_caps: Cap,
}
