use crate::abstract_interp::AbstractValue;
use crate::labels::Cap;
use crate::ssa::type_facts::TypeKind;
use serde::{Deserialize, Serialize};

/// Per-parameter taint transform describing how taint flows through a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SsaFuncSummary {
    /// Per-parameter flows to return value: (param_index, transform).
    pub param_to_return: Vec<(usize, TaintTransform)>,
    /// Per-parameter flows to internal sinks: (param_index, sink_caps).
    pub param_to_sink: Vec<(usize, Cap)>,
    /// Source caps introduced regardless of parameters (e.g., function reads env).
    pub source_caps: Cap,
    /// Per-parameter flows to specific internal sink argument positions:
    /// (caller_param_index, sink_arg_position, sink_caps).
    #[serde(default)]
    pub param_to_sink_param: Vec<(usize, usize, Cap)>,
    /// [STUB – future inter-procedural heap analysis] Parameter indices whose
    /// container identity flows to the return value (e.g., function returns
    /// the same container it received as input).
    #[serde(default)]
    pub param_container_to_return: Vec<usize>,
    /// [STUB – future inter-procedural heap analysis] (src_param, container_param)
    /// pairs: indicates that src_param's taint is stored into container_param's
    /// container contents.
    #[serde(default)]
    pub param_to_container_store: Vec<(usize, usize)>,
    /// Inferred return type of the function, when determinable from constructor
    /// calls or type annotations. Enables cross-file type-qualified resolution.
    #[serde(default)]
    pub return_type: Option<TypeKind>,
    /// Abstract domain fact for the return value (Phase 17 hardening).
    /// When present, callers can use this to seed the return SSA value's
    /// abstract state for cross-procedural interval/string analysis.
    #[serde(default)]
    pub return_abstract: Option<AbstractValue>,
    /// Internal source taint flows to a call of parameter N with these caps.
    /// Detects callback patterns like `fn apply(f: F) { let x = source(); f(x); }`
    /// where the function invokes a callback parameter with tainted data.
    #[serde(default)]
    pub source_to_callback: Vec<(usize, Cap)>,
    /// How receiver (`self`/`this`) taint flows to the return value.
    /// `None` when receiver taint does not reach the return.  Matches the
    /// semantics of `param_to_return`'s `TaintTransform` for positional params.
    #[serde(default)]
    pub receiver_to_return: Option<TaintTransform>,
    /// Caps that the receiver's taint reaches in internal sinks.
    /// Empty when the receiver is not used as a sink payload inside the body.
    #[serde(default)]
    pub receiver_to_sink: Cap,
}
