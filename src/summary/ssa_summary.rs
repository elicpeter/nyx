use crate::abstract_interp::{AbstractTransfer, AbstractValue};
use crate::labels::Cap;
use crate::ssa::type_facts::TypeKind;
use crate::summary::SinkSite;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

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
    /// Per-parameter flows to internal sinks: each entry binds a parameter
    /// index to one or more [`SinkSite`]s inside this function's body.
    ///
    /// Phase 1 of primary sink-location attribution: carrying the callee's
    /// sink source-location through the summary lets cross-file findings
    /// attribute the finding to the actual dangerous instruction rather
    /// than to the call site.  Each `SinkSite` records the bits (`cap`) it
    /// contributes, so consumers deriving a coarse `Cap` union across all
    /// sites for a given parameter remain behavior-compatible.
    #[serde(default)]
    pub param_to_sink: Vec<(usize, SmallVec<[SinkSite; 1]>)>,
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
    /// Phase CF-3: per-parameter abstract-domain transfer channels.
    ///
    /// Each entry `(param_index, transfer)` describes how a caller-known
    /// abstract value at that parameter maps to the function's return
    /// abstract value.  At cross-file call sites the caller applies each
    /// transfer to the corresponding argument's abstract state and joins
    /// the results (then `meet`s with [`Self::return_abstract`]) to
    /// synthesise the return abstract value — recovering interval bounds
    /// and string prefixes that would otherwise be lost to the summary's
    /// Top-seeded baseline.
    ///
    /// Empty when no parameter carries useful abstract flow.  Individual
    /// entries are omitted when their transfer is "top" (no knowledge),
    /// so on-disk size grows only when the callee really does propagate
    /// abstract values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub abstract_transfer: Vec<(usize, AbstractTransfer)>,
}

impl SsaFuncSummary {
    /// Per-parameter union of [`Cap`] bits across every [`SinkSite`] recorded
    /// for that parameter.
    ///
    /// Returns one `(param_index, caps)` pair per distinct parameter, with
    /// `caps` being the bitwise OR of every site's own `cap`.  This is the
    /// backward-compatible view that pre-`SinkSite` consumers (resolver,
    /// taint engine) still rely on.
    pub fn param_to_sink_caps(&self) -> Vec<(usize, Cap)> {
        self.param_to_sink
            .iter()
            .map(|(idx, sites)| {
                let caps = sites.iter().fold(Cap::empty(), |acc, s| acc | s.cap);
                (*idx, caps)
            })
            .collect()
    }

    /// Total [`Cap`] bits reached across every parameter's recorded sink sites.
    pub fn total_param_sink_caps(&self) -> Cap {
        self.param_to_sink
            .iter()
            .flat_map(|(_, sites)| sites.iter())
            .fold(Cap::empty(), |acc, s| acc | s.cap)
    }
}
