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

/// Phase CF-4: maximum [`ReturnPathTransform`] entries retained per parameter.
///
/// Most functions have one or two return paths; eight is a generous bound
/// that still keeps per-summary memory O(1).  Beyond the cap, extraction
/// joins the overflow into a single Top-predicate entry so the caller-side
/// application always sees a bounded vector.
pub const MAX_RETURN_PATHS: usize = 8;

/// Phase CF-4: a single return-path entry in a per-parameter summary.
///
/// Per-return-path decomposition preserves callee-internal path splits that
/// the aggregate [`TaintTransform`] would erase.  Each entry records the
/// path predicate under which this return is reached, the behavioural
/// transform on that path, and (optionally) an abstract-domain contribution.
///
/// Callers carry their own path-state at the call site and apply only
/// entries whose predicate is consistent with the caller's validated set;
/// the remainder are skipped.  Applicable entries are joined to produce
/// the effective transform at the call site.
///
/// When a callee has a single return path, `param_return_paths` stays empty
/// and the caller falls back to `param_to_return`'s union view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnPathTransform {
    /// Behavioural kind on this path (Identity / StripBits / AddBits).
    pub transform: TaintTransform,
    /// Deterministic hash of the path-predicate gate at this return.
    ///
    /// `0` is reserved for "no predicate gate" — a return reached under
    /// no known predicate.  Two return blocks whose path predicates are
    /// observationally equivalent hash to the same value and are joined.
    pub path_predicate_hash: u64,
    /// `PredicateSummary::known_true` bits that must hold on every path
    /// into this return.  Encoded using [`crate::taint::domain::predicate_kind_bit`]:
    /// bit 0 = NullCheck, 1 = EmptyCheck, 2 = ErrorCheck.
    pub known_true: u8,
    /// `PredicateSummary::known_false` bits at this return (same encoding
    /// as [`Self::known_true`]).
    pub known_false: u8,
    /// Abstract contribution for this return path, when non-Top.
    ///
    /// Callers combine this with their own abstract fact on the call
    /// site's argument using `AbstractValue::meet` to recover bounds that
    /// survive a specific return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abstract_contribution: Option<AbstractValue>,
}

impl ReturnPathTransform {
    /// Dedup key combining the semantic fields of a path entry.  Two entries
    /// with the same `(path_predicate_hash, transform, known_true, known_false)`
    /// describe the same behaviour on paths gated by the same predicate and
    /// can collapse without losing information.  `abstract_contribution` is
    /// deliberately ignored — the dedup path joins the two entries'
    /// abstract facts rather than dropping one.
    pub fn dedup_key(&self) -> (u64, &TaintTransform, u8, u8) {
        (
            self.path_predicate_hash,
            &self.transform,
            self.known_true,
            self.known_false,
        )
    }
}

/// Phase CF-4: merge `incoming` into `existing`, deduping by
/// [`ReturnPathTransform::dedup_key`] and joining abstract contributions on
/// collision.  Caps the final vector at [`MAX_RETURN_PATHS`]; overflow is
/// conservatively joined into a single Top-predicate entry.
pub fn merge_return_paths(
    existing: &mut SmallVec<[ReturnPathTransform; 2]>,
    incoming: &[ReturnPathTransform],
) {
    for new_entry in incoming {
        let key = new_entry.dedup_key();
        if let Some(slot) = existing.iter_mut().find(|e| e.dedup_key() == key) {
            slot.abstract_contribution = match (
                slot.abstract_contribution.take(),
                &new_entry.abstract_contribution,
            ) {
                (Some(a), Some(b)) => Some(a.join(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            };
        } else {
            existing.push(new_entry.clone());
        }
    }
    if existing.len() > MAX_RETURN_PATHS {
        let mut joined = ReturnPathTransform {
            transform: TaintTransform::Identity,
            path_predicate_hash: 0,
            known_true: 0,
            known_false: 0,
            abstract_contribution: None,
        };
        let mut strip_bits = Cap::all();
        let mut add_bits = Cap::empty();
        let mut saw_add = false;
        let mut abs: Option<AbstractValue> = None;
        let mut known_true = u8::MAX;
        let mut known_false = u8::MAX;
        for e in existing.iter() {
            match &e.transform {
                TaintTransform::Identity => {
                    // Identity strips nothing; join intersects to empty.
                    strip_bits = Cap::empty();
                }
                TaintTransform::StripBits(bits) => strip_bits &= *bits,
                TaintTransform::AddBits(bits) => {
                    add_bits |= *bits;
                    saw_add = true;
                }
            }
            known_true &= e.known_true;
            known_false &= e.known_false;
            abs = match (abs, &e.abstract_contribution) {
                (None, None) => None,
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b.clone()),
                (Some(a), Some(b)) => Some(a.join(b)),
            };
        }
        joined.transform = if saw_add {
            TaintTransform::AddBits(add_bits)
        } else if strip_bits.is_empty() {
            TaintTransform::Identity
        } else {
            TaintTransform::StripBits(strip_bits)
        };
        joined.known_true = known_true;
        joined.known_false = known_false;
        joined.abstract_contribution = abs;
        existing.clear();
        existing.push(joined);
    }
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
    /// Phase CF-4: per-parameter return-path decomposition.
    ///
    /// When non-empty, supplies finer-grained per-path data than
    /// [`Self::param_to_return`].  Each parameter maps to up to
    /// [`MAX_RETURN_PATHS`] [`ReturnPathTransform`] entries, one per
    /// distinct path-predicate gate.  Callers consult their own predicate
    /// state at the call site and apply only entries whose predicate is
    /// consistent with the caller's validated set, joining the applicable
    /// set into the effective call-site transform.
    ///
    /// Empty when the callee has a single return path — the aggregate
    /// [`param_to_return`] is already precise — or when extraction
    /// could not derive per-return state (e.g. early-exit probes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_return_paths: Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)>,
}

/// Phase CF-4: union-merge two `param_return_paths` lists keyed by parameter
/// index.  Each parameter keeps its own deduped [`ReturnPathTransform`] list,
/// joining abstract contributions on collision and enforcing the
/// [`MAX_RETURN_PATHS`] cap.  Used by merge paths that combine summaries
/// across iterations or files (SSA summaries are currently last-writer-wins
/// in `GlobalSummaries`, but this helper is the entry point future union
/// paths should call so per-path semantics stay centralised).
pub fn union_param_return_paths(
    existing: &mut Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)>,
    incoming: &[(usize, SmallVec<[ReturnPathTransform; 2]>)],
) {
    for (idx, paths) in incoming {
        if let Some((_, slot)) = existing.iter_mut().find(|(i, _)| *i == *idx) {
            merge_return_paths(slot, paths);
        } else {
            let mut fresh: SmallVec<[ReturnPathTransform; 2]> = SmallVec::new();
            merge_return_paths(&mut fresh, paths);
            existing.push((*idx, fresh));
        }
    }
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
