use crate::symbol::{FuncKey, Lang};

/// Identifies a specific call site within a caller function.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CallSiteKey {
    pub caller_lang: Lang,
    /// Project-relative file path of the caller.
    pub caller_namespace: String,
    /// Enclosing function name at the call site.
    pub caller_func: String,
    /// The identifier at the call site (callee name as written).
    pub callee_symbol: String,
    /// Per-function call ordinal (0-based).  `0` acts as a wildcard during
    /// matching (matches any ordinal).
    pub ordinal: u32,
}

/// An explicit cross-language bridge edge.
///
/// Connects a call site in one language to a function definition in another.
/// Without an `InteropEdge`, cross-language resolution is never attempted —
/// this prevents false positives from name collisions across languages.
#[derive(Clone, Debug)]
pub struct InteropEdge {
    pub from: CallSiteKey,
    pub to: FuncKey,
    /// Maps caller argument positions to callee parameter positions.
    #[allow(dead_code)] // used for future per-argument taint mapping
    pub arg_map: Vec<(usize, usize)>,
    /// Whether the callee's return value carries taint.
    #[allow(dead_code)] // used for future interop return taint control
    pub ret_taints: bool,
}
