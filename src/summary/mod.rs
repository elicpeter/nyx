use crate::labels::{Cap, DataLabel};
use crate::symbol::{FuncKey, Lang, normalize_namespace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serialisable summary of a single function's taint behaviour.
///
/// One of these is produced per function during **pass 1** of a scan and
/// persisted to the `function_summaries` SQLite table.  During **pass 2** the
/// full set of summaries across every file is loaded into memory so the taint
/// engine can resolve cross‑file calls.
///
/// Design notes
/// ────────────
/// * **All three cap fields are independent.**  A function can simultaneously
///   act as a source (introduces fresh taint), a sanitizer (cleans certain
///   bits), and a sink (passes tainted data to a dangerous operation).
///   The old code picked a single `DataLabel` which lost information.
///
/// * **`propagates_taint`** captures pass‑through behaviour: if an input
///   parameter is tainted, does the return value carry that taint?  This is
///   essential for chains like `let y = transform(tainted_x); sink(y);`.
///
/// * **`callees`** are recorded for future call‑graph construction
///   (topological analysis, approach 2) but are not used in pass‑1/pass‑2
///   taint resolution yet.
///
/// * **`tainted_sink_params`** marks which parameter *positions* flow to
///   internal sinks.  Today the taint engine treats the whole call as a
///   single "tainted or not" question; this field future‑proofs the summary
///   for per‑argument precision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncSummary {
    /// Function name as it appears in the source (`my_func`, not the full path).
    pub name: String,

    /// Absolute path of the file that defines this function.
    pub file_path: String,

    /// Language slug (`"rust"`, `"javascript"`, …).
    pub lang: String,

    // ── Signature information ────────────────────────────────────────────
    /// Total number of parameters (including `self`/`&self` for methods).
    pub param_count: usize,

    /// Parameter names in declaration order.
    pub param_names: Vec<String>,

    // ── Taint behaviour ──────────────────────────────────────────────────
    // Stored as raw `u8` so serde doesn't need to know about `bitflags`.
    /// Caps this function **introduces** — i.e. the return value carries
    /// freshly‑tainted data even if no argument was tainted.
    pub source_caps: u8,

    /// Caps this function **cleans** — passing tainted data through this
    /// function strips the corresponding bits.
    pub sanitizer_caps: u8,

    /// Caps this function **consumes unsafely** — calling it with tainted
    /// arguments that still carry these bits is a finding.
    pub sink_caps: u8,

    /// `true` when taint on *any* input parameter can flow through to the
    /// return value.  Conservative: set to `true` if *any* code path
    /// propagates an argument to the return expression.
    pub propagates_taint: bool,

    /// Indices of parameters that flow to internal sinks (0‑based).
    pub tainted_sink_params: Vec<usize>,

    /// Names of functions/methods/macros called inside this function body.
    /// Stored for future call‑graph / topological‑sort analysis.
    pub callees: Vec<String>,
}

// ── Cap conversion helpers ──────────────────────────────────────────────

impl FuncSummary {
    #[inline]
    pub fn source_caps(&self) -> Cap {
        Cap::from_bits_truncate(self.source_caps)
    }

    #[inline]
    pub fn sanitizer_caps(&self) -> Cap {
        Cap::from_bits_truncate(self.sanitizer_caps)
    }

    #[inline]
    pub fn sink_caps(&self) -> Cap {
        Cap::from_bits_truncate(self.sink_caps)
    }

    /// Collapse the three independent cap fields back into the single
    /// `DataLabel` that the current taint engine expects.
    ///
    /// Priority: **Sink > Source > Sanitizer**.  Sinks first because
    /// missing a dangerous call‑site is worse than a false‑positive on a
    /// source.  Sources beat sanitizers because an un‑tracked source is
    /// a missed vulnerability, while an un‑tracked sanitizer only causes
    /// false positives.
    #[allow(dead_code)]
    pub fn primary_label(&self) -> Option<DataLabel> {
        let sink = self.sink_caps();
        let src = self.source_caps();
        let san = self.sanitizer_caps();

        if !sink.is_empty() {
            Some(DataLabel::Sink(sink))
        } else if !src.is_empty() {
            Some(DataLabel::Source(src))
        } else if !san.is_empty() {
            Some(DataLabel::Sanitizer(san))
        } else {
            None
        }
    }

    /// Returns `true` when this function has **any** observable taint
    /// effect — it is a source, sanitizer, sink, or propagates taint.
    #[allow(dead_code)]
    pub fn is_interesting(&self) -> bool {
        self.source_caps != 0
            || self.sanitizer_caps != 0
            || self.sink_caps != 0
            || self.propagates_taint
    }

    /// Build a [`FuncKey`] from this summary, normalizing the namespace
    /// relative to `scan_root`.
    pub fn func_key(&self, scan_root: Option<&str>) -> FuncKey {
        FuncKey {
            lang: Lang::from_slug(&self.lang).unwrap_or(Lang::Rust),
            namespace: normalize_namespace(&self.file_path, scan_root),
            name: self.name.clone(),
            arity: Some(self.param_count),
        }
    }
}

// ── Callee resolution ────────────────────────────────────────────────────

/// Result of resolving a bare callee name to a [`FuncKey`].
///
/// Three-valued: the call graph builder and taint engine need to distinguish
/// "no candidates at all" from "multiple candidates, can't pick one".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalleeResolution {
    /// Exactly one candidate matched.
    Resolved(FuncKey),
    /// No candidates found at all.
    NotFound,
    /// Multiple candidates — ambiguous, cannot pick one.
    Ambiguous(Vec<FuncKey>),
}

// ── Lookup map used by the taint engine ─────────────────────────────────

/// A merged view of all function summaries keyed by qualified [`FuncKey`].
///
/// Functions are partitioned by language + namespace + name + arity.  Two
/// functions with the same bare name but different languages or namespaces
/// are stored separately — no implicit cross-language merging occurs.
///
/// A secondary index `(Lang, name)` supports fast lookup by language + name
/// for same-language resolution in the taint engine.
#[derive(Default)]
pub struct GlobalSummaries {
    by_key: HashMap<FuncKey, FuncSummary>,
    by_lang_name: HashMap<(Lang, String), Vec<FuncKey>>,
}

impl GlobalSummaries {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or merge a summary.  If an exact `FuncKey` match exists,
    /// merge conservatively (OR caps/booleans, union params/callees).
    pub fn insert(&mut self, key: FuncKey, summary: FuncSummary) {
        let lang = key.lang;
        let name = key.name.clone();

        self.by_key
            .entry(key.clone())
            .and_modify(|existing| {
                existing.source_caps |= summary.source_caps;
                existing.sanitizer_caps |= summary.sanitizer_caps;
                existing.sink_caps |= summary.sink_caps;
                existing.propagates_taint |= summary.propagates_taint;
                for &idx in &summary.tainted_sink_params {
                    if !existing.tainted_sink_params.contains(&idx) {
                        existing.tainted_sink_params.push(idx);
                    }
                }
                for c in &summary.callees {
                    if !existing.callees.contains(c) {
                        existing.callees.push(c.clone());
                    }
                }
            })
            .or_insert(summary);

        let keys = self.by_lang_name.entry((lang, name)).or_default();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    /// Exact lookup by fully-qualified key.
    pub fn get(&self, key: &FuncKey) -> Option<&FuncSummary> {
        self.by_key.get(key)
    }

    /// All same-language matches for a bare function name.
    pub fn lookup_same_lang(&self, lang: Lang, name: &str) -> Vec<(&FuncKey, &FuncSummary)> {
        self.by_lang_name
            .get(&(lang, name.to_string()))
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.by_key.get(k).map(|v| (k, v)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Merge another `GlobalSummaries` into this one (for parallel fold/reduce).
    pub fn merge(&mut self, other: GlobalSummaries) {
        for (key, summary) in other.by_key {
            self.insert(key, summary);
        }
    }

    #[allow(dead_code)] // used by tests and future call-graph consumers
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Iterate over all (key, summary) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&FuncKey, &FuncSummary)> {
        self.by_key.iter()
    }

    /// Resolve a bare (already-normalized) callee name to a [`FuncKey`].
    ///
    /// Resolution order:
    /// 1. Collect all same-language candidates matching the name.
    /// 2. If `arity_hint` is `Some`, filter candidates by matching arity.
    /// 3. If exactly one candidate → [`CalleeResolution::Resolved`].
    /// 4. If multiple, filter by `caller_namespace`; if exactly one → `Resolved`.
    /// 5. If still multiple → [`CalleeResolution::Ambiguous`].
    /// 6. If zero candidates → [`CalleeResolution::NotFound`].
    pub fn resolve_callee_key(
        &self,
        callee: &str,
        caller_lang: Lang,
        caller_namespace: &str,
        arity_hint: Option<usize>,
    ) -> CalleeResolution {
        let candidates = self.lookup_same_lang(caller_lang, callee);
        if candidates.is_empty() {
            return CalleeResolution::NotFound;
        }

        // Apply arity filter if hint provided.
        let filtered: Vec<&FuncKey> = if let Some(arity) = arity_hint {
            candidates
                .iter()
                .filter(|(k, _)| k.arity == Some(arity))
                .map(|(k, _)| *k)
                .collect()
        } else {
            candidates.iter().map(|(k, _)| *k).collect()
        };

        match filtered.len() {
            0 => CalleeResolution::NotFound,
            1 => CalleeResolution::Resolved(filtered[0].clone()),
            _ => {
                // Namespace disambiguation: prefer same-namespace match.
                let same_ns: Vec<&FuncKey> = filtered
                    .iter()
                    .filter(|k| k.namespace == caller_namespace)
                    .copied()
                    .collect();
                match same_ns.len() {
                    1 => CalleeResolution::Resolved(same_ns[0].clone()),
                    0 => CalleeResolution::Ambiguous(filtered.into_iter().cloned().collect()),
                    _ => CalleeResolution::Ambiguous(same_ns.into_iter().cloned().collect()),
                }
            }
        }
    }
}

impl std::fmt::Debug for GlobalSummaries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalSummaries")
            .field("len", &self.by_key.len())
            .finish()
    }
}

/// Merge a set of per‑file summaries into a single `GlobalSummaries` map.
///
/// Merging only happens for exact `FuncKey` matches (same lang + namespace +
/// name + arity).  Functions with the same bare name but different languages
/// or namespaces are stored separately.
pub fn merge_summaries(
    per_file: impl IntoIterator<Item = FuncSummary>,
    scan_root: Option<&str>,
) -> GlobalSummaries {
    let mut map = GlobalSummaries::new();

    for fs in per_file {
        let key = fs.func_key(scan_root);
        map.insert(key, fs);
    }

    map
}

#[cfg(test)]
mod tests;
