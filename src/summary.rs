use crate::labels::{Cap, DataLabel};
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
}

// ── Lookup map used by the taint engine ─────────────────────────────────

/// A merged view of all function summaries keyed by function name.
///
/// When multiple files define a function with the same unqualified name the
/// summaries are merged conservatively (union of all cap bits, any‑true for
/// booleans).  This is sound — we may over‑approximate but never miss a
/// real flow.  Future module‑path resolution will make this more precise.
pub type GlobalSummaries = HashMap<String, FuncSummary>;

/// Merge a set of per‑file summaries into a single `GlobalSummaries` map.
///
/// For name collisions the rule is *conservative union*: every cap bit that
/// any definition sets is kept, `propagates_taint` is OR‑ed, and
/// `tainted_sink_params` are unioned.
pub fn merge_summaries(per_file: impl IntoIterator<Item = FuncSummary>) -> GlobalSummaries {
    let mut map = GlobalSummaries::new();

    for fs in per_file {
        map.entry(fs.name.clone())
            .and_modify(|existing| {
                existing.source_caps |= fs.source_caps;
                existing.sanitizer_caps |= fs.sanitizer_caps;
                existing.sink_caps |= fs.sink_caps;
                existing.propagates_taint |= fs.propagates_taint;

                // union tainted_sink_params (deduplicated)
                for &idx in &fs.tainted_sink_params {
                    if !existing.tainted_sink_params.contains(&idx) {
                        existing.tainted_sink_params.push(idx);
                    }
                }

                // union callees
                for c in &fs.callees {
                    if !existing.callees.contains(c) {
                        existing.callees.push(c.clone());
                    }
                }
            })
            .or_insert(fs);
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(name: &str, src: u8, san: u8, sink: u8) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: "test.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: src,
            sanitizer_caps: san,
            sink_caps: sink,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        }
    }

    #[test]
    fn primary_label_priority() {
        // sink beats everything
        let s = make("f", 0xFF, 0xFF, 0x01);
        assert!(matches!(s.primary_label(), Some(DataLabel::Sink(_))));

        // source beats sanitizer
        let s = make("f", 0x01, 0x02, 0x00);
        assert!(matches!(s.primary_label(), Some(DataLabel::Source(_))));

        // sanitizer alone
        let s = make("f", 0x00, 0x04, 0x00);
        assert!(matches!(s.primary_label(), Some(DataLabel::Sanitizer(_))));

        // nothing
        let s = make("f", 0, 0, 0);
        assert!(s.primary_label().is_none());
    }

    #[test]
    fn merge_unions_conservatively() {
        let a = make("foo", 0x01, 0x00, 0x00);
        let b = FuncSummary {
            sink_caps: 0x04,
            propagates_taint: true,
            tainted_sink_params: vec![0],
            callees: vec!["bar".into()],
            ..make("foo", 0x00, 0x02, 0x00)
        };

        let merged = merge_summaries(vec![a, b]);
        let foo = merged.get("foo").unwrap();

        assert_eq!(foo.source_caps, 0x01);
        assert_eq!(foo.sanitizer_caps, 0x02);
        assert_eq!(foo.sink_caps, 0x04);
        assert!(foo.propagates_taint);
        assert_eq!(foo.tainted_sink_params, vec![0]);
        assert_eq!(foo.callees, vec!["bar".to_string()]);
    }

    #[test]
    fn is_interesting_detects_all_cases() {
        assert!(!make("f", 0, 0, 0).is_interesting());
        assert!(make("f", 1, 0, 0).is_interesting());
        assert!(make("f", 0, 1, 0).is_interesting());
        assert!(make("f", 0, 0, 1).is_interesting());

        let mut p = make("f", 0, 0, 0);
        p.propagates_taint = true;
        assert!(p.is_interesting());
    }
}
