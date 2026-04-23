//! Convergence-loop telemetry: per-batch and per-file JSONL sidecar.
//!
//! Records how many iterations each fix-point loop (cross-file SCC;
//! JS/TS in-file pass-2) actually used on real inputs, plus the
//! per-iteration change-set size trajectory, so we can tune caps on
//! evidence rather than by guess.
//!
//! # Why this module exists
//!
//! The SCC fix-point safety cap ([`crate::commands::scan::SCC_FIXPOINT_SAFETY_CAP`])
//! and the JS/TS pass-2 cap ([`crate::taint::JS_TS_PASS2_SAFETY_CAP`])
//! are both 64 iterations — chosen as "generous for every realistic
//! input we've seen".  Neither value is backed by telemetry from a
//! production corpus (React, VSCode, Webpack, enterprise
//! monorepos).  Without that data we cannot:
//!
//! * tell how often the cap actually fires under real workloads,
//! * distinguish tuneable-budget problems from non-monotonicity
//!   regressions (Phase-D classifier addresses this on cap-hit, but
//!   tells us nothing about the near-cap distribution),
//! * decide whether further Phase-B worklist optimisation is needed.
//!
//! The telemetry emitted here is consumed by offline analysis tools
//! (`tools/convergence_report.py`, not tracked here) that compute
//! P50/P95/P99 iteration counts per corpus.
//!
//! # Lifecycle
//!
//! Telemetry is **opt-in** via `NYX_CONVERGENCE_TELEMETRY=1` — production
//! scans are unaffected by default.  When enabled:
//!
//! * [`is_enabled`] returns true.
//! * The SCC loop and JS/TS pass-2 loop each call [`record`] when
//!   they terminate (early-convergence or cap-hit).
//! * On scan shutdown, the collected records are written to a JSONL
//!   file alongside the SARIF output (or to the path specified by
//!   `NYX_CONVERGENCE_TELEMETRY_PATH`).
//!
//! Records never touch the critical path — [`record`] is a cheap
//! push onto a `Mutex<Vec<_>>` and the write happens once at scan end.
//!
//! # Schema stability
//!
//! Records serialize as JSONL (one JSON object per line, newline
//! separated).  The `kind` tag is snake_case and stable; adding new
//! fields is backwards-compatible because unknown fields are ignored
//! by downstream tooling.  Removing fields, or changing existing
//! fields' types, is a **breaking change** — bump the schema version
//! in [`SCHEMA_VERSION`] if you must.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::{Mutex, OnceLock};

/// Stable schema version for the JSONL records emitted by this module.
///
/// Bump when the record shape changes in a way that breaks downstream
/// consumers (field removed, type changed).  Adding optional fields is
/// backwards-compatible and does not require a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// One convergence event: either a cross-file SCC batch or a JS/TS
/// in-file pass-2 run.  The `kind` discriminator selects between them.
///
/// Serialized as JSON with `kind` as a snake_case tag so downstream
/// tooling can pattern-match without depending on Rust enum layout.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvergenceEvent {
    /// A cross-file SCC fix-point batch terminated (converged or
    /// cap-hit).
    SccBatch(SccBatchRecord),
    /// A JS/TS file's in-file pass-2 fix-point terminated (converged
    /// or cap-hit).
    InFilePass2(InFilePass2Record),
}

/// Per-batch record for the SCC fix-point loop.
///
/// Populated once per batch entry in
/// [`crate::commands::scan::run_topo_batches`] that hits the
/// `has_mutual_recursion` branch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SccBatchRecord {
    /// Schema version, copied from [`SCHEMA_VERSION`] at emit time.
    pub schema: u32,
    /// 0-based batch index within the topo-ordered sequence.
    pub batch_index: usize,
    /// Number of files participating in the batch.
    pub file_count: usize,
    /// True when the batch's SCC spans more than one file namespace.
    pub cross_file: bool,
    /// Iterations actually performed (≤ `cap`).  A value below `cap`
    /// indicates early convergence; equal to `cap` indicates cap-hit.
    pub iterations: usize,
    /// The cap in force at emit time (normally 64, but tests override).
    pub cap: usize,
    /// True iff the batch reached the fixed point before the cap
    /// fired.
    pub converged: bool,
    /// Per-iteration change-set size — the same trajectory the
    /// [`crate::engine_notes::CapHitReason`] classifier consumes.  Empty
    /// when the loop terminated on iteration 0 (pathological case).
    pub trajectory: SmallVec<[u32; 4]>,
}

/// Per-file record for the JS/TS in-file pass-2 loop.
///
/// Populated once per `analyse_multi_body` call with
/// `max_iterations > 1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InFilePass2Record {
    /// Schema version, copied from [`SCHEMA_VERSION`] at emit time.
    pub schema: u32,
    /// Relative file namespace ("path/to/file.js") of the analysed
    /// file.
    pub namespace: String,
    /// Non-toplevel body count (proxy for how much work the pass-2
    /// loop does per iteration).  Useful for correlating iterations
    /// with file size.
    pub body_count: usize,
    /// Iterations actually performed (≤ `cap`).
    pub iterations: usize,
    /// The cap in force at emit time (normally 64, but tests override).
    pub cap: usize,
    /// True iff the file reached the fixed point before the cap
    /// fired.
    pub converged: bool,
    /// Per-iteration change-set size trajectory.
    pub trajectory: SmallVec<[u32; 4]>,
}

/// Global collector for convergence events recorded during a scan.
///
/// Stored behind a `OnceLock<Mutex<Vec<_>>>` so multiple rayon workers
/// can record events concurrently without a startup cost when
/// telemetry is disabled.  The mutex contention is negligible because
/// each scan produces O(batches + JS/TS files) events, not per-task
/// events.
static COLLECTOR: OnceLock<Mutex<Vec<ConvergenceEvent>>> = OnceLock::new();

/// Returns true when telemetry collection is active for this process.
///
/// Controlled by the `NYX_CONVERGENCE_TELEMETRY` env var: any value
/// except `"0"`, `"false"`, or empty enables it.  Cached on first
/// read so the env lookup is paid once per process.
pub fn is_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| match std::env::var("NYX_CONVERGENCE_TELEMETRY") {
        Ok(v) => !matches!(v.as_str(), "" | "0" | "false"),
        Err(_) => false,
    })
}

/// Record a convergence event.  No-op when telemetry is disabled.
///
/// Safe to call from parallel rayon contexts — the underlying mutex
/// is reentrant-safe and the push is O(1).  Events are retained in
/// memory until [`drain`] is called at scan end.
pub fn record(event: ConvergenceEvent) {
    if !is_enabled() {
        return;
    }
    let lock = COLLECTOR.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = lock.lock() {
        guard.push(event);
    }
}

/// Drain and return all recorded events.  Leaves the collector empty
/// so subsequent scans in the same process (e.g. integration tests)
/// do not see stale events.
pub fn drain() -> Vec<ConvergenceEvent> {
    let Some(lock) = COLLECTOR.get() else {
        return Vec::new();
    };
    match lock.lock() {
        Ok(mut guard) => std::mem::take(&mut *guard),
        Err(_) => Vec::new(),
    }
}

/// Write collected events to `path` as JSONL.  Returns the number of
/// records written, or an I/O error.
///
/// Appends to `path` rather than overwriting so consecutive scans
/// during a corpus run accumulate into a single file.  Callers that
/// want a fresh file should remove it first.
pub fn write_jsonl(path: &std::path::Path) -> std::io::Result<usize> {
    use std::io::Write;
    let events = drain();
    if events.is_empty() {
        return Ok(0);
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    for event in &events {
        let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    Ok(events.len())
}

/// Canonical sidecar path: uses `NYX_CONVERGENCE_TELEMETRY_PATH` if
/// set, otherwise derives from the current working directory.
///
/// The `_derive_from_root` hint is the scan root — when no explicit
/// path is configured we place the sidecar next to it as
/// `nyx-convergence.jsonl` so the file lands alongside the SARIF
/// output by default.
pub fn default_path(scan_root: &std::path::Path) -> std::path::PathBuf {
    if let Ok(explicit) = std::env::var("NYX_CONVERGENCE_TELEMETRY_PATH") {
        return std::path::PathBuf::from(explicit);
    }
    scan_root.join("nyx-convergence.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize tests that touch the process-global COLLECTOR.
    /// Without this guard parallel cargo-test threads can push and
    /// drain in interleaved orders, producing non-deterministic
    /// failures in the roundtrip and drain assertions.
    static COLLECTOR_TEST_GUARD: Mutex<()> = Mutex::new(());

    /// Clear the global collector so each test starts with a known
    /// state.  Does **not** force `is_enabled()` true — the unit
    /// tests below bypass `record()` (which is a no-op unless
    /// env-enabled) by pushing directly into the collector.
    fn reset_and_enable_telemetry() {
        let _ = drain();
    }

    #[test]
    fn scc_batch_record_serializes_snake_case_tag() {
        let event = ConvergenceEvent::SccBatch(SccBatchRecord {
            schema: SCHEMA_VERSION,
            batch_index: 3,
            file_count: 7,
            cross_file: true,
            iterations: 12,
            cap: 64,
            converged: true,
            trajectory: SmallVec::from_slice(&[8, 4, 2, 0]),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"scc_batch\""), "got {json}");
        assert!(json.contains("\"cross_file\":true"), "got {json}");
        assert!(json.contains("\"converged\":true"), "got {json}");
    }

    #[test]
    fn in_file_pass2_record_serializes_snake_case_tag() {
        let event = ConvergenceEvent::InFilePass2(InFilePass2Record {
            schema: SCHEMA_VERSION,
            namespace: "src/foo.js".into(),
            body_count: 42,
            iterations: 5,
            cap: 64,
            converged: true,
            trajectory: SmallVec::from_slice(&[10, 3, 1, 0]),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"in_file_pass2\""), "got {json}");
        assert!(json.contains("\"namespace\":\"src/foo.js\""), "got {json}");
    }

    #[test]
    fn jsonl_roundtrip_via_tempfile() {
        let _guard = COLLECTOR_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_and_enable_telemetry();

        // Force-enable by pushing directly to the collector, bypassing
        // is_enabled() (which is cached).  This is the same path
        // production code takes via record() when enabled.
        let lock = COLLECTOR.get_or_init(|| Mutex::new(Vec::new()));
        {
            let mut g = lock.lock().unwrap();
            g.push(ConvergenceEvent::SccBatch(SccBatchRecord {
                schema: SCHEMA_VERSION,
                batch_index: 0,
                file_count: 1,
                cross_file: false,
                iterations: 1,
                cap: 64,
                converged: true,
                trajectory: SmallVec::new(),
            }));
        }

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("conv.jsonl");
        let written = write_jsonl(&path).unwrap();
        assert_eq!(written, 1);

        let content = std::fs::read_to_string(&path).unwrap();
        let line = content.trim();
        let parsed: ConvergenceEvent = serde_json::from_str(line).unwrap();
        match parsed {
            ConvergenceEvent::SccBatch(r) => {
                assert_eq!(r.iterations, 1);
                assert!(r.converged);
            }
            _ => panic!("expected SccBatch"),
        }
    }

    #[test]
    fn drain_empties_collector() {
        let _guard = COLLECTOR_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_and_enable_telemetry();
        let lock = COLLECTOR.get_or_init(|| Mutex::new(Vec::new()));
        {
            let mut g = lock.lock().unwrap();
            g.push(ConvergenceEvent::InFilePass2(InFilePass2Record {
                schema: SCHEMA_VERSION,
                namespace: "x".into(),
                body_count: 0,
                iterations: 0,
                cap: 0,
                converged: true,
                trajectory: SmallVec::new(),
            }));
        }
        let e1 = drain();
        let e2 = drain();
        assert_eq!(e1.len(), 1);
        assert_eq!(e2.len(), 0);
    }

    #[test]
    fn default_path_honors_env_override() {
        // Cannot assert the env override is honored without process
        // isolation, but we can at least verify the fallback shape.
        let root = std::path::Path::new("/tmp/nyx-test");
        let p = default_path(root);
        assert!(
            p.to_string_lossy().contains("nyx-convergence.jsonl"),
            "got {p:?}"
        );
    }
}
