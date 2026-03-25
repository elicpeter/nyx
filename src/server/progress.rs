use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// Lock-free progress reporting from rayon workers during a scan.
#[derive(Debug)]
pub struct ScanProgress {
    /// 0=queued, 1=discovering, 2=parsing, 3=analyzing, 4=complete
    stage: AtomicU8,
    files_discovered: AtomicU64,
    files_parsed: AtomicU64,
    files_analyzed: AtomicU64,
    current_file: Mutex<String>,
    started_at: Instant,
    walk_ms: AtomicU64,
    pass1_ms: AtomicU64,
    call_graph_ms: AtomicU64,
    pass2_ms: AtomicU64,
    post_process_ms: AtomicU64,
    languages: Mutex<HashMap<String, u64>>,
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            stage: AtomicU8::new(0),
            files_discovered: AtomicU64::new(0),
            files_parsed: AtomicU64::new(0),
            files_analyzed: AtomicU64::new(0),
            current_file: Mutex::new(String::new()),
            started_at: Instant::now(),
            walk_ms: AtomicU64::new(0),
            pass1_ms: AtomicU64::new(0),
            call_graph_ms: AtomicU64::new(0),
            pass2_ms: AtomicU64::new(0),
            post_process_ms: AtomicU64::new(0),
            languages: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_stage(&self, stage: u8) {
        self.stage.store(stage, Relaxed);
    }

    pub fn set_files_discovered(&self, count: u64) {
        self.files_discovered.store(count, Relaxed);
    }

    pub fn inc_parsed(&self, n: u64) {
        self.files_parsed.fetch_add(n, Relaxed);
    }

    pub fn inc_analyzed(&self, n: u64) {
        self.files_analyzed.fetch_add(n, Relaxed);
    }

    pub fn set_current_file(&self, path: &str) {
        if let Ok(mut f) = self.current_file.try_lock() {
            f.clear();
            f.push_str(path);
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    pub fn record_walk_ms(&self, ms: u64) {
        self.walk_ms.store(ms, Relaxed);
    }

    pub fn record_pass1_ms(&self, ms: u64) {
        self.pass1_ms.store(ms, Relaxed);
    }

    pub fn record_call_graph_ms(&self, ms: u64) {
        self.call_graph_ms.store(ms, Relaxed);
    }

    pub fn record_pass2_ms(&self, ms: u64) {
        self.pass2_ms.store(ms, Relaxed);
    }

    pub fn record_post_process_ms(&self, ms: u64) {
        self.post_process_ms.store(ms, Relaxed);
    }

    pub fn record_language(&self, lang: &str) {
        if let Ok(mut langs) = self.languages.try_lock() {
            *langs.entry(lang.to_string()).or_insert(0) += 1;
        }
    }

    pub fn snapshot(&self) -> ScanProgressSnapshot {
        let stage_num = self.stage.load(Relaxed);
        let stage = match stage_num {
            0 => "queued",
            1 => "discovering",
            2 => "parsing",
            3 => "analyzing",
            4 => "complete",
            _ => "unknown",
        }
        .to_string();

        let current_file = self
            .current_file
            .try_lock()
            .map(|f| f.clone())
            .unwrap_or_default();

        let languages = self
            .languages
            .try_lock()
            .map(|l| l.clone())
            .unwrap_or_default();

        ScanProgressSnapshot {
            stage,
            files_discovered: self.files_discovered.load(Relaxed),
            files_parsed: self.files_parsed.load(Relaxed),
            files_analyzed: self.files_analyzed.load(Relaxed),
            current_file,
            elapsed_ms: self.elapsed_ms(),
            timing: TimingBreakdown {
                walk_ms: self.walk_ms.load(Relaxed),
                pass1_ms: self.pass1_ms.load(Relaxed),
                call_graph_ms: self.call_graph_ms.load(Relaxed),
                pass2_ms: self.pass2_ms.load(Relaxed),
                post_process_ms: self.post_process_ms.load(Relaxed),
            },
            languages,
        }
    }
}

/// Serializable snapshot of scan progress.
#[derive(Debug, Clone, Serialize)]
pub struct ScanProgressSnapshot {
    pub stage: String,
    pub files_discovered: u64,
    pub files_parsed: u64,
    pub files_analyzed: u64,
    pub current_file: String,
    pub elapsed_ms: u64,
    pub timing: TimingBreakdown,
    pub languages: HashMap<String, u64>,
}

/// Timing breakdown for each scan phase.
#[derive(Debug, Clone, Serialize, serde::Deserialize, Default)]
pub struct TimingBreakdown {
    pub walk_ms: u64,
    pub pass1_ms: u64,
    pub call_graph_ms: u64,
    pub pass2_ms: u64,
    pub post_process_ms: u64,
}

/// Engine-level metrics collected during a scan.
#[derive(Debug)]
pub struct ScanMetrics {
    pub cfg_nodes: AtomicU64,
    pub call_edges: AtomicU64,
    pub functions_analyzed: AtomicU64,
    pub summaries_reused: AtomicU64,
    pub unresolved_calls: AtomicU64,
}

impl Default for ScanMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanMetrics {
    pub fn new() -> Self {
        Self {
            cfg_nodes: AtomicU64::new(0),
            call_edges: AtomicU64::new(0),
            functions_analyzed: AtomicU64::new(0),
            summaries_reused: AtomicU64::new(0),
            unresolved_calls: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> ScanMetricsSnapshot {
        ScanMetricsSnapshot {
            cfg_nodes: self.cfg_nodes.load(Relaxed),
            call_edges: self.call_edges.load(Relaxed),
            functions_analyzed: self.functions_analyzed.load(Relaxed),
            summaries_reused: self.summaries_reused.load(Relaxed),
            unresolved_calls: self.unresolved_calls.load(Relaxed),
        }
    }
}

/// Serializable snapshot of engine metrics.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanMetricsSnapshot {
    pub cfg_nodes: u64,
    pub call_edges: u64,
    pub functions_analyzed: u64,
    pub summaries_reused: u64,
    pub unresolved_calls: u64,
}
