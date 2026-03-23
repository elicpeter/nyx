use crate::commands::scan::{self, Diag};
use crate::server::app::ServerEvent;
use crate::utils::config::Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Status of a scan job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

/// A single scan job with its state and results.
#[derive(Debug, Clone)]
pub struct ScanJob {
    pub id: String,
    pub status: JobStatus,
    pub scan_root: PathBuf,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_secs: Option<f64>,
    pub findings: Option<Vec<Diag>>,
    pub error: Option<String>,
}

/// Manages scan jobs with single-scan policy.
pub struct JobManager {
    jobs: Mutex<HashMap<String, ScanJob>>,
    /// Insertion-order tracking for listing.
    job_order: Mutex<Vec<String>>,
    active_job_id: Mutex<Option<String>>,
    max_jobs: usize,
}

impl std::fmt::Debug for JobManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobManager")
            .field("max_jobs", &self.max_jobs)
            .finish()
    }
}

impl JobManager {
    pub fn new(max_jobs: usize) -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            job_order: Mutex::new(Vec::new()),
            active_job_id: Mutex::new(None),
            max_jobs,
        }
    }

    /// Start a new scan. Returns Err if a scan is already running.
    pub fn start_scan(
        self: &Arc<Self>,
        scan_root: PathBuf,
        config: Config,
        event_tx: broadcast::Sender<ServerEvent>,
    ) -> Result<String, &'static str> {
        let mut active = self.active_job_id.lock().unwrap();
        if active.is_some() {
            return Err("A scan is already running");
        }

        let job_id = Uuid::new_v4().to_string();
        let job = ScanJob {
            id: job_id.clone(),
            status: JobStatus::Running,
            scan_root: scan_root.clone(),
            started_at: Some(chrono::Utc::now()),
            finished_at: None,
            duration_secs: None,
            findings: None,
            error: None,
        };

        {
            let mut jobs = self.jobs.lock().unwrap();
            let mut order = self.job_order.lock().unwrap();

            // Evict oldest if at capacity.
            while order.len() >= self.max_jobs {
                if let Some(oldest_id) = order.first().cloned() {
                    // Don't evict the active job.
                    if Some(&oldest_id) == active.as_ref() {
                        break;
                    }
                    jobs.remove(&oldest_id);
                    order.remove(0);
                }
            }

            jobs.insert(job_id.clone(), job);
            order.push(job_id.clone());
        }

        *active = Some(job_id.clone());

        let _ = event_tx.send(ServerEvent::ScanStarted {
            job_id: job_id.clone(),
        });

        // Spawn a std::thread for the scan (it uses rayon internally).
        let manager = Arc::clone(self);
        let jid = job_id.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            let result = scan::scan_filesystem(&scan_root, &config, false);
            let elapsed = start.elapsed().as_secs_f64();

            let mut jobs = manager.jobs.lock().unwrap();
            if let Some(job) = jobs.get_mut(&jid) {
                job.finished_at = Some(chrono::Utc::now());
                job.duration_secs = Some(elapsed);
                match result {
                    Ok(mut diags) => {
                        scan::post_process_diags(&mut diags, &config);
                        job.status = JobStatus::Completed;
                        job.findings = Some(diags);
                        let _ = event_tx.send(ServerEvent::ScanCompleted {
                            job_id: jid.clone(),
                        });
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        job.status = JobStatus::Failed;
                        job.error = Some(err_str.clone());
                        let _ = event_tx.send(ServerEvent::ScanFailed {
                            job_id: jid.clone(),
                            error: err_str,
                        });
                    }
                }
            }
            drop(jobs);

            let mut active = manager.active_job_id.lock().unwrap();
            if active.as_deref() == Some(&jid) {
                *active = None;
            }
        });

        Ok(job_id)
    }

    /// Get a specific job.
    pub fn get_job(&self, id: &str) -> Option<ScanJob> {
        self.jobs.lock().unwrap().get(id).cloned()
    }

    /// List all jobs, most recent first.
    pub fn list_jobs(&self) -> Vec<ScanJob> {
        let jobs = self.jobs.lock().unwrap();
        let order = self.job_order.lock().unwrap();
        order
            .iter()
            .rev()
            .filter_map(|id| jobs.get(id).cloned())
            .collect()
    }

    /// Get the currently active (running) job.
    pub fn active_job(&self) -> Option<ScanJob> {
        let active = self.active_job_id.lock().unwrap();
        active
            .as_ref()
            .and_then(|id| self.jobs.lock().unwrap().get(id).cloned())
    }

    /// Get the latest completed job.
    pub fn get_latest_completed(&self) -> Option<ScanJob> {
        let jobs = self.jobs.lock().unwrap();
        let order = self.job_order.lock().unwrap();
        order
            .iter()
            .rev()
            .filter_map(|id| jobs.get(id))
            .find(|j| j.status == JobStatus::Completed)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::default()
    }

    #[test]
    fn single_scan_policy() {
        let manager = Arc::new(JobManager::new(10));
        let (tx, _rx) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();

        let id = manager
            .start_scan(dir.path().to_path_buf(), test_config(), tx.clone())
            .unwrap();
        assert!(!id.is_empty());

        // Second scan should fail while first is running.
        let result = manager.start_scan(dir.path().to_path_buf(), test_config(), tx);
        assert!(result.is_err());
    }

    #[test]
    fn bounded_history() {
        let manager = Arc::new(JobManager::new(2));
        let (tx, _rx) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();

        // Start scan and wait for it to finish.
        let id1 = manager
            .start_scan(dir.path().to_path_buf(), test_config(), tx.clone())
            .unwrap();

        // Wait for scan to complete (it's scanning an empty dir so should be fast).
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Some(j) = manager.get_job(&id1) {
                if j.status != JobStatus::Running {
                    break;
                }
            }
        }

        let id2 = manager
            .start_scan(dir.path().to_path_buf(), test_config(), tx.clone())
            .unwrap();

        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Some(j) = manager.get_job(&id2) {
                if j.status != JobStatus::Running {
                    break;
                }
            }
        }

        // Third scan should evict the oldest.
        let _id3 = manager
            .start_scan(dir.path().to_path_buf(), test_config(), tx)
            .unwrap();

        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if manager.active_job().is_none() {
                break;
            }
        }

        // First job should be evicted.
        assert!(manager.get_job(&id1).is_none());
    }
}
