use crate::utils::Config;
use crossbeam_channel::{Receiver, Sender, bounded};
use ignore::{WalkBuilder, WalkState, overrides::OverrideBuilder};
use std::thread::JoinHandle;
use std::{
    mem,
    path::{Path, PathBuf},
    thread,
};

// ---------------------------------------------------------------------------
// Internal constants / helpers
// ---------------------------------------------------------------------------

type Paths = Vec<PathBuf>;

struct BatchSender {
    tx: Sender<Paths>,
    batch: Paths,
    batch_size: usize,
}
impl BatchSender {
    fn new(tx: Sender<Paths>, batch_size: usize) -> Self {
        Self {
            tx,
            batch: Vec::with_capacity(batch_size),
            batch_size,
        }
    }

    fn push_path(&mut self, path: PathBuf) {
        self.batch.push(path);
        if self.batch.len() >= self.batch_size {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.batch.is_empty() {
            tracing::debug!(n_paths = self.batch.len(), "flushing batch");
            let _ = self.tx.send(mem::take(&mut self.batch));
        }
    }
}
impl Drop for BatchSender {
    fn drop(&mut self) {
        self.flush();
    }
}

fn build_overrides(root: &Path, cfg: &Config) -> ignore::overrides::Override {
    let mut ob = OverrideBuilder::new(root);

    for ext in &cfg.scanner.excluded_extensions {
        if let Err(e) = ob.add(&format!("!*.{ext}")) {
            tracing::warn!("invalid exclude‐extension pattern ‘{ext}’: {e}");
        }
    }
    for dir in &cfg.scanner.excluded_directories {
        if let Err(e) = ob.add(&format!("!**/{dir}/**")) {
            tracing::warn!("invalid exclude‐dir pattern ‘{dir}’: {e}");
        }
    }

    ob.build().unwrap_or_else(|e| {
        tracing::error!("failed to build ignore overrides: {e}");
        ignore::overrides::Override::empty()
    })
}

// ---------------------------------------------------------------------------
/// Walk `root` and send *batches* of paths through the returned channel.
pub fn spawn_file_walker(root: &Path, cfg: &Config) -> (Receiver<Paths>, JoinHandle<()>) {
    let _span = tracing::info_span!("spawn_file_walker", root = %root.display()).entered();
    let overrides = build_overrides(root, cfg);

    // ----- 2  channel & thread pool parameters -----------------------------
    let workers = cfg.performance.worker_threads.unwrap_or(num_cpus::get());
    let (tx, rx) = bounded::<Paths>(workers * cfg.performance.channel_multiplier);

    let root = root.to_path_buf();
    let scan_hidden = cfg.scanner.scan_hidden_files;
    let follow = cfg.scanner.follow_symlinks;
    let max_bytes = cfg.scanner.max_file_size_mb.unwrap_or(0) * 1_048_576;
    let batch_size = cfg.performance.batch_size;

    // ----- 3  the background walker thread ---------------------------------
    let handle = thread::spawn(move || {
        tracing::info!(
            root = ?root,
            workers = workers,
            scan_hidden = scan_hidden,
            follow_links = follow,
            max_bytes = max_bytes,
            batch_size = batch_size,
            "starting directory walk"
        );

        WalkBuilder::new(root)
            .hidden(!scan_hidden)
            .follow_links(follow)
            .threads(workers)
            .overrides(overrides)
            .filter_entry(|e| {
                e.file_type()
                    .map(|ft| ft.is_dir() || ft.is_file())
                    .unwrap_or(true)
            })
            .build_parallel()
            .run(move || {
                let mut bs = BatchSender::new(tx.clone(), batch_size);

                Box::new(move |entry| {
                    if let Ok(e) = entry {
                        let is_file = e.file_type().is_some_and(|ft| ft.is_file());
                        let under_limit = max_bytes == 0
                            || e.metadata().map(|m| m.len() <= max_bytes).unwrap_or(true);

                        if is_file && under_limit {
                            bs.push_path(e.into_path());
                        }
                    }
                    WalkState::Continue
                })
            });
        tracing::info!("directory walk complete");
    });

    (rx, handle)
}

#[test]
fn walker_respects_excluded_extensions() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("keep.rs"), "fn main(){}").unwrap();
    std::fs::write(tmp.path().join("skip.txt"), "ignored").unwrap();

    let mut cfg = Config::default();
    cfg.scanner.excluded_extensions = vec!["txt".into()];
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let (rx, handle) = spawn_file_walker(tmp.path(), &cfg);
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
    }

    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.iter().any(|p| p.ends_with("keep.rs")));
    assert!(all.iter().all(|p| !p.ends_with("skip.txt")));
}
