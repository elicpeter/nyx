use crate::database::index::Indexer;
use crate::errors::NyxResult;
use crate::server::app::{AppState, build_router};
use crate::server::jobs::JobManager;
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use console::style;
use std::path::Path;
use std::sync::{Arc, RwLock};

pub fn handle(
    path: &str,
    port: Option<u16>,
    host: Option<&str>,
    no_browser: bool,
    config_dir: &Path,
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_root = Path::new(path).canonicalize()?;

    let host = host
        .map(String::from)
        .unwrap_or_else(|| config.server.host.clone());
    let port = port.unwrap_or(config.server.port);
    let open_browser = !no_browser && config.server.open_browser;
    let max_jobs = config.server.max_saved_runs as usize;
    let rayon_stack_size = config.performance.rayon_thread_stack_size;

    let (event_tx, _) = tokio::sync::broadcast::channel(64);

    // Initialize DB pool for scan persistence
    let db_pool = {
        let (_, db_path) = get_project_info(&scan_root, database_dir)?;
        match Indexer::init(&db_path) {
            Ok(pool) => Some(pool),
            Err(e) => {
                tracing::warn!("Failed to initialize scan DB: {e}");
                None
            }
        }
    };

    let state = AppState {
        scan_root: scan_root.clone(),
        config_dir: config_dir.to_path_buf(),
        database_dir: database_dir.to_path_buf(),
        config: Arc::new(RwLock::new(config.clone())),
        job_manager: Arc::new(JobManager::new(max_jobs, rayon_stack_size)),
        event_tx,
        db_pool,
    };

    let router = build_router(state);

    let addr = format!("{host}:{port}");
    let url = format!("http://{addr}");

    eprintln!(
        "\n  {} Nyx web UI at {}\n",
        style("Serving").green().bold(),
        style(&url).cyan().underlined(),
    );
    eprintln!(
        "  Scan root: {}\n  Press {} to stop\n",
        style(scan_root.display()).dim(),
        style("Ctrl+C").bold(),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| crate::errors::NyxError::Msg(format!("Failed to build tokio runtime: {e}")))?;

    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| crate::errors::NyxError::Msg(format!("Failed to bind {addr}: {e}")))?;

        if open_browser {
            open_browser_url(&url);
        }

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| crate::errors::NyxError::Msg(format!("Server error: {e}")))?;

        eprintln!("\n  {} Server stopped.", style("Done.").green().bold());
        Ok(())
    })
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl+C");
    eprintln!("\n  Shutting down...");
    // SSE connections block graceful shutdown indefinitely.
    // Use a raw OS thread to force exit — tokio tasks may not
    // run reliably during shutdown.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(250));
        std::process::exit(0);
    });
}

fn open_browser_url(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
}
