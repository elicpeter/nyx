// ─────────────────────────────────────────────────────────────────────────────
// examples/cross-file/exec.rs — Sinks
//
// Functions that perform dangerous operations.  Passing tainted data to
// these without the matching sanitiser is a vulnerability.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  FuncSummary produced by pass 1:                                       │
// │                                                                        │
// │  run_command      → sink_caps: SHELL_ESCAPE, tainted_sink_params: [0]  │
// │  render_page      → sink_caps: HTML_ESCAPE,  tainted_sink_params: [0]  │
// │  log_and_execute  → sink_caps: SHELL_ESCAPE, source_caps: ALL          │
// │                     (both a source AND a sink!)                         │
// └─────────────────────────────────────────────────────────────────────────┘
// ─────────────────────────────────────────────────────────────────────────────

use std::env;
use std::process::Command;

/// Executes a shell command.
/// Taint: SINK(SHELL_ESCAPE) on `cmd` (param 0).
pub fn run_command(cmd: &str) {
    Command::new("sh").arg(cmd).status().unwrap();
}

/// Renders user content into an HTML page.
/// Taint: SINK(HTML_ESCAPE) on `body` (param 0).
pub fn render_page(body: &str) {
    println!("<html><body>{body}</body></html>");
}

/// Reads an env var *and* shells out — a function that is simultaneously
/// a source (return value) and a sink (cmd parameter).
///
/// This exercises the "independent caps" design: source_caps and sink_caps
/// are both non-zero on the same summary.
pub fn log_and_execute(cmd: &str) -> String {
    let log_path = env::var("LOG_PATH").unwrap_or_default();
    Command::new("sh").arg(cmd).status().unwrap();
    log_path
}
