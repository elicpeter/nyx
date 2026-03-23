mod ast;
mod callgraph;
mod cfg;
mod cfg_analysis;
mod cli;
mod commands;
mod database;
mod errors;
mod evidence;
mod fmt;
mod interop;
mod labels;
mod output;
mod patterns;
mod rank;
#[cfg(feature = "serve")]
mod server;
mod ssa;
mod state;
mod summary;
mod suppress;
mod symbol;
mod taint;
mod utils;
mod walk;

use crate::errors::NyxResult;
use crate::utils::Config;
use clap::Parser;
use cli::Cli;
use console::style;
use directories::ProjectDirs;
use std::fs;
use std::time::Instant;
use tracing_subscriber::fmt::time;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry, fmt as tracing_fmt};
// use tracing_appender::rolling::{RollingFileAppender, Rotation};
// use tracing_appender::non_blocking;

fn init_tracing() {
    // let file_appender = RollingFileAppender::new(Rotation::HOURLY, "logs", "nyx-scanner.log");
    // let (file_writer, guard) = non_blocking(file_appender);

    let fmt_layer = tracing_fmt::layer()
        .pretty()
        .with_thread_ids(true)
        .with_timer(time::UtcTime::rfc_3339());

    // let file_layer = fmt::layer()
    //     .with_writer(file_writer)
    //     .without_time()
    //     .json();

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt_layer)
        .init();
}

fn main() -> NyxResult<()> {
    let now = Instant::now();
    init_tracing();

    tracing::debug!("CLI starting up");

    if std::env::args().count() == 1 {
        eprint!("{}", fmt::render_welcome());
        return Ok(());
    }

    let cli = Cli::parse();

    let proj_dirs =
        ProjectDirs::from("", "", "nyx").ok_or("Unable to determine project directories")?;

    // todo: check if we want to actually build a config file, maybe some environments will not want to have anything written
    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;

    let database_dir = proj_dirs.data_local_dir();
    fs::create_dir_all(database_dir)?;

    let (mut config, config_note) = Config::load(config_dir)?;

    rayon::ThreadPoolBuilder::new()
        .stack_size(config.performance.rayon_thread_stack_size)
        .build_global()
        .expect("set rayon stack size");

    let is_serve = cli.command.is_serve();
    let quiet = config.output.quiet || cli.command.is_structured_output(&config);

    // Print config note before scanning (human-readable mode only).
    if let Some(note) = config_note.filter(|_| !quiet) {
        eprint!("{note}");
    }

    commands::handle_command(cli.command, database_dir, config_dir, &mut config)?;

    if !quiet && !is_serve {
        eprintln!(
            "{} in {:.3}s.",
            style("Finished").green().bold(),
            now.elapsed().as_secs_f32()
        );
    }
    Ok(())
}
