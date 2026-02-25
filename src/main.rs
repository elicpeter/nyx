mod ast;
mod cfg;
mod cli;
mod commands;
mod database;
mod errors;
mod interop;
mod labels;
mod patterns;
mod summary;
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
use tracing_subscriber::{EnvFilter, Registry, fmt};
// use tracing_appender::rolling::{RollingFileAppender, Rotation};
// use tracing_appender::non_blocking;

fn init_tracing() {
    // let file_appender = RollingFileAppender::new(Rotation::HOURLY, "logs", "nyx-scanner.log");
    // let (file_writer, guard) = non_blocking(file_appender);

    let fmt_layer = fmt::layer()
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
    let cli = Cli::parse();

    let proj_dirs = ProjectDirs::from("dev", "ecpeter23", "nyx")
        .ok_or("Unable to determine project directories")?;

    // todo: check if we want to actually build a config file, maybe some environments will not want to have anything written
    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;

    let database_dir = proj_dirs.data_local_dir();
    fs::create_dir_all(database_dir)?;

    let mut config = Config::load(config_dir)?;

    rayon::ThreadPoolBuilder::new()
        .stack_size(config.performance.rayon_thread_stack_size)
        .build_global()
        .expect("set rayon stack size");

    commands::handle_command(cli.command, database_dir, &mut config)?;

    println!(
        "{} in {:.3}s.",
        style("Finished").green().bold(),
        now.elapsed().as_secs_f32()
    );
    Ok(())
}
