// Regression fixture: Rust async flow through `tokio::process::Command`.
//
// Per docs/language-maturity.md, Rust's Tokio process variants are not
// yet covered, the Tokio async process APIs are a known gap.  The
// fixture is checked in so that when Rust async-process coverage lands,
// the engine begins producing the intended finding and the
// `forbidden_findings` assertion forces whoever adds the coverage to
// update this expectation.
#![allow(unused)]
use std::env;

async fn fetch_and_exec() {
    let cmd = env::var("CMD").unwrap_or_default();
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .await
        .ok();
}

#[tokio::main]
async fn main() {
    fetch_and_exec().await;
}
