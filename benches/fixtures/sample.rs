use std::env;
use std::process::Command;

fn get_config() -> String {
    env::var("APP_CONFIG").unwrap_or_default()
}

fn sanitize_shell(input: &str) -> String {
    shell_escape::unix::escape(input.into()).to_string()
}

fn run_command(cmd: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .expect("failed to execute");
}

fn safe_run() {
    let config = get_config();
    let clean = sanitize_shell(&config);
    run_command(&clean);
}

fn unsafe_run() {
    let config = get_config();
    run_command(&config);
}

fn main() {
    safe_run();
    unsafe_run();
}
