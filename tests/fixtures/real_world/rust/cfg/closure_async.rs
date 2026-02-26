use std::env;
use std::process::Command;

fn apply_command<F: Fn(&str)>(f: F) {
    let cmd = env::var("CMD").unwrap();
    f(&cmd);
}

fn main() {
    apply_command(|cmd| {
        Command::new("sh").arg("-c").arg(cmd).output().unwrap();
    });
}
