use std::process::Command;

fn run_known_commands() {
    let commands = vec!["date", "whoami", "hostname"];
    for cmd in commands {
        if let Ok(output) = Command::new(cmd).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{}: {}", cmd, stdout);
        }
    }
}
