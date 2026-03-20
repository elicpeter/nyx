use std::env;
use std::process::Command;

fn sanitize_shell(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn run_user_tool() {
    if let Ok(tool) = env::var("USER_TOOL") {
        let safe_tool = sanitize_shell(&tool);
        if let Ok(output) = Command::new(&safe_tool).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{}", stdout);
        }
    }
}
