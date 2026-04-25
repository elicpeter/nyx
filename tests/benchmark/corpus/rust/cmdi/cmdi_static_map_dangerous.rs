use std::collections::HashMap;
use std::env;
use std::process::Command;

fn main() {
    let key = env::var("ACTION").unwrap();
    let mut table: HashMap<&str, &str> = HashMap::new();
    table.insert("list", "ls");
    // Dangerous literal: chained shell metachar means the finite set is NOT
    // shell-safe, so the SSA/CFG suppressions must both decline to clear
    // the `Command::new(cmd)` sink.
    table.insert("pwned", "echo hi; rm -rf /");
    let cmd = table.get(key.as_str()).copied().unwrap_or("true");
    Command::new(cmd).status().unwrap();
}
