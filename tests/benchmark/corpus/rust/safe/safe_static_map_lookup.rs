use std::collections::HashMap;
use std::env;
use std::process::Command;

fn main() {
    let key = env::var("ACTION").unwrap();
    let table: HashMap<&str, &str> = HashMap::from([
        ("list", "ls"),
        ("show", "cat"),
    ]);
    let cmd = table.get(key.as_str()).copied().unwrap_or("true");
    Command::new(cmd).status().unwrap();
}
