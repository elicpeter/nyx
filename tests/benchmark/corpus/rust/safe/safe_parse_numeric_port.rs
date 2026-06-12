use std::env;
use std::process::Command;

fn main() {
    // A u16 port parsed from the environment is numeric and cannot carry
    // shell metacharacters.  The `let port: u16` annotation lowers to
    // TypeKind::Int, keeping the bare-`parse` -> Int suppression so the
    // shell arg stays silent (precision counterpart to the PathBuf vuln).
    let raw = env::var("PORT").unwrap();
    let port: u16 = raw.parse().unwrap();
    Command::new("listener")
        .arg(port.to_string())
        .status()
        .unwrap();
}
