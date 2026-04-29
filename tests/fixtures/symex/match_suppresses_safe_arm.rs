// Fixture for symex per-case path-constraint exploration.
//
// The match arm with `cap == Cap::Raw` flows tainted environment input
// into a shell sink. The Cap::Safe arm allowlists the input via match
// before reaching the sink. After the executor refactor, the symex
// explorer forks per match arm with a `cap == <arm_value>` path
// constraint; the Safe arm explores along its own state where the
// allowlist guards the sink.

use std::env;
use std::process::Command;

#[derive(PartialEq)]
enum Cap {
    Raw,
    Safe,
}

pub fn dispatch(cap: Cap) {
    let user_cmd = env::var("USER_CMD").unwrap_or_default();
    match cap {
        // Raw arm, tainted user_cmd flows directly into the shell.
        Cap::Raw => {
            Command::new("sh")
                .arg("-c")
                .arg(&user_cmd)
                .output()
                .unwrap();
        }
        // Safe arm, allowlist-guarded execution.
        Cap::Safe => {
            let allowed = ["ls", "date"];
            if allowed.contains(&user_cmd.as_str()) {
                Command::new(&user_cmd).output().unwrap();
            }
        }
    }
}
