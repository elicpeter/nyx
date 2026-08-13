// Vulnerable counterpart to `safe_numeric_parse_shell_arg.rs`.
//
// `user_cmd.to_string()` on a *String* env value is an identity passthrough,
// NOT a numeric confinement: the receiver of `.to_string()` is a String, so
// the result still carries the raw attacker-controlled bytes.  The command
// injection must still fire — confinement only applies when every occurrence
// of the leaf is consumed by a numeric / safe-string producer.
use std::process::Command;

fn spawn_cmd() {
    let user_cmd = std::env::var("USER_CMD").unwrap_or_default();
    let _ = Command::new("nc").arg(user_cmd.to_string()).output();
}
