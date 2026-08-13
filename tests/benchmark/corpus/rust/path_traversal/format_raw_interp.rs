// Raw string interpolation into a filesystem path via `format!`.
//
// Vulnerable counterpart to `safe/safe_format_numeric_interp.rs`: the
// interpolated `name` is a raw String env value with no numeric coercion, so
// it is NOT numeric-confined and an attacker-supplied `../../etc/passwd` walks
// out of `/var/data`.  Proves the `format!`-macro confinement recogniser does
// not over-suppress a string interpolation — only digits-only numeric chains.
use std::env;
use std::fs;

fn read_record() {
    let name = env::var("RECORD_NAME").unwrap();
    let _ = fs::read(format!("/var/data/{}", name)).unwrap();
}
