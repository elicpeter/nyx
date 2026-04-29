use crate::auth::token::validate;

// `validate(&cmd)` must resolve unambiguously to `auth::token::validate`
// (a pass-through sanitizer), NOT `auth::session::validate` (which sinks
// its arg into std::process::Command). A correct use-map driven resolver
// produces zero cross-file taint findings on this file.
fn main() {
    let cmd = std::env::var("CMD").unwrap();
    let cleaned = validate(&cmd);
    println!("{}", cleaned);
}
