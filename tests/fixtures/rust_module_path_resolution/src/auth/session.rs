// Session-module validate: accidentally shells out with its param.
// Same name + arity as auth::token::validate, ambiguous without a use map.
// If cross-file resolution incorrectly targets this function from main.rs,
// the param taint from env::var will flow into Command::arg → taint finding.
pub fn validate(input: &str) -> String {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(input)
        .output()
        .expect("command failed");
    String::from_utf8_lossy(&out.stdout).to_string()
}
