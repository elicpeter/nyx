fn source_env(var: &str) -> String {
    env::var(var).unwrap_or_default()                          // Source(env-var)
}

fn main() {
    let raw = source_env("USER_CMD");
    Command::new("sh").arg(raw).status().unwrap();
}