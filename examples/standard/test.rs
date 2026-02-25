fn source_env(var: &str) -> String {
    env::var(var).unwrap_or_default()                          // Source(env-var)
}

fn source_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()               // Source(file-io)
}

fn sink_shell(arg: &str) {
    Command::new("sh").arg(arg).status().unwrap();             // Sink(process-spawn)
}

fn sink_html(out: &str) {
    println!("{out}");                                         // Sink(html-out)
}

fn main() {
    let raw = source_env("USER_CMD");
    let raw2 = source_file("ANOTHER");
    let x = source_env("ANOTHER");
    if x.len() > 5 {
        sink_shell(&x);                     // EXPECT: UNSAFE
        return;
    } else {
        let escaped = sanitize_shell(&x);
        sink_shell(&escaped);               // safe
    }
    sink_shell(raw);                       // EXPECT: UNSAFE
    sink_html(raw2);
}