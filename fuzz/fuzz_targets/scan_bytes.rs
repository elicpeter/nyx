#![no_main]

use libfuzzer_sys::fuzz_target;
use nyx_scanner::ast::run_rules_on_bytes;
use nyx_scanner::utils::config::Config;
use std::path::Path;

// One extension per supported tree-sitter grammar. The first input byte
// picks which language path the parser takes; the rest is fed in as
// source. Splitting this way lets a single corpus exercise all 10
// language frontends without separate fuzz targets.
const EXTENSIONS: &[&str] = &[
    "rs", "js", "ts", "py", "go", "java", "rb", "php", "c", "cpp",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let ext = EXTENSIONS[(data[0] as usize) % EXTENSIONS.len()];
    let path_buf = format!("fuzz_input.{ext}");
    let path = Path::new(&path_buf);
    let cfg = Config::default();
    let _ = run_rules_on_bytes(&data[1..], path, &cfg, None, None);
});
