#![no_main]

// Pass-1 of the two-pass scanner: parse + summary extraction only,
// without taint, rules, or cross-file resolution. Smaller surface than
// `scan_bytes`, so libFuzzer converges on parse / lowering bugs faster
// when they exist.
use libfuzzer_sys::fuzz_target;
use nyx_scanner::ast::extract_summaries_from_bytes;
use nyx_scanner::utils::config::Config;
use std::path::Path;

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
    let _ = extract_summaries_from_bytes(&data[1..], path, &cfg);
});
