#![no_main]

// Cross-file resolution path: drives `run_rules_on_bytes` with a
// pre-seeded `GlobalSummaries` so the SSA/taint engine actually
// exercises `resolve_callee` against external summaries instead of
// short-circuiting on `None` like `scan_bytes` does. The synthetic
// summaries register one source / sanitizer / sink / pass-through
// helper per language under fixed names, so libFuzzer mutations that
// produce calls to those names hit the cross-file merge + resolution
// paths (`GlobalSummaries::insert`, `by_lang_name` / `by_lang_qualified`
// lookups, `ssa_by_key` precedence). The dictionary committed alongside
// this target lists those names so libFuzzer biases towards them.

use libfuzzer_sys::fuzz_target;
use nyx_scanner::ast::run_rules_on_bytes;
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::{FuncSummary, GlobalSummaries};
use nyx_scanner::symbol::{FuncKey, Lang};
use nyx_scanner::utils::config::Config;
use std::path::Path;
use std::sync::OnceLock;

const EXTENSIONS: &[&str] = &[
    "rs", "js", "ts", "py", "go", "java", "rb", "php", "c", "cpp",
];

const LANGS: &[Lang] = &[
    Lang::Rust,
    Lang::JavaScript,
    Lang::TypeScript,
    Lang::Python,
    Lang::Go,
    Lang::Java,
    Lang::Ruby,
    Lang::Php,
    Lang::C,
    Lang::Cpp,
];

// Helper names registered in `GlobalSummaries`. The dictionary file
// (`fuzz/dict/all.dict`) lists these so libFuzzer mutations bias
// toward producing calls that resolve to them.
const SYNTHETIC_HELPERS: &[(&str, HelperRole)] = &[
    ("nyx_taint_source", HelperRole::Source),
    ("nyx_sanitize", HelperRole::Sanitizer),
    ("nyx_dangerous_sink", HelperRole::Sink),
    ("nyx_pass_through", HelperRole::PassThrough),
];

#[derive(Clone, Copy)]
enum HelperRole {
    Source,
    Sanitizer,
    Sink,
    PassThrough,
}

fn build_global_summaries() -> GlobalSummaries {
    let mut g = GlobalSummaries::new();
    for &lang in LANGS {
        for &(name, role) in SYNTHETIC_HELPERS {
            let arity = match role {
                HelperRole::Source => 0,
                HelperRole::Sanitizer | HelperRole::Sink | HelperRole::PassThrough => 1,
            };
            let key = FuncKey {
                lang,
                namespace: format!("nyx_synthetic_{}.{}", lang.as_str(), default_ext(lang)),
                name: name.into(),
                arity: Some(arity),
                ..Default::default()
            };
            let summary = match role {
                HelperRole::Source => FuncSummary {
                    name: name.into(),
                    file_path: key.namespace.clone(),
                    lang: lang.as_str().into(),
                    param_count: 0,
                    param_names: vec![],
                    source_caps: Cap::all().bits(),
                    ..Default::default()
                },
                HelperRole::Sanitizer => FuncSummary {
                    name: name.into(),
                    file_path: key.namespace.clone(),
                    lang: lang.as_str().into(),
                    param_count: 1,
                    param_names: vec!["input".into()],
                    sanitizer_caps: Cap::all().bits(),
                    propagating_params: vec![0],
                    ..Default::default()
                },
                HelperRole::Sink => FuncSummary {
                    name: name.into(),
                    file_path: key.namespace.clone(),
                    lang: lang.as_str().into(),
                    param_count: 1,
                    param_names: vec!["input".into()],
                    sink_caps: Cap::all().bits(),
                    tainted_sink_params: vec![0],
                    ..Default::default()
                },
                HelperRole::PassThrough => FuncSummary {
                    name: name.into(),
                    file_path: key.namespace.clone(),
                    lang: lang.as_str().into(),
                    param_count: 1,
                    param_names: vec!["input".into()],
                    propagating_params: vec![0],
                    ..Default::default()
                },
            };
            g.insert(key, summary);
        }
    }
    g
}

fn default_ext(lang: Lang) -> &'static str {
    match lang {
        Lang::Rust => "rs",
        Lang::JavaScript => "js",
        Lang::TypeScript => "ts",
        Lang::Python => "py",
        Lang::Go => "go",
        Lang::Java => "java",
        Lang::Ruby => "rb",
        Lang::Php => "php",
        Lang::C => "c",
        Lang::Cpp => "cpp",
    }
}

static GLOBAL: OnceLock<GlobalSummaries> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let ext = EXTENSIONS[(data[0] as usize) % EXTENSIONS.len()];
    let path_buf = format!("fuzz_input.{ext}");
    let path = Path::new(&path_buf);
    let cfg = Config::default();
    let summaries = GLOBAL.get_or_init(build_global_summaries);
    let _ = run_rules_on_bytes(&data[1..], path, &cfg, Some(summaries), None);
});
