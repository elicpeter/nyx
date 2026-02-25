use super::*;
use crate::cfg::FuncSummaries;
use crate::interop::InteropEdge;
use crate::symbol::FuncKey;

#[test]
fn env_to_arg_is_flagged() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS_ARG").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    assert_eq!(findings.len(), 1); // exactly one unsanitised Source→Sink
}

#[test]
fn taint_through_if_else() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let safe = html_escape::encode_safe(&x);

            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();   // UNSAFE
            } else {
                Command::new("sh").arg(&safe).status().unwrap(); // SAFE
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    // exactly one path (via the True branch) should be flagged
    assert_eq!(findings.len(), 1);
}

#[test]
fn taint_through_while_loop() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            while x.len() < 100 {                       // Loop header (Loop)
                x.push_str("a");
            }
            Command::new("sh").arg(x).status().unwrap(); // Should be flagged
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert_eq!(findings.len(), 1);
}

#[test]
fn taint_killed_by_matching_sanitizer() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // shell_escape sanitizer strips SHELL_ESCAPE → Command sink checks
    // SHELL_ESCAPE → the matching bit is gone → no finding.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert!(
        findings.is_empty(),
        "matching sanitizer should kill the taint"
    );
}

#[test]
fn wrong_sanitizer_preserves_taint() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // html_escape sanitizer strips HTML_ESCAPE, but Command sink checks
    // SHELL_ESCAPE → the wrong bit was stripped → finding persists.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = html_escape::encode_safe(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert_eq!(
        findings.len(),
        1,
        "wrong sanitizer should NOT kill the taint"
    );
}

#[test]
fn taint_breaks_out_of_loop() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            loop {
                let x = env::var("DANGEROUS").unwrap();
                Command::new("sh").arg(&x).status().unwrap(); // vulnerable
                break;
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_two_sources_one_sanitised() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Two env sources, one properly sanitised with the MATCHING sanitiser.
    // x → unsanitised → Command = FINDING
    // y → shell_escape → Command = safe
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = env::var("ANOTHER").unwrap();
            let clean = shell_escape::unix::escape(&y);
            Command::new("sh").arg(x).status().unwrap();
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert_eq!(
        findings.len(),
        1,
        "only the unsanitised source should be flagged"
    );
}

#[test]
fn test_two_sources_wrong_sanitiser_both_flagged() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Two env sources, one "sanitised" with the WRONG sanitiser.
    // x → unsanitised → Command = FINDING
    // y → html_escape → Command = FINDING (wrong sanitiser for shell sink)
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = env::var("ANOTHER").unwrap();
            let clean = html_escape::encode_safe(&y);
            Command::new("sh").arg(x).status().unwrap();
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert_eq!(
        findings.len(),
        2,
        "both should be flagged — wrong sanitiser"
    );
}

#[test]
fn test_should_not_panic_on_empty_function() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn f() {
            if cond() {
                return;
            }
            do_something();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    assert!(findings.is_empty());
}

#[test]
fn cross_file_source_resolved_via_global_summaries() {
    use crate::summary::FuncSummary;

    // Simulate file B calling `get_dangerous()` which is defined in file A.
    // File A's summary says get_dangerous is a Source(all).
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = get_dangerous();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let (cfg, entry, local_summaries) = parse_rust(src);

    // Build global summaries as if file A exported get_dangerous
    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "get_dangerous".into(),
        arity: Some(0),
    };
    global.insert(
        key,
        FuncSummary {
            name: "get_dangerous".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    let findings = analyse_file(
        &cfg,
        entry,
        &local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );
    assert_eq!(findings.len(), 1, "cross-file source should be detected");
}

#[test]
fn cross_file_sanitizer_resolved_via_global_summaries() {
    use crate::summary::FuncSummary;

    // File B gets tainted data and passes it through `my_sanitize()` from file A.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = my_sanitize(x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let (cfg, entry, local_summaries) = parse_rust(src);

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "my_sanitize".into(),
        arity: Some(1),
    };
    global.insert(
        key,
        FuncSummary {
            name: "my_sanitize".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["input".into()],
            source_caps: 0,
            sanitizer_caps: Cap::all().bits(),
            sink_caps: 0,
            propagates_taint: true,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    let findings = analyse_file(
        &cfg,
        entry,
        &local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );
    assert!(
        findings.is_empty(),
        "cross-file sanitizer should neutralise taint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Shared test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse Rust source bytes → (cfg, entry, local_summaries)
fn parse_rust(src: &[u8]) -> (Cfg, NodeIndex, FuncSummaries) {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    build_cfg(&tree, src, "rust", "test.rs")
}

/// Parse Rust source bytes, build CFG, and export cross-file summaries.
fn extract_summaries_from_bytes(src: &[u8], path: &str) -> Vec<crate::summary::FuncSummary> {
    use crate::cfg::export_summaries;
    let (_, _, local) = parse_rust(src);
    export_summaries(&local, path, "rust")
}

#[test]
fn cross_file_sink_resolved_via_global_summaries() {
    use crate::summary::FuncSummary;

    // File B calls `dangerous_exec(x)` from file A which is a sink.
    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("INPUT").unwrap();
            dangerous_exec(x);
        }"#;

    let (cfg, entry, local_summaries) = parse_rust(src);

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "dangerous_exec".into(),
        arity: Some(1),
    };
    global.insert(
        key,
        FuncSummary {
            name: "dangerous_exec".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["cmd".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            propagates_taint: false,
            tainted_sink_params: vec![0],
            callees: vec!["Command::new".into()],
        },
    );

    let findings = analyse_file(
        &cfg,
        entry,
        &local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );
    assert_eq!(findings.len(), 1, "cross-file sink should be detected");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Multi-file integration tests (real parsing, full pass-1 → pass-2 pipeline)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn multi_file_source_to_sink_detected() {
    use crate::summary::merge_summaries;

    // File A: defines get_dangerous() which calls env::var (a source).
    let lib_src = br#"
        use std::env;
        fn get_dangerous() -> String {
            env::var("SECRET").unwrap()
        }
    "#;

    // File B: calls get_dangerous() then passes result to Command (a sink).
    let caller_src = br#"
        use std::process::Command;
        fn main() {
            let x = get_dangerous();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "cross-file source → inline sink should produce 1 finding"
    );
}

#[test]
fn multi_file_sanitizer_neutralises_cross_file_source() {
    use crate::summary::merge_summaries;

    // File A: source + matching shell sanitizer.
    // NOTE: function name avoids `sanitize_` prefix which triggers
    //       the inline HTML sanitizer label rule.
    let lib_src = br#"
        use std::env;
        fn get_input() -> String {
            env::var("INPUT").unwrap()
        }
        fn clean_shell(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
    "#;

    // File B: source → clean_shell → shell sink.
    let caller_src = br#"
        use std::process::Command;
        fn main() {
            let x = get_input();
            let clean = clean_shell(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert!(
        findings.is_empty(),
        "matching cross-file sanitizer should neutralise taint, got {} findings",
        findings.len()
    );
}

#[test]
fn multi_file_wrong_sanitizer_preserves_taint() {
    use crate::summary::merge_summaries;

    // File A: source + HTML sanitizer (wrong for shell sink).
    let lib_src = br#"
        use std::env;
        fn get_input() -> String {
            env::var("INPUT").unwrap()
        }
        fn clean_html(s: &str) -> String {
            html_escape::encode_safe(s).to_string()
        }
    "#;

    // File B: source → HTML sanitize → shell sink → should still flag.
    let caller_src = br#"
        use std::process::Command;
        fn main() {
            let x = get_input();
            let clean = clean_html(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "wrong sanitizer (HTML for shell sink) should NOT neutralise taint"
    );
}

#[test]
fn multi_file_sink_in_another_file() {
    use crate::summary::merge_summaries;

    // File A: defines exec_cmd() which internally calls Command::new (a sink).
    let lib_src = br#"
        use std::process::Command;
        fn exec_cmd(cmd: &str) {
            Command::new("sh").arg(cmd).status().unwrap();
        }
    "#;

    // File B: env::var → exec_cmd() — sink is cross-file.
    let caller_src = br#"
        use std::env;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            exec_cmd(&x);
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(findings.len(), 1, "cross-file sink should be detected");
}

#[test]
fn multi_file_passthrough_preserves_taint() {
    use crate::summary::FuncSummary;

    // identity() just returns its argument — it propagates taint but has no
    // source/sanitizer/sink caps of its own.
    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "identity".into(),
        arity: Some(1),
    };
    global.insert(
        key,
        FuncSummary {
            name: "identity".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["s".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: true,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    let caller_src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = identity(&x);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "taint should propagate through passthrough function"
    );
}

#[test]
fn multi_file_chain_source_sanitize_sink_across_files() {
    use crate::summary::merge_summaries;

    // Library file defines all three roles: source, sanitizer, sink.
    let lib_src = br#"
        use std::env;
        use std::process::Command;
        fn get_input() -> String {
            env::var("INPUT").unwrap()
        }
        fn clean_shell(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
        fn exec_cmd(cmd: &str) {
            Command::new("sh").arg(cmd).status().unwrap();
        }
    "#;

    // Caller: source → correct sanitizer → sink.
    let caller_src = br#"
        fn main() {
            let x = get_input();
            let clean = clean_shell(&x);
            exec_cmd(&clean);
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert!(
        findings.is_empty(),
        "source → matching sanitizer → sink should produce 0 findings, got {}",
        findings.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Edge-case unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sanitizer_strips_only_matching_bits() {
    // Source(ALL) → shell_escape → sink_html (HTML sink).
    // shell_escape strips SHELL_ESCAPE but not HTML_ESCAPE.
    // sink_html is an HTML sink — HTML_ESCAPE bit is still set → 1 finding.
    let src = br#"
        use std::env;
        fn sink_html(s: &str) {}
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            sink_html(&clean);
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    assert_eq!(
        findings.len(),
        1,
        "shell sanitizer should NOT strip HTML_ESCAPE bit; HTML sink should still fire"
    );
}

#[test]
fn multiple_sanitizers_strip_all_bits() {
    // Source → shell_escape → html_escape → Command (shell sink).
    // shell_escape strips SHELL_ESCAPE; html_escape strips HTML_ESCAPE.
    // After both, the remaining taint bits relevant to SHELL_ESCAPE are gone.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let a = shell_escape::unix::escape(&x);
            let b = html_escape::encode_safe(&a);
            Command::new("sh").arg(b).status().unwrap();
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    assert!(
        findings.is_empty(),
        "both sanitizers together should strip all relevant bits"
    );
}

#[test]
fn taint_through_variable_reassignment() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = x;
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    assert_eq!(
        findings.len(),
        1,
        "taint should flow through simple variable reassignment"
    );
}

#[test]
fn untainted_variable_at_sink_is_safe() {
    // A string literal (not from a source) passed to Command — no finding.
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = "harmless";
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    assert!(
        findings.is_empty(),
        "untainted literal should not trigger a finding"
    );
}

#[test]
fn local_summary_takes_precedence_over_global() {
    use crate::summary::FuncSummary;

    // The caller file defines my_func locally as a source.
    // Global says my_func is a sanitizer.
    // Local should win → finding expected.
    let caller_src = br#"
        use std::{env, process::Command};
        fn my_func() -> String {
            env::var("SECRET").unwrap()
        }
        fn main() {
            let x = my_func();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "other.rs".into(),
        name: "my_func".into(),
        arity: Some(0),
    };
    global.insert(
        key,
        FuncSummary {
            name: "my_func".into(),
            file_path: "other.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: Cap::all().bits(),
            sink_caps: 0,
            propagates_taint: true,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "local summary (source) should take precedence over global (sanitizer)"
    );
}

#[test]
fn empty_global_summaries_same_as_none() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);

    let findings_none = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);
    let empty = GlobalSummaries::new();
    let findings_empty = analyse_file(
        &cfg,
        entry,
        &summaries,
        Some(&empty),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings_none.len(),
        findings_empty.len(),
        "empty GlobalSummaries should behave identically to None"
    );
}

#[test]
fn taint_not_introduced_by_non_source_function() {
    // Call an unknown function (no summary anywhere), assign to var, pass to sink.
    // Unknown calls should NOT introduce taint.
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = totally_unknown_func();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Rust, "test.rs", &[]);

    assert!(
        findings.is_empty(),
        "unknown function call should not introduce taint"
    );
}

#[test]
fn source_and_sink_on_same_function() {
    use crate::summary::FuncSummary;

    // Cross-file function that is both source AND sink.
    // Tainted arg hits sink → 1 finding.
    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "source_and_sink".into(),
        arity: Some(1),
    };
    global.insert(
        key,
        FuncSummary {
            name: "source_and_sink".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["input".into()],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            propagates_taint: false,
            tainted_sink_params: vec![0],
            callees: vec![],
        },
    );

    // Pass tainted data from env::var into source_and_sink.
    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            source_and_sink(x);
        }
    "#;

    let (cfg, entry, local) = parse_rust(src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "function that is both source and sink should detect tainted arg as finding"
    );
}

#[test]
fn multiple_cross_file_sources_one_sanitised() {
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    // Two cross-file sources
    let key1 = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "get_secret".into(),
        arity: Some(0),
    };
    global.insert(
        key1,
        FuncSummary {
            name: "get_secret".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );
    let key2 = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "get_other_secret".into(),
        arity: Some(0),
    };
    global.insert(
        key2,
        FuncSummary {
            name: "get_other_secret".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    // One source sanitised, one not.
    let src = br#"
        use std::process::Command;
        fn main() {
            let a = get_secret();
            let b = get_other_secret();
            let clean_a = shell_escape::unix::escape(&a);
            Command::new("sh").arg(clean_a).status().unwrap();
            Command::new("sh").arg(b).status().unwrap();
        }
    "#;

    let (cfg, entry, local) = parse_rust(src);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "only the unsanitised cross-file source should produce a finding"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Multi-language helpers and tests
// ─────────────────────────────────────────────────────────────────────────────

/// Parse source bytes for any supported language → (cfg, entry, local_summaries)
fn parse_lang(
    src: &[u8],
    slug: &str,
    ts_lang: tree_sitter::Language,
) -> (Cfg, NodeIndex, FuncSummaries) {
    use crate::cfg::build_cfg;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let ext = match slug {
        "rust" => "test.rs",
        "javascript" => "test.js",
        "typescript" => "test.ts",
        "python" => "test.py",
        "go" => "test.go",
        "java" => "test.java",
        "c" => "test.c",
        "cpp" => "test.cpp",
        "php" => "test.php",
        "ruby" => "test.rb",
        _ => "test.txt",
    };
    build_cfg(&tree, src, slug, ext)
}

#[test]
fn js_source_to_sink() {
    let src = b"function main() {\n  let x = document.location();\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "javascript", lang);
    let findings = analyse_file(
        &cfg,
        entry,
        &summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
    );
    assert_eq!(
        findings.len(),
        1,
        "JS: source->sink should produce 1 finding"
    );
}

#[test]
fn ts_source_to_sink() {
    let src = b"function main() {\n  let x = document.location();\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let (cfg, entry, summaries) = parse_lang(src, "typescript", lang);
    let findings = analyse_file(
        &cfg,
        entry,
        &summaries,
        None,
        Lang::TypeScript,
        "test.ts",
        &[],
    );
    assert_eq!(
        findings.len(),
        1,
        "TS: source->sink should produce 1 finding"
    );
}

#[test]
fn python_source_to_sink() {
    let src = b"def main():\n    x = os.getenv(\"SECRET\")\n    os.system(x)\n";
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "python", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Python, "test.py", &[]);
    assert_eq!(
        findings.len(),
        1,
        "Python: source->sink should produce 1 finding"
    );
}

#[test]
fn go_source_to_sink() {
    let src =
        b"package main\n\nfunc main() {\n\tx := os.Getenv(\"SECRET\")\n\texec.Command(x)\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "go", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Go, "test.go", &[]);
    assert_eq!(
        findings.len(),
        1,
        "Go: source->sink should produce 1 finding"
    );
}

#[test]
fn java_source_to_sink() {
    let src = b"class Main {\n  void main() {\n    String x = System.getenv(\"SECRET\");\n    Runtime.exec(x);\n  }\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "java", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Java, "test.java", &[]);
    assert_eq!(
        findings.len(),
        1,
        "Java: source->sink should produce 1 finding"
    );
}

#[test]
fn c_source_to_sink() {
    let src = b"void main() {\n  char* x = getenv(\"SECRET\");\n  system(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "c", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::C, "test.c", &[]);
    assert_eq!(
        findings.len(),
        1,
        "C: source->sink should produce 1 finding"
    );
}

#[test]
fn cpp_source_to_sink() {
    let src = b"void main() {\n  char* x = getenv(\"SECRET\");\n  system(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "cpp", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Cpp, "test.cpp", &[]);
    assert_eq!(
        findings.len(),
        1,
        "C++: source->sink should produce 1 finding"
    );
}

#[test]
fn php_source_to_sink() {
    let src =
        b"<?php\nfunction main() {\n  $x = file_get_contents(\"secret\");\n  system($x);\n}\n?>";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let (cfg, entry, summaries) = parse_lang(src, "php", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Php, "test.php", &[]);
    assert_eq!(
        findings.len(),
        1,
        "PHP: source->sink should produce 1 finding"
    );
}

#[test]
fn ruby_source_to_sink() {
    let src = b"def main\n  x = gets()\n  system(x)\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "ruby", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None, Lang::Ruby, "test.rb", &[]);
    assert_eq!(
        findings.len(),
        1,
        "Ruby: source->sink should produce 1 finding"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cross-language multi-file tests
// ─────────────────────────────────────────────────────────────────────────────
//
// Cross-language resolution now requires explicit InteropEdge declarations.
// Without an edge, functions from different languages are never resolved —
// this prevents false positives from name collisions across languages.

/// Extract cross-file summaries from any language's source bytes.
fn extract_lang_summaries(
    src: &[u8],
    slug: &str,
    ts_lang: tree_sitter::Language,
    path: &str,
) -> Vec<crate::summary::FuncSummary> {
    use crate::cfg::export_summaries;
    let (_, _, local) = parse_lang(src, slug, ts_lang);
    export_summaries(&local, path, slug)
}

// ── Scenario 1: Python source function → JavaScript sink via interop ─────
#[test]
fn cross_lang_python_source_to_js_sink_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let py_src = b"def get_input():\n    x = os.getenv(\"SECRET\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_summaries = extract_lang_summaries(py_src, "python", py_lang, "lib.py");
    let global = merge_summaries(py_summaries, None);

    // JavaScript file calls get_input() and passes to eval()
    let js_src = b"function main() {\n  let x = get_input();\n  eval(x);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, local) = parse_lang(js_src, "javascript", js_lang);

    // Without interop: no cross-lang resolution
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &[],
    );
    assert!(findings.is_empty(), "No cross-lang without interop edge");

    // With interop edge
    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "get_input".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Python,
            namespace: "lib.py".into(),
            name: "get_input".into(),
            arity: Some(0),
        },
        arg_map: vec![],
        ret_taints: true,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
    );
    assert_eq!(
        findings.len(),
        1,
        "Python source → JS sink via interop edge"
    );
}

// ── Scenario 2: Go source function → Python sink via interop ─────────────
#[test]
fn cross_lang_go_source_to_python_sink_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let go_src =
        b"package main\n\nfunc fetch_env() string {\n\tx := os.Getenv(\"SECRET\")\n\treturn x\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let go_summaries = extract_lang_summaries(go_src, "go", go_lang, "lib.go");
    let global = merge_summaries(go_summaries, None);

    let py_src = b"def main():\n    x = fetch_env()\n    os.system(x)\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, entry, local) = parse_lang(py_src, "python", py_lang);

    // Without interop: no findings
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Python,
        "main.py",
        &[],
    );
    assert!(findings.is_empty(), "No cross-lang without interop");

    // With interop
    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Python,
            caller_namespace: "main.py".into(),
            caller_func: "main".into(),
            callee_symbol: "fetch_env".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Go,
            namespace: "lib.go".into(),
            name: "fetch_env".into(),
            arity: Some(0),
        },
        arg_map: vec![],
        ret_taints: true,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Python,
        "main.py",
        &edges,
    );
    assert_eq!(findings.len(), 1, "Go source → Python sink via interop");
}

// ── Scenario 3: Rust sanitizer applied in JavaScript context via interop ──
#[test]
fn cross_lang_rust_sanitizer_in_js_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let rs_src = br#"
        fn clean_shell(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
    "#;
    let rs_lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let rs_summaries = extract_lang_summaries(rs_src, "rust", rs_lang, "lib.rs");
    let global = merge_summaries(rs_summaries, None);

    // JS: source → Rust sanitizer → shell sink
    let js_src = b"function main() {\n  let x = document.location();\n  let y = clean_shell(x);\n  eval(y);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, local) = parse_lang(js_src, "javascript", js_lang);

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "clean_shell".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "clean_shell".into(),
            arity: Some(1),
        },
        arg_map: vec![],
        ret_taints: true,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
    );
    assert!(
        findings.is_empty(),
        "Rust SHELL_ESCAPE sanitizer should neutralise taint via interop"
    );
}

// ── Scenario 4: C sink function called from Java via interop ─────────────
#[test]
fn cross_lang_c_sink_called_from_java_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let c_src = b"void run_cmd(char* cmd) {\n  system(cmd);\n}\n";
    let c_lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let c_summaries = extract_lang_summaries(c_src, "c", c_lang, "native.c");
    let global = merge_summaries(c_summaries, None);

    let java_src = b"class Main {\n  void main() {\n    String x = System.getenv(\"INPUT\");\n    run_cmd(x);\n  }\n}\n";
    let java_lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, entry, local) = parse_lang(java_src, "java", java_lang);

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Java,
            caller_namespace: "Main.java".into(),
            caller_func: "main".into(),
            callee_symbol: "run_cmd".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::C,
            namespace: "native.c".into(),
            name: "run_cmd".into(),
            arity: Some(0), // C param extraction yields 0 (pre-existing limitation)
        },
        arg_map: vec![],
        ret_taints: false,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Java,
        "Main.java",
        &edges,
    );
    assert_eq!(findings.len(), 1, "Java source → C sink via interop");
}

// ── Scenario 5: Multi-language summary merge with interop ────────────────
#[test]
fn cross_lang_three_languages_merged_summaries_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    // Python: source function
    let py_src = b"def get_secret():\n    x = os.getenv(\"SECRET\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "source.py");

    // C: sink function
    let c_src = b"void run_dangerous(char* cmd) {\n  system(cmd);\n}\n";
    let c_lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let c_sums = extract_lang_summaries(c_src, "c", c_lang, "native.c");

    // Rust: sanitizer function
    let rs_src = br#"
        fn make_safe(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
    "#;
    let rs_lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let rs_sums = extract_lang_summaries(rs_src, "rust", rs_lang, "lib.rs");

    let all_sums: Vec<_> = py_sums.into_iter().chain(c_sums).chain(rs_sums).collect();
    let global = merge_summaries(all_sums, None);

    // Go caller: source → sanitizer → sink (all cross-language)
    let go_src = b"package main\n\nfunc main() {\n\tx := get_secret()\n\ty := make_safe(x)\n\trun_dangerous(y)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry, local) = parse_lang(go_src, "go", go_lang);

    let edges = vec![
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "get_secret".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Python,
                namespace: "source.py".into(),
                name: "get_secret".into(),
                arity: Some(0),
            },
            arg_map: vec![],
            ret_taints: true,
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "make_safe".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Rust,
                namespace: "lib.rs".into(),
                name: "make_safe".into(),
                arity: Some(1),
            },
            arg_map: vec![],
            ret_taints: true,
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_dangerous".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::C,
                namespace: "native.c".into(),
                name: "run_dangerous".into(),
                arity: Some(0), // C param extraction yields 0 (pre-existing limitation)
            },
            arg_map: vec![],
            ret_taints: false,
        },
    ];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
    );
    assert!(
        findings.is_empty(),
        "source(Py) → sanitizer(Rs) → sink(C) via interop should be safe; got {} findings",
        findings.len()
    );
}

// ── Scenario 6: Same flow without sanitizer should flag via interop ──────
#[test]
fn cross_lang_three_languages_unsanitised_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let py_src = b"def get_secret():\n    x = os.getenv(\"SECRET\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "source.py");

    let c_src = b"void run_dangerous(char* cmd) {\n  system(cmd);\n}\n";
    let c_lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let c_sums = extract_lang_summaries(c_src, "c", c_lang, "native.c");

    let all_sums: Vec<_> = py_sums.into_iter().chain(c_sums).collect();
    let global = merge_summaries(all_sums, None);

    // Go caller: source → sink directly (no sanitizer)
    let go_src = b"package main\n\nfunc main() {\n\tx := get_secret()\n\trun_dangerous(x)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry, local) = parse_lang(go_src, "go", go_lang);

    let edges = vec![
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "get_secret".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Python,
                namespace: "source.py".into(),
                name: "get_secret".into(),
                arity: Some(0),
            },
            arg_map: vec![],
            ret_taints: true,
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_dangerous".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::C,
                namespace: "native.c".into(),
                name: "run_dangerous".into(),
                arity: Some(0), // C param extraction yields 0 (pre-existing limitation)
            },
            arg_map: vec![],
            ret_taints: false,
        },
    ];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
    );
    assert_eq!(
        findings.len(),
        1,
        "source(Py) → sink(C) without sanitizer via interop"
    );
}

// ── Scenario 7: Name collision across languages stays separate ───────────
#[test]
fn cross_lang_name_collision_stays_separate() {
    use crate::summary::merge_summaries;

    // Python version: source
    let py_src = b"def process_data():\n    x = os.getenv(\"DATA\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "handler.py");

    // C version: benign passthrough (constructed manually)
    let c_summary = crate::summary::FuncSummary {
        name: "process_data".into(),
        file_path: "handler.c".into(),
        lang: "c".into(),
        param_count: 1,
        param_names: vec!["s".into()],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagates_taint: true,
        tainted_sink_params: vec![],
        callees: vec![],
    };

    let all_sums: Vec<_> = py_sums
        .into_iter()
        .chain(std::iter::once(c_summary))
        .collect();
    let global = merge_summaries(all_sums, None);

    // Verify they are stored under different FuncKeys
    let py_matches = global.lookup_same_lang(Lang::Python, "process_data");
    let c_matches = global.lookup_same_lang(Lang::C, "process_data");
    assert_eq!(py_matches.len(), 1, "Python version stored separately");
    assert_eq!(c_matches.len(), 1, "C version stored separately");

    // Python's source_caps should NOT bleed into C
    assert!(py_matches[0].1.source_caps != 0, "Python has source caps");
    assert_eq!(
        c_matches[0].1.source_caps, 0,
        "C should NOT get Python's source caps"
    );
}

// ── Scenario 8: Ruby passthrough in JS via interop ───────────────────────
#[test]
fn cross_lang_ruby_passthrough_in_js_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Ruby,
        namespace: "helper.rb".into(),
        name: "transform".into(),
        arity: Some(1),
    };
    global.insert(
        key.clone(),
        FuncSummary {
            name: "transform".into(),
            file_path: "helper.rb".into(),
            lang: "ruby".into(),
            param_count: 1,
            param_names: vec!["data".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: true,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    let js_src = b"function main() {\n  let x = document.location();\n  let y = transform(x);\n  eval(y);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, local) = parse_lang(js_src, "javascript", js_lang);

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "transform".into(),
            ordinal: 0,
        },
        to: key,
        arg_map: vec![],
        ret_taints: true,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
    );
    assert_eq!(
        findings.len(),
        1,
        "taint should propagate through cross-lang passthrough via interop"
    );
}

// ── Scenario 9: PHP source → Go sink via interop ─────────────────────────
#[test]
fn cross_lang_php_source_to_go_sink_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::{FuncSummary, merge_summaries};

    let php_summary = FuncSummary {
        name: "read_input".into(),
        file_path: "input.php".into(),
        lang: "php".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec!["file_get_contents".into()],
    };

    let global = merge_summaries(vec![php_summary], None);

    let go_src = b"package main\n\nfunc main() {\n\tx := read_input()\n\texec.Command(x)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry, local) = parse_lang(go_src, "go", go_lang);

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Go,
            caller_namespace: "main.go".into(),
            caller_func: "main".into(),
            callee_symbol: "read_input".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Php,
            namespace: "input.php".into(),
            name: "read_input".into(),
            arity: Some(0),
        },
        arg_map: vec![],
        ret_taints: true,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
    );
    assert_eq!(findings.len(), 1, "PHP source → Go sink via interop");
}

// ── Scenario 10: Wrong sanitizer caps still wrong across languages ───────
#[test]
fn cross_lang_wrong_sanitizer_still_flags_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "sanitizers.py".into(),
        name: "html_clean".into(),
        arity: Some(1),
    };
    global.insert(
        key.clone(),
        FuncSummary {
            name: "html_clean".into(),
            file_path: "sanitizers.py".into(),
            lang: "python".into(),
            param_count: 1,
            param_names: vec!["text".into()],
            source_caps: 0,
            sanitizer_caps: Cap::HTML_ESCAPE.bits(),
            sink_caps: 0,
            propagates_taint: true,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    // JS: source → Python HTML sanitizer → shell sink
    let js_src = b"function main() {\n  let x = document.location();\n  let y = html_clean(x);\n  eval(y);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, local) = parse_lang(js_src, "javascript", js_lang);

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "html_clean".into(),
            ordinal: 0,
        },
        to: key,
        arg_map: vec![],
        ret_taints: true,
    }];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
    );
    assert_eq!(
        findings.len(),
        1,
        "wrong cross-language sanitizer should NOT neutralise"
    );
}

// ── Scenario 11: Summary lang field preserved (different FuncKeys) ───────
#[test]
fn cross_lang_summary_preserves_lang_metadata() {
    use crate::summary::merge_summaries;

    let py_summary = crate::summary::FuncSummary {
        name: "helper".into(),
        file_path: "lib.py".into(),
        lang: "python".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };

    let js_summary = crate::summary::FuncSummary {
        name: "helper".into(),
        file_path: "lib.js".into(),
        lang: "javascript".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: Cap::SHELL_ESCAPE.bits(),
        propagates_taint: true,
        tainted_sink_params: vec![0],
        callees: vec![],
    };

    let global = merge_summaries(vec![py_summary, js_summary], None);

    // They are now separate entries — not merged
    let py_matches = global.lookup_same_lang(Lang::Python, "helper");
    let js_matches = global.lookup_same_lang(Lang::JavaScript, "helper");

    assert_eq!(py_matches.len(), 1, "Python helper stored separately");
    assert_eq!(js_matches.len(), 1, "JS helper stored separately");
    assert!(
        py_matches[0].1.source_caps != 0,
        "Python source caps preserved"
    );
    assert!(js_matches[0].1.sink_caps != 0, "JS sink caps preserved");
    assert!(
        js_matches[0].1.propagates_taint,
        "JS propagates_taint preserved"
    );
}

// ── Scenario 12: Full pipeline Python lib + JS caller via interop ────────
#[test]
fn cross_lang_full_pipeline_python_lib_js_caller_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    // Python library: defines dangerous_query() that reads from os.getenv
    let py_src = b"def dangerous_query():\n    x = os.getenv(\"SQL\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "db.py");

    // JavaScript library: defines run_query() that calls eval (a sink)
    let js_lib_src = b"function run_query(q) {\n  eval(q);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let js_sums = extract_lang_summaries(js_lib_src, "javascript", js_lang, "db.js");

    let all_sums: Vec<_> = py_sums.into_iter().chain(js_sums).collect();
    let global = merge_summaries(all_sums, None);

    // Go caller: dangerous_query() → run_query()
    let go_src = b"package main\n\nfunc main() {\n\tq := dangerous_query()\n\trun_query(q)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry, local) = parse_lang(go_src, "go", go_lang);

    let edges = vec![
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "dangerous_query".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Python,
                namespace: "db.py".into(),
                name: "dangerous_query".into(),
                arity: Some(0),
            },
            arg_map: vec![],
            ret_taints: true,
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_query".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::JavaScript,
                namespace: "db.js".into(),
                name: "run_query".into(),
                arity: Some(1),
            },
            arg_map: vec![],
            ret_taints: false,
        },
    ];
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
    );
    assert_eq!(
        findings.len(),
        1,
        "Python source → JS sink via Go caller via interop"
    );
}

// ── New tests: ambiguous resolution, interop edge specificity ────────────

#[test]
fn ambiguous_resolution_returns_none() {
    use crate::summary::FuncSummary;

    // Two same-lang functions, same name + arity, different namespaces
    let mut global = GlobalSummaries::new();
    for ns in &["a.rs", "b.rs"] {
        let key = FuncKey {
            lang: Lang::Rust,
            namespace: (*ns).to_string(),
            name: "helper".into(),
            arity: Some(0),
        };
        global.insert(
            key,
            FuncSummary {
                name: "helper".into(),
                file_path: (*ns).to_string(),
                lang: "rust".into(),
                param_count: 0,
                param_names: vec![],
                source_caps: Cap::all().bits(),
                sanitizer_caps: 0,
                sink_caps: 0,
                propagates_taint: false,
                tainted_sink_params: vec![],
                callees: vec![],
            },
        );
    }

    // Caller from c.rs calls helper() — ambiguous (two matches, neither is caller's namespace)
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = helper();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let (cfg, entry, local) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &local, Some(&global), Lang::Rust, "c.rs", &[]);

    // Ambiguous resolution returns None → no source → no finding
    assert!(
        findings.is_empty(),
        "ambiguous resolution (two namespaces) should return None → no finding"
    );
}

#[test]
fn exact_namespace_match_wins() {
    use crate::summary::FuncSummary;

    // Same name in two namespaces, but one matches caller's namespace
    let mut global = GlobalSummaries::new();
    // test.rs version: source
    let key_local = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "helper".into(),
        arity: Some(0),
    };
    global.insert(
        key_local,
        FuncSummary {
            name: "helper".into(),
            file_path: "test.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );
    // other.rs version: no caps
    let key_other = FuncKey {
        lang: Lang::Rust,
        namespace: "other.rs".into(),
        name: "helper".into(),
        arity: Some(0),
    };
    global.insert(
        key_other,
        FuncSummary {
            name: "helper".into(),
            file_path: "other.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    let src = br#"
        use std::process::Command;
        fn main() {
            let x = helper();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let (cfg, entry, local) = parse_rust(src);
    // caller_namespace = "test.rs" matches the source version
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
    );

    assert_eq!(
        findings.len(),
        1,
        "exact namespace match should resolve to the source version"
    );
}

#[test]
fn interop_edge_wrong_caller_lang_no_match() {
    use crate::interop::CallSiteKey;
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "lib.py".into(),
        name: "get_data".into(),
        arity: Some(0),
    };
    global.insert(
        key.clone(),
        FuncSummary {
            name: "get_data".into(),
            file_path: "lib.py".into(),
            lang: "python".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
        },
    );

    // Edge specifies Python caller, but we're calling from JavaScript
    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Python, // wrong!
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "get_data".into(),
            ordinal: 0,
        },
        to: key,
        arg_map: vec![],
        ret_taints: true,
    }];

    let js_src = b"function main() {\n  let x = get_data();\n  eval(x);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, local) = parse_lang(js_src, "javascript", js_lang);
    let findings = analyse_file(
        &cfg,
        entry,
        &local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
    );

    assert!(
        findings.is_empty(),
        "Edge for wrong caller_lang should not match"
    );
}

#[test]
fn return_call_recognized_as_source() {
    use crate::cfg::{build_cfg, export_summaries};
    use tree_sitter::Language;

    // fn foo() -> String { env::var("X").unwrap() }
    // The return statement contains a call to env::var which should be
    // recognized as a source after the return-call fix.
    let src = br#"
        use std::env;
        fn foo() -> String {
            env::var("X").unwrap()
        }
    "#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let (_, _, summaries) = build_cfg(&tree, src, "rust", "test.rs");
    let exported = export_summaries(&summaries, "test.rs", "rust");

    let foo = exported
        .iter()
        .find(|s| s.name == "foo")
        .expect("foo should exist");
    assert!(
        foo.source_caps != 0,
        "foo() should have source_caps set because env::var is called inside return"
    );
}
