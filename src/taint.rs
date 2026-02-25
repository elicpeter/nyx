use crate::cfg::{Cfg, FuncSummaries, NodeInfo, StmtKind};
use crate::labels::{Cap, DataLabel};
use crate::summary::GlobalSummaries;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;
use tracing::debug;

/// A detected taint finding with both source and sink locations.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The CFG node where tainted data reaches a dangerous operation.
    pub sink: NodeIndex,
    /// The CFG node where taint originated (may be Entry if source is
    /// cross-file and couldn't be pinpointed to a specific node).
    pub source: NodeIndex,
    /// The full path from source to sink through the CFG.
    #[allow(dead_code)] // used for future detailed diagnostics / path display
    pub path: Vec<NodeIndex>,
}

fn taint_hash(taint: &HashMap<String, Cap>) -> u64 {
    let mut v: Vec<_> = taint.iter().collect();
    v.sort_by_key(|(k, _)| k.as_str());
    let mut hasher = blake3::Hasher::new();
    for (k, bits) in v {
        hasher.update(k.as_bytes());
        hasher.update(&bits.bits().to_le_bytes());
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(digest.as_bytes()[0..8].try_into().unwrap())
}

/// Resolved summary for a callee — a uniform view regardless of whether the
/// summary came from a local (same‑file) or global (cross‑file) source.
struct ResolvedSummary {
    source_caps: Cap,
    sanitizer_caps: Cap,
    sink_caps: Cap,
    propagates_taint: bool,
}

/// Try to resolve a callee name against local summaries first, then global.
///
/// Local wins because it is always more precise (built from the same parse).
fn resolve_callee(
    callee: &str,
    local: &FuncSummaries,
    global: Option<&GlobalSummaries>,
) -> Option<ResolvedSummary> {
    // 1) Local
    if let Some(ls) = local.get(callee) {
        return Some(ResolvedSummary {
            source_caps: ls.source_caps,
            sanitizer_caps: ls.sanitizer_caps,
            sink_caps: ls.sink_caps,
            propagates_taint: ls.propagates_taint,
        });
    }

    // 2) Global (cross-file)
    if let Some(gs) = global
        && let Some(fs) = gs.get(callee)
    {
        return Some(ResolvedSummary {
            source_caps: fs.source_caps(),
            sanitizer_caps: fs.sanitizer_caps(),
            sink_caps: fs.sink_caps(),
            propagates_taint: fs.propagates_taint,
        });
    }

    None
}

fn apply_taint(
    node: &NodeInfo,
    taint: &HashMap<String, Cap>,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> HashMap<String, Cap> {
    debug!(target: "taint", "Applying taint to node: {:?}", node);
    debug!(target: "taint", "Taint: {:?}", taint);
    let mut out = taint.clone();

    match node.label {
        // A new untrusted value enters the program
        Some(DataLabel::Source(bits)) => {
            if let Some(v) = &node.defines {
                out.insert(v.clone(), bits);
            }
        }
        // Sanitizer: propagate input taint through the assignment FIRST,
        // then strip the sanitizer's capability bits.  This ensures that
        // `let y = sanitize_html(&x)` gives y the taint of x minus the
        // HTML_ESCAPE bit — rather than leaving y completely clean (which
        // would hide "wrong sanitiser for this sink" bugs).
        Some(DataLabel::Sanitizer(bits)) => {
            if let Some(v) = &node.defines {
                // 1. Propagate: union taint from all read variables
                let mut combined = Cap::empty();
                for u in &node.uses {
                    if let Some(b) = out.get(u) {
                        combined |= *b;
                    }
                }
                // 2. Strip the sanitiser's bits
                let new = combined & !bits;
                if new.is_empty() {
                    out.remove(v);
                } else {
                    out.insert(v.clone(), new);
                }
            }
        }

        // A function call — resolve against local + global summaries
        _ if node.kind == StmtKind::Call => {
            if let Some(callee) = &node.callee
                && let Some(resolved) = resolve_callee(callee, local_summaries, global_summaries)
            {
                // Build the return value's taint bits in stages, then
                // write once at the end.  Order matters:
                //
                //   1. Start with fresh source taint (if the callee is a source)
                //   2. Union with propagated arg taint (if the callee propagates)
                //   3. Strip sanitizer bits last (so sanitization always wins)

                let mut return_bits = Cap::empty();

                // ── 1. Source behaviour ──
                return_bits |= resolved.source_caps;

                // ── 2. Propagation ──
                if resolved.propagates_taint {
                    for u in &node.uses {
                        if let Some(bits) = out.get(u) {
                            return_bits |= *bits;
                        }
                    }
                }

                // ── 3. Sanitizer behaviour (applied last so it always wins) ──
                return_bits &= !resolved.sanitizer_caps;

                // ── Write the result ──
                if let Some(v) = &node.defines {
                    if return_bits.is_empty() {
                        out.remove(v);
                    } else {
                        out.insert(v.clone(), return_bits);
                    }
                }

                // ── Sink behaviour: handled in the main analysis loop
                //    (checked via node.label or resolved summary) ──

                return out;
            }

            // Unresolved call — fall through to default gen/kill below
        }

        // All other statements: classic gen/kill for assignments
        _ => {}
    }

    // Default gen/kill: propagate taint through variable assignments
    if !matches!(node.label, Some(DataLabel::Source(_)) | Some(DataLabel::Sanitizer(_)))
        && let Some(d) = &node.defines
    {
        let mut combined = Cap::empty();
        for u in &node.uses {
            if let Some(bits) = out.get(u) {
                combined |= *bits;
            }
        }
        if combined.is_empty() {
            out.remove(d);
        } else {
            out.insert(d.clone(), combined);
        }
    }

    out
}

/// Run taint analysis on a single file's CFG.
///
/// `global_summaries` is `None` for pass‑1 / single‑file mode and
/// `Some(&map)` for pass‑2 cross‑file analysis.
pub fn analyse_file(
    cfg: &Cfg,
    entry: NodeIndex,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> Vec<Finding> {
    use std::collections::{HashMap, HashSet, VecDeque};

    /// Queue item: current CFG node + taint map that holds here
    #[derive(Clone)]
    struct Item {
        node: NodeIndex,
        taint: HashMap<String, Cap>,
    }

    // (node, taint_hash)  →  predecessor key   (for path rebuild)
    type Key = (NodeIndex, u64);
    let mut pred: HashMap<Key, Key> = HashMap::new();

    // Seen states so we do not revisit them infinitely
    let mut seen: HashSet<Key> = HashSet::new();

    // Resulting findings: (sink_node, source_node, full_path)
    let mut findings: Vec<Finding> = Vec::new();

    let mut q = VecDeque::new();
    q.push_back(Item {
        node: entry,
        taint: HashMap::new(),
    });
    seen.insert((entry, 0));

    while let Some(Item { node, taint }) = q.pop_front() {
        let out = apply_taint(&cfg[node], &taint, local_summaries, global_summaries);

        // ── Sink check ──────────────────────────────────────────────────
        // Two ways a node can be a sink:
        //   1. Its AST label says Sink (existing inline labels)
        //   2. Its callee resolves to a function with sink_caps (cross-file)
        let sink_caps = match cfg[node].label {
            Some(DataLabel::Sink(caps)) => caps,
            _ => {
                // check if callee resolves to a sink
                cfg[node]
                    .callee
                    .as_ref()
                    .and_then(|c| resolve_callee(c, local_summaries, global_summaries))
                    .filter(|r| !r.sink_caps.is_empty())
                    .map(|r| r.sink_caps)
                    .unwrap_or(Cap::empty())
            }
        };

        if !sink_caps.is_empty() {
            let bad = cfg[node].uses.iter().any(|u| {
                out.get(u)
                    .is_some_and(|b| (*b & sink_caps) != Cap::empty())
            });
            if bad {
                // Reconstruct path backwards from sink to source.
                //
                // A node is considered a "source" if:
                //   1. It has an inline DataLabel::Source (same-file), OR
                //   2. It is a Call whose callee resolves to a source via
                //      local or global summaries (cross-file).
                let sink_node = node;
                let mut path = vec![node];
                let mut source_node = node; // fallback: sink itself
                let mut key = (node, taint_hash(&taint));

                while let Some(&(prev, prev_hash)) = pred.get(&key) {
                    path.push(prev);

                    // Check inline source label
                    if matches!(cfg[prev].label, Some(DataLabel::Source(_))) {
                        source_node = prev;
                        break;
                    }

                    // Check cross-file source via resolved callee summary
                    if cfg[prev].kind == StmtKind::Call
                        && let Some(callee) = &cfg[prev].callee
                        && let Some(resolved) =
                            resolve_callee(callee, local_summaries, global_summaries)
                        && !resolved.source_caps.is_empty()
                    {
                        source_node = prev;
                        break;
                    }

                    key = (prev, prev_hash);
                }

                path.reverse();
                findings.push(Finding {
                    sink: sink_node,
                    source: source_node,
                    path,
                });
            }
        }

        // enqueue successors
        for succ in cfg.neighbors(node) {
            let h = taint_hash(&out);
            let key = (succ, h);
            if !seen.contains(&key) {
                seen.insert(key);
                pred.insert(key, (node, taint_hash(&taint)));
                let item = Item {
                    node: succ,
                    taint: out.clone(),
                };
                q.push_back(item);
            }
        }
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);

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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);

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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert!(findings.is_empty(), "matching sanitizer should kill the taint");
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "only the unsanitised source should be flagged");
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 2, "both should be flagged — wrong sanitiser");
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert!(findings.is_empty());
}

#[test]
fn cross_file_source_resolved_via_global_summaries() {
    use crate::cfg::build_cfg;
    use crate::summary::{FuncSummary, GlobalSummaries};
    use tree_sitter::Language;

    // Simulate file B calling `get_dangerous()` which is defined in file A.
    // File A's summary says get_dangerous is a Source(all).
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = get_dangerous();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, local_summaries) = build_cfg(&tree, src, "rust");

    // Build global summaries as if file A exported get_dangerous
    let mut global = GlobalSummaries::new();
    global.insert(
        "get_dangerous".into(),
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

    let findings = analyse_file(&cfg, entry, &local_summaries, Some(&global));
    assert_eq!(findings.len(), 1, "cross-file source should be detected");
}

#[test]
fn cross_file_sanitizer_resolved_via_global_summaries() {
    use crate::cfg::build_cfg;
    use crate::summary::{FuncSummary, GlobalSummaries};
    use tree_sitter::Language;

    // File B gets tainted data and passes it through `my_sanitize()` from file A.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = my_sanitize(x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, local_summaries) = build_cfg(&tree, src, "rust");

    let mut global = GlobalSummaries::new();
    global.insert(
        "my_sanitize".into(),
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

    let findings = analyse_file(&cfg, entry, &local_summaries, Some(&global));
    assert!(
        findings.is_empty(),
        "cross-file sanitizer should neutralise taint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Shared test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse Rust source bytes → (cfg, entry, local_summaries)
#[cfg(test)]
fn parse_rust(src: &[u8]) -> (Cfg, NodeIndex, FuncSummaries) {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    build_cfg(&tree, src, "rust")
}

/// Parse Rust source bytes, build CFG, and export cross-file summaries.
#[cfg(test)]
fn extract_summaries_from_bytes(src: &[u8], path: &str) -> Vec<crate::summary::FuncSummary> {
    use crate::cfg::export_summaries;
    let (_, _, local) = parse_rust(src);
    export_summaries(&local, path, "rust")
}

#[test]
fn cross_file_sink_resolved_via_global_summaries() {
    use crate::cfg::build_cfg;
    use crate::summary::{FuncSummary, GlobalSummaries};
    use tree_sitter::Language;

    // File B calls `dangerous_exec(x)` from file A which is a sink.
    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("INPUT").unwrap();
            dangerous_exec(x);
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry, local_summaries) = build_cfg(&tree, src, "rust");

    let mut global = GlobalSummaries::new();
    global.insert(
        "dangerous_exec".into(),
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

    let findings = analyse_file(&cfg, entry, &local_summaries, Some(&global));
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
    let global = merge_summaries(summaries);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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
    let global = merge_summaries(summaries);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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
    let global = merge_summaries(summaries);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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
    let global = merge_summaries(summaries);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

    assert_eq!(
        findings.len(),
        1,
        "cross-file sink should be detected"
    );
}

#[test]
fn multi_file_passthrough_preserves_taint() {
    use crate::summary::{FuncSummary, GlobalSummaries};

    // identity() just returns its argument — it propagates taint but has no
    // source/sanitizer/sink caps of its own.  We construct this summary
    // manually because the CFG's lightweight dataflow doesn't track simple
    // passthrough without explicit labels.
    let mut global = GlobalSummaries::new();
    global.insert(
        "identity".into(),
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
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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
    let global = merge_summaries(summaries);

    let (cfg, entry, local) = parse_rust(caller_src);
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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
    // Source(ALL) → shell_escape → println (HTML sink).
    // shell_escape strips SHELL_ESCAPE but not HTML_ESCAPE.
    // println is an HTML sink — HTML_ESCAPE bit is still set → 1 finding.
    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            println!("{}", clean);
        }
    "#;

    let (cfg, entry, summaries) = parse_rust(src);
    let findings = analyse_file(&cfg, entry, &summaries, None);

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
    let findings = analyse_file(&cfg, entry, &summaries, None);

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
    let findings = analyse_file(&cfg, entry, &summaries, None);

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
    let findings = analyse_file(&cfg, entry, &summaries, None);

    assert!(
        findings.is_empty(),
        "untainted literal should not trigger a finding"
    );
}

#[test]
fn local_summary_takes_precedence_over_global() {
    use crate::summary::{FuncSummary, GlobalSummaries};

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
    global.insert(
        "my_func".into(),
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
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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

    let findings_none = analyse_file(&cfg, entry, &summaries, None);
    let empty = crate::summary::GlobalSummaries::new();
    let findings_empty = analyse_file(&cfg, entry, &summaries, Some(&empty));

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
    let findings = analyse_file(&cfg, entry, &summaries, None);

    assert!(
        findings.is_empty(),
        "unknown function call should not introduce taint"
    );
}

#[test]
fn source_and_sink_on_same_function() {
    use crate::summary::{FuncSummary, GlobalSummaries};

    // Cross-file function that is both source AND sink.
    // Tainted arg hits sink → 1 finding.
    let mut global = GlobalSummaries::new();
    global.insert(
        "source_and_sink".into(),
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
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

    assert_eq!(
        findings.len(),
        1,
        "function that is both source and sink should detect tainted arg as finding"
    );
}

#[test]
fn multiple_cross_file_sources_one_sanitised() {
    use crate::summary::{FuncSummary, GlobalSummaries};

    let mut global = GlobalSummaries::new();
    // Two cross-file sources
    global.insert(
        "get_secret".into(),
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
    global.insert(
        "get_other_secret".into(),
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
    let findings = analyse_file(&cfg, entry, &local, Some(&global));

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
#[cfg(test)]
fn parse_lang(src: &[u8], slug: &str, ts_lang: tree_sitter::Language) -> (Cfg, NodeIndex, FuncSummaries) {
    use crate::cfg::build_cfg;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    build_cfg(&tree, src, slug)
}

#[test]
fn js_source_to_sink() {
    let src = b"function main() {\n  let x = document.location();\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "js", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "JS: source->sink should produce 1 finding");
}

#[test]
fn ts_source_to_sink() {
    let src = b"function main() {\n  let x = document.location();\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let (cfg, entry, summaries) = parse_lang(src, "ts", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "TS: source->sink should produce 1 finding");
}


#[test]
fn python_source_to_sink() {
    let src = b"def main():\n    x = os.getenv(\"SECRET\")\n    os.system(x)\n";
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "python", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "Python: source->sink should produce 1 finding");
}

#[test]
fn go_source_to_sink() {
    let src = b"package main\n\nfunc main() {\n\tx := os.Getenv(\"SECRET\")\n\texec.Command(x)\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "go", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "Go: source->sink should produce 1 finding");
}

#[test]
fn java_source_to_sink() {
    let src = b"class Main {\n  void main() {\n    String x = System.getenv(\"SECRET\");\n    Runtime.exec(x);\n  }\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "java", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "Java: source->sink should produce 1 finding");
}

#[test]
fn c_source_to_sink() {
    let src = b"void main() {\n  char* x = getenv(\"SECRET\");\n  system(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "c", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "C: source->sink should produce 1 finding");
}

#[test]
fn cpp_source_to_sink() {
    let src = b"void main() {\n  char* x = getenv(\"SECRET\");\n  system(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "cpp", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "C++: source->sink should produce 1 finding");
}

#[test]
fn php_source_to_sink() {
    let src = b"<?php\nfunction main() {\n  $x = file_get_contents(\"secret\");\n  system($x);\n}\n?>";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let (cfg, entry, summaries) = parse_lang(src, "php", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "PHP: source->sink should produce 1 finding");
}

#[test]
fn ruby_source_to_sink() {
    let src = b"def main\n  x = gets()\n  system(x)\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, entry, summaries) = parse_lang(src, "ruby", lang);
    let findings = analyse_file(&cfg, entry, &summaries, None);
    assert_eq!(findings.len(), 1, "Ruby: source->sink should produce 1 finding");
}
