use crate::cfg::{build_cfg, export_summaries};
use crate::cfg_analysis;
use crate::commands::scan::Diag;
use crate::errors::{NyxError, NyxResult};
use crate::labels::build_lang_rules;
use crate::patterns::Severity;
use crate::summary::{FuncSummary, GlobalSummaries};
use crate::symbol::{Lang, normalize_namespace};
use crate::taint::analyse_file;
use crate::utils::config::AnalysisMode;
use crate::utils::ext::lowercase_ext;
use crate::utils::{Config, query_cache};
use std::cell::RefCell;
use std::path::Path;
use tree_sitter::{Language, QueryCursor, StreamingIterator};

thread_local! {
    static PARSER: RefCell<tree_sitter::Parser> = RefCell::new(tree_sitter::Parser::new());
}

/// Convenience alias for node indices.
fn byte_offset_to_point(tree: &tree_sitter::Tree, byte: usize) -> tree_sitter::Point {
    tree.root_node()
        .descendant_for_byte_range(byte, byte)
        .map(|n| n.start_position())
        .unwrap_or_else(|| tree_sitter::Point { row: 0, column: 0 })
}

/// Resolve a file extension to a (tree‑sitter Language, slug) pair.
fn lang_for_path(path: &Path) -> Option<(Language, &'static str)> {
    match lowercase_ext(path) {
        Some("rs") => Some((Language::from(tree_sitter_rust::LANGUAGE), "rust")),
        Some("c") => Some((Language::from(tree_sitter_c::LANGUAGE), "c")),
        Some("cpp") => Some((Language::from(tree_sitter_cpp::LANGUAGE), "cpp")),
        Some("java") => Some((Language::from(tree_sitter_java::LANGUAGE), "java")),
        Some("go") => Some((Language::from(tree_sitter_go::LANGUAGE), "go")),
        Some("php") => Some((Language::from(tree_sitter_php::LANGUAGE_PHP), "php")),
        Some("py") => Some((Language::from(tree_sitter_python::LANGUAGE), "python")),
        Some("ts") => Some((
            Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
            "typescript",
        )),
        Some("js") => Some((
            Language::from(tree_sitter_javascript::LANGUAGE),
            "javascript",
        )),
        Some("rb") => Some((Language::from(tree_sitter_ruby::LANGUAGE), "ruby")),
        _ => None,
    }
}

/// Fast binary-file guard: skip if >1% NUL bytes.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().filter(|b| **b == 0).count() * 100 / bytes.len().max(1) > 1
}

// ─────────────────────────────────────────────────────────────────────────────
//  Pass 1: Extract function summaries (no taint analysis)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract function summaries from pre-read bytes.
///
/// This is the core **pass 1** implementation. Callers that already hold the
/// file contents should use this variant to avoid a redundant `fs::read`.
pub fn extract_summaries_from_bytes(
    bytes: &[u8],
    path: &Path,
    _cfg: &Config,
) -> NyxResult<Vec<FuncSummary>> {
    let _span = tracing::debug_span!("extract_summaries", file = %path.display()).entered();
    if is_binary(bytes) {
        return Ok(vec![]);
    }

    let Some((ts_lang, lang_slug)) = lang_for_path(path) else {
        return Ok(vec![]);
    };

    let tree = PARSER.with(|cell| {
        let mut parser = cell.borrow_mut();
        parser.set_language(&ts_lang)?;
        parser
            .parse(bytes, None)
            .ok_or_else(|| NyxError::Other("tree-sitter failed".into()))
    })?;

    let file_path_str = path.to_string_lossy();
    let lang_rules = build_lang_rules(_cfg, lang_slug);
    let rules_ref = if lang_rules.extra_labels.is_empty()
        && lang_rules.terminators.is_empty()
        && lang_rules.event_handlers.is_empty()
    {
        None
    } else {
        Some(&lang_rules)
    };
    let (_cfg_graph, _entry, local_summaries) =
        build_cfg(&tree, bytes, lang_slug, &file_path_str, rules_ref);

    Ok(export_summaries(
        &local_summaries,
        &file_path_str,
        lang_slug,
    ))
}

/// Convenience wrapper that reads the file then delegates to
/// [`extract_summaries_from_bytes`].
#[allow(dead_code)] // used by benchmarks and lib consumers
pub fn extract_summaries_from_file(path: &Path, cfg: &Config) -> NyxResult<Vec<FuncSummary>> {
    let bytes = std::fs::read(path)?;
    extract_summaries_from_bytes(&bytes, path, cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Pass 2 / single‑file: Full rule execution (AST queries + taint)
// ─────────────────────────────────────────────────────────────────────────────

/// Run all enabled analyses on pre-read bytes and return diagnostics.
///
/// This is the core **pass 2** implementation. Callers that already hold the
/// file contents should use this variant to avoid a redundant `fs::read`.
pub fn run_rules_on_bytes(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> NyxResult<Vec<Diag>> {
    let _span = tracing::debug_span!("run_rules", file = %path.display()).entered();

    if is_binary(bytes) {
        return Ok(vec![]);
    }

    let Some((ts_lang, lang_slug)) = lang_for_path(path) else {
        return Ok(vec![]);
    };

    let _tree = PARSER.with(|cell| {
        let mut parser = cell.borrow_mut();
        parser.set_language(&ts_lang)?;
        parser
            .parse(bytes, None)
            .ok_or_else(|| NyxError::Other("tree-sitter failed".into()))
    })?;

    let mut out = Vec::new();
    let file_path_str = path.to_string_lossy();

    // CFG construction + taint + cfg_analysis only needed for Full/Taint modes.
    let needs_cfg =
        cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Taint;

    if needs_cfg {
        // Build CFG — needed for both taint analysis and CFG structural analyses.
        let lang_rules = build_lang_rules(cfg, lang_slug);
        let rules_ref = if lang_rules.extra_labels.is_empty()
            && lang_rules.terminators.is_empty()
            && lang_rules.event_handlers.is_empty()
        {
            None
        } else {
            Some(&lang_rules)
        };
        let (cfg_graph, entry, summaries) =
            build_cfg(&_tree, bytes, lang_slug, &file_path_str, rules_ref);
        let caller_lang = Lang::from_slug(lang_slug).unwrap_or(Lang::Rust);

        // ── Taint analysis ──────────────────────────────────────────────
        tracing::debug!("Running taint analysis on: {}", path.display());
        tracing::debug!("Func summaries: {:?}", summaries);
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&file_path_str, scan_root_str.as_deref());
        let taint_results = analyse_file(
            &cfg_graph,
            entry,
            &summaries,
            global_summaries,
            caller_lang,
            &namespace,
            &[],
        );
        for finding in &taint_results {
            // Report the SINK location — where the vulnerability manifests.
            let sink_byte = cfg_graph[finding.sink].span.0;
            let sink_point = byte_offset_to_point(&_tree, sink_byte);

            // Include source location in the ID so distinct flows through
            // the same sink (or different sinks at the same line) don't
            // get collapsed by dedup.
            let source_byte = cfg_graph[finding.source].span.0;
            let source_point = byte_offset_to_point(&_tree, source_byte);

            out.push(Diag {
                path: path.to_string_lossy().into_owned(),
                line: sink_point.row + 1,
                col: sink_point.column + 1,
                severity: Severity::High,
                id: format!(
                    "taint-unsanitised-flow (source {}:{})",
                    source_point.row + 1,
                    source_point.column + 1
                ),
            });
        }

        // ── CFG structural analyses ─────────────────────────────────────
        let cfg_ctx = cfg_analysis::AnalysisContext {
            cfg: &cfg_graph,
            entry,
            lang: caller_lang,
            file_path: &file_path_str,
            source_bytes: bytes,
            func_summaries: &summaries,
            global_summaries,
            taint_findings: &taint_results,
            analysis_rules: rules_ref,
        };
        for cf in cfg_analysis::run_all(&cfg_ctx) {
            let point = byte_offset_to_point(&_tree, cf.span.0);
            out.push(Diag {
                path: path.to_string_lossy().into_owned(),
                line: point.row + 1,
                col: point.column + 1,
                severity: cf.severity,
                id: cf.rule_id,
            });
        }
    }

    if cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Ast {
        let root = _tree.root_node();

        let compiled = query_cache::for_lang(lang_slug, ts_lang);
        let mut cursor = QueryCursor::new();

        for cq in compiled.iter() {
            if cfg.scanner.min_severity <= cq.meta.severity {
                continue;
            }
            let mut matches = cursor.matches(&cq.query, root, bytes);
            while let Some(m) = matches.next() {
                if let Some(cap) = m.captures.iter().find(|c| c.index == 0) {
                    let point = cap.node.start_position();
                    out.push(Diag {
                        path: path.to_string_lossy().into_owned(),
                        line: point.row + 1,
                        col: point.column + 1,
                        severity: cq.meta.severity,
                        id: cq.meta.id.to_owned(),
                    });
                }
            }
        }
    }

    // Check to ensure no duplicates
    out.sort_by(|a, b| (a.line, a.col, &a.id, a.severity).cmp(&(b.line, b.col, &b.id, b.severity)));
    out.dedup_by(|a, b| {
        a.line == b.line && a.col == b.col && a.id == b.id && a.severity == b.severity
    });

    Ok(out)
}

/// Convenience wrapper that reads the file then delegates to
/// [`run_rules_on_bytes`].
pub fn run_rules_on_file(
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> NyxResult<Vec<Diag>> {
    let bytes = std::fs::read(path)?;
    run_rules_on_bytes(&bytes, path, cfg, global_summaries, scan_root)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fused single-pass: extract summaries + run full analysis in one parse/CFG
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a fused analysis pass: both function summaries and diagnostics.
pub struct FusedResult {
    pub summaries: Vec<FuncSummary>,
    pub diags: Vec<Diag>,
}

/// Parse the file once, build the CFG once, and produce both function
/// summaries (for cross-file resolution) and full diagnostics (AST queries +
/// taint + CFG structural analyses).
///
/// When `global_summaries` is `None`, the taint engine runs with local
/// context only (equivalent to pass 1 + partial pass 2).  A second call
/// to [`run_taint_only`] can refine findings with the full cross-file view
/// without re-parsing or re-building the CFG.
pub fn analyse_file_fused(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> NyxResult<FusedResult> {
    let _span = tracing::debug_span!("analyse_fused", file = %path.display()).entered();

    if is_binary(bytes) {
        return Ok(FusedResult {
            summaries: vec![],
            diags: vec![],
        });
    }

    let Some((ts_lang, lang_slug)) = lang_for_path(path) else {
        return Ok(FusedResult {
            summaries: vec![],
            diags: vec![],
        });
    };

    let tree = PARSER.with(|cell| {
        let mut parser = cell.borrow_mut();
        parser.set_language(&ts_lang)?;
        parser
            .parse(bytes, None)
            .ok_or_else(|| NyxError::Other("tree-sitter failed".into()))
    })?;

    let file_path_str = path.to_string_lossy();

    // Build language-specific analysis rules once
    let lang_rules = build_lang_rules(cfg, lang_slug);
    let rules_ref = if lang_rules.extra_labels.is_empty()
        && lang_rules.terminators.is_empty()
        && lang_rules.event_handlers.is_empty()
    {
        None
    } else {
        Some(&lang_rules)
    };

    // Build CFG once — used for both summary extraction AND analysis
    let (cfg_graph, entry, local_summaries) =
        build_cfg(&tree, bytes, lang_slug, &file_path_str, rules_ref);

    // Export summaries (always — needed for cross-file merging)
    let summaries = export_summaries(&local_summaries, &file_path_str, lang_slug);

    let mut out = Vec::new();

    // Taint + CFG structural analyses
    let needs_cfg =
        cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Taint;

    if needs_cfg {
        let caller_lang = Lang::from_slug(lang_slug).unwrap_or(Lang::Rust);
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&file_path_str, scan_root_str.as_deref());

        let taint_results = analyse_file(
            &cfg_graph,
            entry,
            &local_summaries,
            global_summaries,
            caller_lang,
            &namespace,
            &[],
        );
        for finding in &taint_results {
            let sink_byte = cfg_graph[finding.sink].span.0;
            let sink_point = byte_offset_to_point(&tree, sink_byte);
            let source_byte = cfg_graph[finding.source].span.0;
            let source_point = byte_offset_to_point(&tree, source_byte);

            out.push(Diag {
                path: path.to_string_lossy().into_owned(),
                line: sink_point.row + 1,
                col: sink_point.column + 1,
                severity: Severity::High,
                id: format!(
                    "taint-unsanitised-flow (source {}:{})",
                    source_point.row + 1,
                    source_point.column + 1
                ),
            });
        }

        let cfg_ctx = cfg_analysis::AnalysisContext {
            cfg: &cfg_graph,
            entry,
            lang: caller_lang,
            file_path: &file_path_str,
            source_bytes: bytes,
            func_summaries: &local_summaries,
            global_summaries,
            taint_findings: &taint_results,
            analysis_rules: rules_ref,
        };
        for cf in cfg_analysis::run_all(&cfg_ctx) {
            let point = byte_offset_to_point(&tree, cf.span.0);
            out.push(Diag {
                path: path.to_string_lossy().into_owned(),
                line: point.row + 1,
                col: point.column + 1,
                severity: cf.severity,
                id: cf.rule_id,
            });
        }
    }

    // AST pattern queries
    if cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Ast {
        let root = tree.root_node();
        let compiled = query_cache::for_lang(lang_slug, ts_lang);
        let mut cursor = QueryCursor::new();

        for cq in compiled.iter() {
            if cfg.scanner.min_severity <= cq.meta.severity {
                continue;
            }
            let mut matches = cursor.matches(&cq.query, root, bytes);
            while let Some(m) = matches.next() {
                if let Some(cap) = m.captures.iter().find(|c| c.index == 0) {
                    let point = cap.node.start_position();
                    out.push(Diag {
                        path: path.to_string_lossy().into_owned(),
                        line: point.row + 1,
                        col: point.column + 1,
                        severity: cq.meta.severity,
                        id: cq.meta.id.to_owned(),
                    });
                }
            }
        }
    }

    // Dedup
    out.sort_by(|a, b| (a.line, a.col, &a.id, a.severity).cmp(&(b.line, b.col, &b.id, b.severity)));
    out.dedup_by(|a, b| {
        a.line == b.line && a.col == b.col && a.id == b.id && a.severity == b.severity
    });

    Ok(FusedResult {
        summaries,
        diags: out,
    })
}

#[test]
fn unknown_extension_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let txt = dir.path().join("notes.txt");
    std::fs::write(&txt, "just some text").unwrap();

    let diags = run_rules_on_file(&txt, &Config::default(), None, None)
        .expect("function should never error on plain text");

    assert!(diags.is_empty());
}

#[test]
fn binary_file_guard_triggers() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("junk.bin");

    let mut data = vec![0_u8; 2048];
    for i in (0..data.len()).step_by(3) {
        data[i] = 0;
    }
    std::fs::write(&bin, &data).unwrap();

    let diags = run_rules_on_file(&bin, &Config::default(), None, None).unwrap();
    assert!(diags.is_empty(), "binary files are skipped");
}
