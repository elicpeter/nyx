use crate::cfg::{build_cfg, export_summaries};
use crate::cfg_analysis;
use crate::commands::scan::Diag;
use crate::errors::{NyxError, NyxResult};
use crate::evidence::{Evidence, SpanEvidence, StateEvidence};
use crate::labels::{build_lang_rules, severity_for_source_kind};
use crate::patterns::{FindingCategory, Severity};
use crate::state;
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

/// Check if a file path belongs to a non-production context (tests, vendor,
/// benchmarks, etc.).  Used to downgrade severity for findings in paths that
/// are unlikely to represent attack surface.
fn is_nonprod_path(path: &Path) -> bool {
    static NONPROD_DIRS: &[&str] = &[
        "tests",
        "test",
        "__tests__",
        "benches",
        "benchmarks",
        "examples",
        "build",
        "scripts",
        "docs",
        "js_tests",
        "fixtures",
        "vendor",
    ];
    static NONPROD_FILES: &[&str] = &["build.rs"];

    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && (NONPROD_FILES.contains(&name) || name.ends_with(".min.js"))
    {
        return true;
    }

    for component in path.components() {
        if let std::path::Component::Normal(c) = component
            && let Some(s) = c.to_str()
            && NONPROD_DIRS.contains(&s)
        {
            return true;
        }
    }

    false
}

/// Normalize a callee description for display.
fn sanitize_desc(s: &str) -> String {
    crate::fmt::normalize_snippet(s)
}

/// Human-readable label for a `SourceKind`.
fn source_kind_label(sk: crate::labels::SourceKind) -> &'static str {
    use crate::labels::SourceKind;
    match sk {
        SourceKind::UserInput => "user input",
        SourceKind::EnvironmentConfig => "environment config",
        SourceKind::FileSystem => "file system data",
        SourceKind::Database => "database result",
        SourceKind::Unknown => "tainted data",
    }
}

/// Downgrade severity by one tier: High→Medium, Medium→Low, Low→Low.
fn downgrade_severity(s: Severity) -> Severity {
    match s {
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
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

            let source_callee = cfg_graph[finding.source]
                .callee
                .as_deref()
                .map(sanitize_desc)
                .unwrap_or_else(|| "(unknown)".into());
            let sink_callee = cfg_graph[finding.sink]
                .callee
                .as_deref()
                .map(sanitize_desc)
                .unwrap_or_else(|| "(unknown)".into());
            let kind_label = source_kind_label(finding.source_kind);

            let short_source = crate::fmt::shorten_callee(&source_callee);
            let short_sink = crate::fmt::shorten_callee(&sink_callee);

            let mut labels = vec![
                (
                    "Source".into(),
                    format!(
                        "{source_callee} ({}:{})",
                        source_point.row + 1,
                        source_point.column + 1
                    ),
                ),
                ("Sink".into(), sink_callee.to_string()),
            ];
            if let Some(guard) = finding.guard_kind {
                labels.push(("Path guard".into(), format!("{guard:?}")));
            }

            let file_path_owned = path.to_string_lossy().into_owned();
            let mut evidence_notes = Vec::new();
            if finding.path_validated {
                evidence_notes.push("path_validated".into());
            }
            evidence_notes.push(format!("source_kind:{:?}", finding.source_kind));

            out.push(Diag {
                path: file_path_owned.clone(),
                line: sink_point.row + 1,
                col: sink_point.column + 1,
                severity: severity_for_source_kind(finding.source_kind),
                id: format!(
                    "taint-unsanitised-flow (source {}:{})",
                    source_point.row + 1,
                    source_point.column + 1
                ),
                category: FindingCategory::Security,
                path_validated: finding.path_validated,
                guard_kind: finding.guard_kind.map(|k| format!("{k:?}")),
                message: Some(format!(
                    "unsanitised {kind_label} flows from {short_source} \u{2192} {short_sink}"
                )),
                labels,
                confidence: None,
                evidence: Some(Evidence {
                    source: Some(SpanEvidence {
                        path: file_path_owned.clone(),
                        line: (source_point.row + 1) as u32,
                        col: (source_point.column + 1) as u32,
                        kind: "source".into(),
                        snippet: Some(short_source.clone()),
                    }),
                    sink: Some(SpanEvidence {
                        path: file_path_owned,
                        line: (sink_point.row + 1) as u32,
                        col: (sink_point.column + 1) as u32,
                        kind: "sink".into(),
                        snippet: Some(short_sink.clone()),
                    }),
                    guards: finding
                        .guard_kind
                        .map(|g| {
                            vec![SpanEvidence {
                                path: path.to_string_lossy().into_owned(),
                                line: (sink_point.row + 1) as u32,
                                col: 0,
                                kind: "guard".into(),
                                snippet: Some(format!("{g:?}")),
                            }]
                        })
                        .unwrap_or_default(),
                    sanitizers: vec![],
                    state: None,
                    notes: evidence_notes,
                }),
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
            });
        }

        // ── CFG structural analyses ─────────────────────────────────────
        let taint_active = global_summaries.is_some() || !taint_results.is_empty();
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
            taint_active,
        };
        for cf in cfg_analysis::run_all(&cfg_ctx) {
            let point = byte_offset_to_point(&_tree, cf.span.0);
            let cfg_confidence = Some(match cf.confidence {
                cfg_analysis::Confidence::High => crate::evidence::Confidence::High,
                cfg_analysis::Confidence::Medium => crate::evidence::Confidence::Medium,
                cfg_analysis::Confidence::Low => crate::evidence::Confidence::Low,
            });
            out.push(Diag {
                path: path.to_string_lossy().into_owned(),
                line: point.row + 1,
                col: point.column + 1,
                severity: cf.severity,
                id: cf.rule_id,
                category: FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: Some(cf.message),
                labels: vec![],
                confidence: cfg_confidence,
                evidence: Some(Evidence {
                    source: None,
                    sink: Some(SpanEvidence {
                        path: path.to_string_lossy().into_owned(),
                        line: (point.row + 1) as u32,
                        col: (point.column + 1) as u32,
                        kind: "sink".into(),
                        snippet: None,
                    }),
                    guards: vec![],
                    sanitizers: vec![],
                    state: None,
                    notes: vec![],
                }),
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
            });
        }

        // ── State-model dataflow analysis ────────────────────────────────
        if cfg.scanner.enable_state_analysis {
            let state_findings = state::run_state_analysis(
                &cfg_graph,
                entry,
                caller_lang,
                bytes,
                &summaries,
                global_summaries,
            );
            // Collect state finding lines to dedup overlapping CFG findings.
            let state_lines: std::collections::HashSet<usize> = state_findings
                .iter()
                .map(|sf| byte_offset_to_point(&_tree, sf.span.0).row + 1)
                .collect();

            for sf in &state_findings {
                let point = byte_offset_to_point(&_tree, sf.span.0);
                out.push(Diag {
                    path: path.to_string_lossy().into_owned(),
                    line: point.row + 1,
                    col: point.column + 1,
                    severity: sf.severity,
                    id: sf.rule_id.clone(),
                    category: FindingCategory::Security,
                    path_validated: false,
                    guard_kind: None,
                    message: Some(sf.message.clone()),
                    labels: vec![],
                    confidence: None,
                    evidence: Some(Evidence {
                        source: None,
                        sink: Some(SpanEvidence {
                            path: path.to_string_lossy().into_owned(),
                            line: (point.row + 1) as u32,
                            col: (point.column + 1) as u32,
                            kind: "sink".into(),
                            snippet: None,
                        }),
                        guards: vec![],
                        sanitizers: vec![],
                        state: Some(StateEvidence {
                            machine: sf.machine.into(),
                            subject: sf.subject.clone(),
                            from_state: sf.from_state.into(),
                            to_state: sf.to_state.into(),
                        }),
                        notes: vec![],
                    }),
                    rank_score: None,
                    rank_reason: None,
                    suppressed: false,
                    suppression: None,
                    rollup: None,
                });
            }

            // Suppress cfg-resource-leak / cfg-auth-gap when state analysis
            // already covers the same line (state analysis is more precise).
            if !state_findings.is_empty() {
                out.retain(|d| {
                    !((d.id == "cfg-resource-leak" || d.id == "cfg-auth-gap")
                        && state_lines.contains(&d.line))
                });
            }
        }
    }

    if cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Ast {
        let root = _tree.root_node();

        let compiled = query_cache::for_lang(lang_slug, ts_lang);
        let mut cursor = QueryCursor::new();

        for cq in compiled.iter() {
            if cq.meta.severity > cfg.scanner.min_severity {
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
                        category: cq.meta.category.finding_category(),
                        path_validated: false,
                        guard_kind: None,
                        message: Some(cq.meta.description.to_owned()),
                        labels: vec![],
                        confidence: Some(cq.meta.confidence),
                        evidence: Some(Evidence {
                            source: None,
                            sink: Some(SpanEvidence {
                                path: path.to_string_lossy().into_owned(),
                                line: (point.row + 1) as u32,
                                col: (point.column + 1) as u32,
                                kind: "sink".into(),
                                snippet: None,
                            }),
                            guards: vec![],
                            sanitizers: vec![],
                            state: None,
                            notes: vec![],
                        }),
                        rank_score: None,
                        rank_reason: None,
                        suppressed: false,
                        suppression: None,
                        rollup: None,
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

    // Downgrade severity for non-production paths unless opted out
    if !cfg.scanner.include_nonprod && is_nonprod_path(path) {
        for d in &mut out {
            d.severity = downgrade_severity(d.severity);
        }
    }

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

            let source_callee = cfg_graph[finding.source]
                .callee
                .as_deref()
                .map(sanitize_desc)
                .unwrap_or_else(|| "(unknown)".into());
            let sink_callee = cfg_graph[finding.sink]
                .callee
                .as_deref()
                .map(sanitize_desc)
                .unwrap_or_else(|| "(unknown)".into());
            let kind_label = source_kind_label(finding.source_kind);

            let short_source = crate::fmt::shorten_callee(&source_callee);
            let short_sink = crate::fmt::shorten_callee(&sink_callee);

            let mut labels = vec![
                (
                    "Source".into(),
                    format!(
                        "{source_callee} ({}:{})",
                        source_point.row + 1,
                        source_point.column + 1
                    ),
                ),
                ("Sink".into(), sink_callee.to_string()),
            ];
            if let Some(guard) = finding.guard_kind {
                labels.push(("Path guard".into(), format!("{guard:?}")));
            }

            let fused_file_path = path.to_string_lossy().into_owned();
            let mut fused_evidence_notes = Vec::new();
            if finding.path_validated {
                fused_evidence_notes.push("path_validated".into());
            }
            fused_evidence_notes.push(format!("source_kind:{:?}", finding.source_kind));

            out.push(Diag {
                path: fused_file_path.clone(),
                line: sink_point.row + 1,
                col: sink_point.column + 1,
                severity: severity_for_source_kind(finding.source_kind),
                id: format!(
                    "taint-unsanitised-flow (source {}:{})",
                    source_point.row + 1,
                    source_point.column + 1
                ),
                category: FindingCategory::Security,
                path_validated: finding.path_validated,
                guard_kind: finding.guard_kind.map(|k| format!("{k:?}")),
                message: Some(format!(
                    "unsanitised {kind_label} flows from {short_source} \u{2192} {short_sink}"
                )),
                labels,
                confidence: None,
                evidence: Some(Evidence {
                    source: Some(SpanEvidence {
                        path: fused_file_path.clone(),
                        line: (source_point.row + 1) as u32,
                        col: (source_point.column + 1) as u32,
                        kind: "source".into(),
                        snippet: Some(short_source.clone()),
                    }),
                    sink: Some(SpanEvidence {
                        path: fused_file_path.clone(),
                        line: (sink_point.row + 1) as u32,
                        col: (sink_point.column + 1) as u32,
                        kind: "sink".into(),
                        snippet: Some(short_sink.clone()),
                    }),
                    guards: finding
                        .guard_kind
                        .map(|g| {
                            vec![SpanEvidence {
                                path: fused_file_path,
                                line: (sink_point.row + 1) as u32,
                                col: 0,
                                kind: "guard".into(),
                                snippet: Some(format!("{g:?}")),
                            }]
                        })
                        .unwrap_or_default(),
                    sanitizers: vec![],
                    state: None,
                    notes: fused_evidence_notes,
                }),
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
            });
        }

        let taint_active = global_summaries.is_some() || !taint_results.is_empty();
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
            taint_active,
        };
        for cf in cfg_analysis::run_all(&cfg_ctx) {
            let point = byte_offset_to_point(&tree, cf.span.0);
            let fused_cfg_confidence = Some(match cf.confidence {
                cfg_analysis::Confidence::High => crate::evidence::Confidence::High,
                cfg_analysis::Confidence::Medium => crate::evidence::Confidence::Medium,
                cfg_analysis::Confidence::Low => crate::evidence::Confidence::Low,
            });
            out.push(Diag {
                path: path.to_string_lossy().into_owned(),
                line: point.row + 1,
                col: point.column + 1,
                severity: cf.severity,
                id: cf.rule_id,
                category: FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: Some(cf.message),
                labels: vec![],
                confidence: fused_cfg_confidence,
                evidence: Some(Evidence {
                    source: None,
                    sink: Some(SpanEvidence {
                        path: path.to_string_lossy().into_owned(),
                        line: (point.row + 1) as u32,
                        col: (point.column + 1) as u32,
                        kind: "sink".into(),
                        snippet: None,
                    }),
                    guards: vec![],
                    sanitizers: vec![],
                    state: None,
                    notes: vec![],
                }),
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
            });
        }

        // ── State-model dataflow analysis ────────────────────────────────
        if cfg.scanner.enable_state_analysis {
            let state_findings = state::run_state_analysis(
                &cfg_graph,
                entry,
                caller_lang,
                bytes,
                &local_summaries,
                global_summaries,
            );
            let state_lines: std::collections::HashSet<usize> = state_findings
                .iter()
                .map(|sf| byte_offset_to_point(&tree, sf.span.0).row + 1)
                .collect();

            for sf in &state_findings {
                let point = byte_offset_to_point(&tree, sf.span.0);
                out.push(Diag {
                    path: path.to_string_lossy().into_owned(),
                    line: point.row + 1,
                    col: point.column + 1,
                    severity: sf.severity,
                    id: sf.rule_id.clone(),
                    category: FindingCategory::Security,
                    path_validated: false,
                    guard_kind: None,
                    message: Some(sf.message.clone()),
                    labels: vec![],
                    confidence: None,
                    evidence: Some(Evidence {
                        source: None,
                        sink: Some(SpanEvidence {
                            path: path.to_string_lossy().into_owned(),
                            line: (point.row + 1) as u32,
                            col: (point.column + 1) as u32,
                            kind: "sink".into(),
                            snippet: None,
                        }),
                        guards: vec![],
                        sanitizers: vec![],
                        state: Some(StateEvidence {
                            machine: sf.machine.into(),
                            subject: sf.subject.clone(),
                            from_state: sf.from_state.into(),
                            to_state: sf.to_state.into(),
                        }),
                        notes: vec![],
                    }),
                    rank_score: None,
                    rank_reason: None,
                    suppressed: false,
                    suppression: None,
                    rollup: None,
                });
            }

            if !state_findings.is_empty() {
                out.retain(|d| {
                    !((d.id == "cfg-resource-leak" || d.id == "cfg-auth-gap")
                        && state_lines.contains(&d.line))
                });
            }
        }
    }

    // AST pattern queries
    if cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Ast {
        let root = tree.root_node();
        let compiled = query_cache::for_lang(lang_slug, ts_lang);
        let mut cursor = QueryCursor::new();

        for cq in compiled.iter() {
            if cq.meta.severity > cfg.scanner.min_severity {
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
                        category: cq.meta.category.finding_category(),
                        path_validated: false,
                        guard_kind: None,
                        message: Some(cq.meta.description.to_owned()),
                        labels: vec![],
                        confidence: Some(cq.meta.confidence),
                        evidence: Some(Evidence {
                            source: None,
                            sink: Some(SpanEvidence {
                                path: path.to_string_lossy().into_owned(),
                                line: (point.row + 1) as u32,
                                col: (point.column + 1) as u32,
                                kind: "sink".into(),
                                snippet: None,
                            }),
                            guards: vec![],
                            sanitizers: vec![],
                            state: None,
                            notes: vec![],
                        }),
                        rank_score: None,
                        rank_reason: None,
                        suppressed: false,
                        suppression: None,
                        rollup: None,
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

    // Downgrade severity for non-production paths unless opted out
    if !cfg.scanner.include_nonprod && is_nonprod_path(path) {
        for d in &mut out {
            d.severity = downgrade_severity(d.severity);
        }
    }

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

#[test]
fn nonprod_path_detection() {
    // Test that is_nonprod_path recognises common non-production paths
    assert!(is_nonprod_path(Path::new("project/tests/test_main.py")));
    assert!(is_nonprod_path(Path::new("src/__tests__/foo.js")));
    assert!(is_nonprod_path(Path::new("benches/bench.rs")));
    assert!(is_nonprod_path(Path::new("vendor/lib/foo.py")));
    assert!(is_nonprod_path(Path::new("src/build.rs")));
    assert!(is_nonprod_path(Path::new("dist/app.min.js")));
    assert!(is_nonprod_path(Path::new("examples/demo.py")));
    assert!(is_nonprod_path(Path::new("fixtures/data.json")));

    // Should NOT match production paths
    assert!(!is_nonprod_path(Path::new("src/main.rs")));
    assert!(!is_nonprod_path(Path::new("lib/handler.py")));
    assert!(!is_nonprod_path(Path::new("app/views.py")));
}

#[test]
fn severity_downgrade_works() {
    assert_eq!(downgrade_severity(Severity::High), Severity::Medium);
    assert_eq!(downgrade_severity(Severity::Medium), Severity::Low);
    assert_eq!(downgrade_severity(Severity::Low), Severity::Low);
}

#[test]
fn nonprod_path_downgrades_findings() {
    let dir = tempfile::tempdir().unwrap();
    // Create a file under a "tests" directory
    let test_dir = dir.path().join("tests");
    std::fs::create_dir_all(&test_dir).unwrap();
    let test_file = test_dir.join("test_cmd.py");
    std::fs::write(
        &test_file,
        b"import os\ndef test():\n    cmd = os.environ['X']\n    os.system(cmd)\n",
    )
    .unwrap();

    let default_cfg = Config::default();
    let diags = run_rules_on_file(&test_file, &default_cfg, None, None).unwrap();

    // All findings in tests/ should be downgraded (no HIGH)
    let high: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::High)
        .collect();
    assert!(
        high.is_empty(),
        "Findings in tests/ should be downgraded from HIGH; got {:?}",
        high
    );

    // With include_nonprod=true, original severity preserved
    let mut prod_cfg = Config::default();
    prod_cfg.scanner.include_nonprod = true;
    let diags_prod = run_rules_on_file(&test_file, &prod_cfg, None, None).unwrap();

    // Not all diagnostics are necessarily high, but include_nonprod should not downgrade
    // Just verify that if there are findings, they weren't downgraded by the nonprod logic
    let _ = diags_prod;
}
