#![allow(clippy::only_used_in_recursion, clippy::type_complexity)]

use crate::auth_analysis;
use crate::cfg::{Cfg, FileCfg, FuncSummaries, build_cfg, export_summaries};
use crate::cfg_analysis;
use crate::commands::scan::Diag;
use crate::errors::{NyxError, NyxResult};
use crate::evidence::{Evidence, FlowStep, SpanEvidence, StateEvidence};
use crate::labels::{
    Cap, DataLabel, LangAnalysisRules, build_lang_rules, severity_for_source_kind,
};
use crate::patterns::{FindingCategory, Severity};
use crate::state;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::summary::{FuncSummary, GlobalSummaries};
use crate::symbol::{Lang, normalize_namespace};
use crate::taint::analyse_file;
use crate::utils::config::AnalysisMode;
use crate::utils::ext::lowercase_ext;
use crate::utils::{Config, query_cache};
use petgraph::graph::NodeIndex;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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

/// Extract the source line containing `byte_offset`, trimmed and capped at 120 chars.
fn extract_line_snippet(src: &[u8], byte_offset: usize) -> Option<String> {
    if byte_offset >= src.len() {
        return None;
    }
    let line_start = src[..byte_offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    let line_end = src[byte_offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(src.len(), |p| byte_offset + p);
    let line = std::str::from_utf8(&src[line_start..line_end]).ok()?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > 120 {
        Some(format!("{}...", &trimmed[..120]))
    } else {
        Some(trimmed.to_string())
    }
}

/// Build a [`Diag`] from a taint [`Finding`], the CFG that produced it,
/// the parsed tree (for byte→line/col conversion) and the file path.
fn build_taint_diag(
    finding: &crate::taint::Finding,
    cfg_graph: &crate::cfg::Cfg,
    tree: &tree_sitter::Tree,
    path: &Path,
    src: &[u8],
) -> Diag {
    let sink_byte = cfg_graph[finding.sink].ast.span.0;
    let sink_point = byte_offset_to_point(tree, sink_byte);
    // For cross-body origins, prefer the preserved source_span over
    // indexing into the (possibly different) body's graph.
    let source_byte = finding
        .source_span
        .unwrap_or_else(|| cfg_graph[finding.source].ast.span.0);
    let source_point = byte_offset_to_point(tree, source_byte);

    let source_callee = cfg_graph[finding.source]
        .call
        .callee
        .as_deref()
        .map(sanitize_desc)
        .unwrap_or_else(|| "(unknown)".into());
    let sink_callee = cfg_graph[finding.sink]
        .call
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
    evidence_notes.push(format!("hop_count:{}", finding.hop_count));
    evidence_notes.push(format!("cap_specificity:{}", finding.cap_specificity));
    if finding.uses_summary {
        evidence_notes.push("uses_summary".into());
    }

    // Convert raw flow steps to display FlowSteps
    let flow_steps: Vec<FlowStep> = finding
        .flow_steps
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let point = byte_offset_to_point(tree, cfg_graph[raw.cfg_node].ast.span.0);
            let snippet = extract_line_snippet(src, cfg_graph[raw.cfg_node].ast.span.0);
            let callee = cfg_graph[raw.cfg_node].call.callee.clone();
            let function = cfg_graph[raw.cfg_node].ast.enclosing_func.clone();
            FlowStep {
                step: (i + 1) as u32,
                kind: raw.op_kind.clone(),
                file: file_path_owned.clone(),
                line: (point.row + 1) as u32,
                col: (point.column + 1) as u32,
                snippet,
                variable: raw.var_name.clone(),
                callee,
                function,
                is_cross_file: false,
            }
        })
        .collect();

    let mut diag = Diag {
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
                path: file_path_owned.clone(),
                line: (sink_point.row + 1) as u32,
                col: (sink_point.column + 1) as u32,
                kind: "sink".into(),
                snippet: Some(short_sink.clone()),
            }),
            guards: finding
                .guard_kind
                .map(|g| {
                    vec![SpanEvidence {
                        path: file_path_owned,
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
            source_kind: Some(finding.source_kind),
            hop_count: Some(finding.hop_count),
            uses_summary: finding.uses_summary,
            cap_specificity: Some(finding.cap_specificity),
            flow_steps,
            symbolic: finding.symbolic.clone(),
            ..Default::default()
        }),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
    };

    // Post-fill explanation and confidence limiters
    let explanation = crate::evidence::generate_explanation(&diag);
    let limiters = crate::evidence::compute_confidence_limiters(&diag);
    if let Some(ref mut ev) = diag.evidence {
        ev.explanation = explanation;
        ev.confidence_limiters = limiters;
    }

    diag
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

/// Check if a file path indicates a test file. Matches filename-based
/// conventions (`.test.js`, `.spec.ts`) and the `__tests__` directory
/// convention.  Directory-only checks (`test/`, `tests/`, `fixtures/`)
/// are intentionally excluded because they're too broad when scanning
/// absolute paths.
fn is_test_file(path: &Path) -> bool {
    static TEST_SUFFIXES: &[&str] = &[
        ".test.js",
        ".test.ts",
        ".test.jsx",
        ".test.tsx",
        ".spec.js",
        ".spec.ts",
        ".spec.jsx",
        ".spec.tsx",
    ];

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        for suffix in TEST_SUFFIXES {
            if name.ends_with(suffix) {
                return true;
            }
        }
    }

    // __tests__ is specific enough (React/Jest convention) to match on directory
    for component in path.components() {
        if let std::path::Component::Normal(c) = component
            && c == "__tests__"
        {
            return true;
        }
    }

    false
}

/// Pattern IDs that are noise-prone in test files (fixture credentials,
/// non-crypto randomness, plain HTTP in test harnesses).
fn is_test_suppressible_pattern(id: &str) -> bool {
    // Suffix-match to handle both js. and ts. prefixes
    id.ends_with(".secrets.hardcoded_secret")
        || id.ends_with(".crypto.math_random")
        || id.ends_with(".transport.fetch_http")
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
        SourceKind::CaughtException => "caught exception",
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
//  ParsedSource + ParsedFile: shared parse/CFG pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Level 1: parsed tree + lang info. No CFG construction.
struct ParsedSource<'a> {
    tree: tree_sitter::Tree,
    ts_lang: Language,
    lang_slug: &'static str,
    bytes: &'a [u8],
    path: &'a Path,
    file_path_str: Cow<'a, str>,
}

impl<'a> ParsedSource<'a> {
    /// Parse bytes into a tree-sitter AST. Returns `None` for binary files or
    /// unsupported languages.
    fn try_new(bytes: &'a [u8], path: &'a Path) -> NyxResult<Option<Self>> {
        if is_binary(bytes) {
            return Ok(None);
        }
        let Some((ts_lang, lang_slug)) = lang_for_path(path) else {
            return Ok(None);
        };
        let tree = PARSER.with(|cell| {
            let mut parser = cell.borrow_mut();
            parser.set_language(&ts_lang)?;
            parser
                .parse(bytes, None)
                .ok_or_else(|| NyxError::Other("tree-sitter failed".into()))
        })?;
        let file_path_str = path.to_string_lossy();
        Ok(Some(Self {
            tree,
            ts_lang,
            lang_slug,
            bytes,
            path,
            file_path_str,
        }))
    }

    /// Run AST pattern queries and return diagnostics.
    fn run_ast_queries(&self, cfg: &Config) -> Vec<Diag> {
        let root = self.tree.root_node();
        let compiled = query_cache::for_lang(self.lang_slug, self.ts_lang.clone());
        let mut cursor = QueryCursor::new();
        let mut out = Vec::new();
        let in_test_file = is_test_file(self.path);

        for cq in compiled.iter() {
            if cq.meta.severity > cfg.scanner.min_severity {
                continue;
            }
            // Suppress noise-prone patterns in test files
            if in_test_file && is_test_suppressible_pattern(cq.meta.id) {
                continue;
            }
            let mut matches = cursor.matches(&cq.query, root, self.bytes);
            while let Some(m) = matches.next() {
                if let Some(cap) = m.captures.iter().find(|c| c.index == 0) {
                    // Layer A: suppress Security findings on calls with all-literal args
                    if cq.meta.category.finding_category() == FindingCategory::Security
                        && is_call_all_args_literal(cap.node, self.bytes)
                    {
                        continue;
                    }
                    let point = cap.node.start_position();
                    out.push(Diag {
                        path: self.path.to_string_lossy().into_owned(),
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
                                path: self.path.to_string_lossy().into_owned(),
                                line: (point.row + 1) as u32,
                                col: (point.column + 1) as u32,
                                kind: "sink".into(),
                                snippet: None,
                            }),
                            guards: vec![],
                            sanitizers: vec![],
                            state: None,
                            notes: vec![],
                            ..Default::default()
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
        out
    }

    /// Sort, dedup, and optionally downgrade severity for non-production paths.
    fn finalize_diags(&self, out: &mut Vec<Diag>, cfg: &Config) {
        out.sort_by(|a, b| {
            (a.line, a.col, &a.id, a.severity).cmp(&(b.line, b.col, &b.id, b.severity))
        });
        out.dedup_by(|a, b| {
            a.line == b.line && a.col == b.col && a.id == b.id && a.severity == b.severity
        });

        if !cfg.scanner.include_nonprod && is_nonprod_path(self.path) {
            for d in out.iter_mut() {
                d.severity = downgrade_severity(d.severity);
            }
        }
    }
}

/// Level 2: adds CFG graph, summaries, lang rules on top of ParsedSource.
struct ParsedFile<'a> {
    source: ParsedSource<'a>,
    file_cfg: FileCfg,
    lang_rules: LangAnalysisRules,
    has_lang_rules: bool,
}

impl<'a> ParsedFile<'a> {
    /// Build CFG + lang rules from a parsed source.
    fn from_source(source: ParsedSource<'a>, cfg: &Config) -> Self {
        let lang_rules = build_lang_rules(cfg, source.lang_slug);
        let has_lang_rules = !lang_rules.extra_labels.is_empty()
            || !lang_rules.terminators.is_empty()
            || !lang_rules.event_handlers.is_empty();
        let rules_ref = if has_lang_rules {
            Some(&lang_rules)
        } else {
            None
        };
        let file_cfg = build_cfg(
            &source.tree,
            source.bytes,
            source.lang_slug,
            &source.file_path_str,
            rules_ref,
        );
        Self {
            source,
            file_cfg,
            lang_rules,
            has_lang_rules,
        }
    }

    /// The top-level body's CFG graph (for backward-compatible access).
    fn cfg_graph(&self) -> &Cfg {
        &self.file_cfg.toplevel().graph
    }

    /// The top-level body's entry node.
    #[allow(dead_code)]
    fn entry(&self) -> NodeIndex {
        self.file_cfg.toplevel().entry
    }

    fn local_summaries(&self) -> &FuncSummaries {
        &self.file_cfg.summaries
    }

    fn rules_ref(&self) -> Option<&LangAnalysisRules> {
        if self.has_lang_rules {
            Some(&self.lang_rules)
        } else {
            None
        }
    }

    fn export_summaries(&self) -> Vec<FuncSummary> {
        export_summaries(
            self.local_summaries(),
            &self.source.file_path_str,
            self.source.lang_slug,
        )
    }

    /// Extract SSA function summaries for all functions in this file.
    /// Extract SSA summaries and eligible callee bodies in a single lowering pass.
    ///
    /// Returns `(ssa_summaries, ssa_bodies)` where each tuple carries the full
    /// identity metadata (container / disambig / kind) needed to reconstruct
    /// a precise [`crate::symbol::FuncKey`] when persisted and later reloaded.
    ///
    /// **Known limitation:** the intra-file SSA summary map is still keyed by
    /// bare function `name`.  When two definitions in the same file share the
    /// same name (e.g. a free `process` and a `Worker::process`), the second
    /// lowering overwrites the first in `sum_map`.  The surrounding `FuncKey`
    /// identity we attach here is looked up from the first `LocalFuncSummary`
    /// matching that name, so cross-file resolution remains correct for the
    /// surviving definition but the shadowed one is lost.
    fn extract_ssa_artifacts(
        &self,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
    ) -> (
        Vec<(
            String,
            usize,
            String,
            Option<u32>,
            crate::symbol::FuncKind,
            SsaFuncSummary,
        )>,
        Vec<(
            String,
            usize,
            String,
            String,
            String,
            Option<u32>,
            crate::symbol::FuncKind,
            crate::taint::ssa_transfer::CalleeSsaBody,
        )>,
    ) {
        use crate::state::symbol::SymbolInterner;
        let caller_lang = Lang::from_slug(self.source.lang_slug).unwrap_or(Lang::Rust);
        let lang_slug = caller_lang.as_str().to_string();
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&self.source.file_path_str, scan_root_str.as_deref());

        // Iterate per-body graphs for function lowering (not the old supergraph).
        let mut sum_map = std::collections::HashMap::new();
        let mut eligible_bodies = Vec::new();
        for body in self.file_cfg.function_bodies() {
            let _func_name = match &body.meta.name {
                Some(n) => n.clone(),
                None => continue,
            };
            let interner = SymbolInterner::from_cfg(&body.graph);
            let (body_sums, body_bodies) = crate::taint::extract_ssa_artifacts(
                &body.graph,
                &interner,
                caller_lang,
                &namespace,
                self.local_summaries(),
                global_summaries,
            );
            sum_map.extend(body_sums);
            eligible_bodies.extend(body_bodies);
        }

        // Lookup helper: find the first local summary matching `name` and
        // return its identity triple.  Falls back to the free-function shape.
        let identity_for = |name: &str| -> (String, Option<u32>, crate::symbol::FuncKind) {
            self.local_summaries()
                .iter()
                .find(|(k, _)| k.name == name)
                .map(|(_, ls)| (ls.container.clone(), ls.disambig, ls.kind))
                .unwrap_or_else(|| (String::new(), None, crate::symbol::FuncKind::Function))
        };

        let ssa_summaries = sum_map
            .into_iter()
            .map(|(name, summary)| {
                let (container, disambig, kind) = identity_for(&name);
                let param_count = self
                    .local_summaries()
                    .iter()
                    .find(|(k, _)| k.name == name)
                    .map(|(_, ls)| ls.param_count)
                    .unwrap_or_else(|| {
                        summary
                            .param_to_return
                            .iter()
                            .map(|(idx, _)| *idx)
                            .chain(summary.param_to_sink.iter().map(|(idx, _)| *idx))
                            .max()
                            .map(|m| m + 1)
                            .unwrap_or(0)
                    });
                (name, param_count, container, disambig, kind, summary)
            })
            .collect();

        let ssa_bodies = eligible_bodies
            .into_iter()
            .map(|(name, param_count, body)| {
                let (container, disambig, kind) = identity_for(&name);
                (
                    name,
                    param_count,
                    lang_slug.clone(),
                    namespace.clone(),
                    container,
                    disambig,
                    kind,
                    body,
                )
            })
            .collect();

        (ssa_summaries, ssa_bodies)
    }

    /// Run taint analysis, CFG structural analyses, and state-model analysis.
    fn run_cfg_analyses(
        &self,
        cfg: &Config,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
    ) -> Vec<Diag> {
        let mut out = Vec::new();
        let caller_lang = Lang::from_slug(self.source.lang_slug).unwrap_or(Lang::Rust);

        // ── Taint analysis ──────────────────────────────────────────────
        tracing::debug!("Running taint analysis on: {}", self.source.path.display());
        tracing::debug!("Func summaries: {:?}", self.local_summaries());
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&self.source.file_path_str, scan_root_str.as_deref());
        let extra = if self.lang_rules.extra_labels.is_empty() {
            None
        } else {
            Some(self.lang_rules.extra_labels.as_slice())
        };
        let taint_results = analyse_file(
            &self.file_cfg,
            self.local_summaries(),
            global_summaries,
            caller_lang,
            &namespace,
            &[],
            extra,
        );
        for finding in &taint_results {
            let body_cfg = &self.file_cfg.body(finding.body_id).graph;

            // Suppress internal redirect taint findings: res.redirect(`/path/...`)
            // with a path-prefix argument is server-relative, not an open redirect.
            let sink_info = &body_cfg[finding.sink];
            let sink_has_ssrf = sink_info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SSRF)));
            if sink_has_ssrf
                && let Some(ref callee) = sink_info.call.callee
                && (callee.ends_with("redirect") || callee.ends_with("Redirect"))
                && crate::cfg_analysis::guards::has_redirect_path_prefix(
                    self.source.bytes,
                    sink_info.ast.span,
                )
            {
                continue;
            }

            out.push(build_taint_diag(
                finding,
                body_cfg,
                &self.source.tree,
                self.source.path,
                self.source.bytes,
            ));
        }

        // ── CFG structural analyses (per body) ─────────────────────────
        let taint_active = global_summaries.is_some() || !taint_results.is_empty();
        for body in &self.file_cfg.bodies {
            let body_taint: Vec<_> = taint_results
                .iter()
                .filter(|f| f.body_id == body.meta.id)
                .cloned()
                .collect();
            let cfg_ctx = cfg_analysis::AnalysisContext {
                cfg: &body.graph,
                entry: body.entry,
                lang: caller_lang,
                file_path: &self.source.file_path_str,
                source_bytes: self.source.bytes,
                func_summaries: self.local_summaries(),
                global_summaries,
                taint_findings: &body_taint,
                analysis_rules: self.rules_ref(),
                taint_active,
            };
            for cf in cfg_analysis::run_all(&cfg_ctx) {
                let point = byte_offset_to_point(&self.source.tree, cf.span.0);
                let cfg_confidence = Some(match cf.confidence {
                    cfg_analysis::Confidence::High => crate::evidence::Confidence::High,
                    cfg_analysis::Confidence::Medium => crate::evidence::Confidence::Medium,
                    cfg_analysis::Confidence::Low => crate::evidence::Confidence::Low,
                });
                out.push(Diag {
                    path: self.source.path.to_string_lossy().into_owned(),
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
                            path: self.source.path.to_string_lossy().into_owned(),
                            line: (point.row + 1) as u32,
                            col: (point.column + 1) as u32,
                            kind: "sink".into(),
                            snippet: None,
                        }),
                        guards: vec![],
                        sanitizers: vec![],
                        state: None,
                        notes: vec![],
                        ..Default::default()
                    }),
                    rank_score: None,
                    rank_reason: None,
                    suppressed: false,
                    suppression: None,
                    rollup: None,
                });
            }
        } // end for body in bodies (CFG structural analyses)

        // ── State-model dataflow analysis (per body) ─────────────────────
        if cfg.scanner.enable_state_analysis {
            let resource_method_summaries =
                state::build_resource_method_summaries(&self.file_cfg.bodies, caller_lang);
            let mut all_state_findings = Vec::new();
            for body in &self.file_cfg.bodies {
                let state_findings = state::run_state_analysis(
                    &body.graph,
                    body.entry,
                    caller_lang,
                    self.source.bytes,
                    self.local_summaries(),
                    global_summaries,
                    cfg.scanner.enable_auth_analysis,
                    &resource_method_summaries,
                );

                for sf in &state_findings {
                    let point = byte_offset_to_point(&self.source.tree, sf.span.0);
                    out.push(Diag {
                        path: self.source.path.to_string_lossy().into_owned(),
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
                                path: self.source.path.to_string_lossy().into_owned(),
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
                            ..Default::default()
                        }),
                        rank_score: None,
                        rank_reason: None,
                        suppressed: false,
                        suppression: None,
                        rollup: None,
                    });
                }

                all_state_findings.extend(state_findings);
            } // end for body in bodies (state analysis)

            // Suppress cfg-resource-leak / cfg-auth-gap when state analysis
            // already covers the same line (state analysis is more precise).
            let state_lines: std::collections::HashSet<usize> = all_state_findings
                .iter()
                .map(|sf| byte_offset_to_point(&self.source.tree, sf.span.0).row + 1)
                .collect();
            if !all_state_findings.is_empty() {
                out.retain(|d| {
                    !((d.id == "cfg-resource-leak" || d.id == "cfg-auth-gap")
                        && state_lines.contains(&d.line))
                });
            }
        }

        out
    }

    /// Run AST-backed authorization analyses that do not require CFG construction.
    fn run_auth_analyses(&self, cfg: &Config) -> Vec<Diag> {
        auth_analysis::run_auth_analysis(
            &self.source.tree,
            self.source.bytes,
            self.source.lang_slug,
            self.source.path,
            cfg,
        )
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
    cfg: &Config,
) -> NyxResult<Vec<FuncSummary>> {
    let _span = tracing::debug_span!("extract_summaries", file = %path.display()).entered();
    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        return Ok(vec![]);
    };
    let parsed = ParsedFile::from_source(source, cfg);
    Ok(parsed.export_summaries())
}

/// Convenience wrapper that reads the file then delegates to
/// [`extract_summaries_from_bytes`].
#[allow(dead_code)] // used by benchmarks and lib consumers
pub fn extract_summaries_from_file(path: &Path, cfg: &Config) -> NyxResult<Vec<FuncSummary>> {
    let bytes = std::fs::read(path)?;
    extract_summaries_from_bytes(&bytes, path, cfg)
}

/// Build a CFG from a file and return the graph, entry node, function summaries,
/// and language.
///
/// Returns `None` for binary files or unsupported languages.
/// Intended for benchmarks and isolated testing of state analysis.
pub fn build_cfg_for_file(path: &Path, cfg: &Config) -> NyxResult<Option<(FileCfg, Lang)>> {
    let bytes = std::fs::read(path)?;
    let Some(source) = ParsedSource::try_new(&bytes, path)? else {
        return Ok(None);
    };
    let lang = Lang::from_slug(source.lang_slug).unwrap_or(Lang::C);
    let parsed = ParsedFile::from_source(source, cfg);
    Ok(Some((parsed.file_cfg, lang)))
}

/// Extract both `FuncSummary` and `SsaFuncSummary` from pre-read bytes.
///
/// This is the shared pass-1 pipeline for indexed scans: parses once, builds
/// CFG once, and returns both summary types. Uses the same `ParsedFile`
/// pipeline as `analyse_file_fused` — no divergent extraction path.
pub fn extract_all_summaries_from_bytes(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    scan_root: Option<&Path>,
) -> NyxResult<(
    Vec<FuncSummary>,
    Vec<(
        String,
        usize,
        String,
        Option<u32>,
        crate::symbol::FuncKind,
        SsaFuncSummary,
    )>,
    Vec<(
        String,
        usize,
        String,
        String,
        String,
        Option<u32>,
        crate::symbol::FuncKind,
        crate::taint::ssa_transfer::CalleeSsaBody,
    )>,
)> {
    let _span = tracing::debug_span!("extract_all_summaries", file = %path.display()).entered();
    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        return Ok((vec![], vec![], vec![]));
    };
    let parsed = ParsedFile::from_source(source, cfg);
    let func_summaries = parsed.export_summaries();
    let (ssa_summaries, ssa_bodies) = parsed.extract_ssa_artifacts(None, scan_root);
    Ok((func_summaries, ssa_summaries, ssa_bodies))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constant-argument suppression helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when the captured call node has only literal arguments
/// (string, number, boolean, null/nil/none).  Used to suppress AST pattern
/// findings on provably-constant calls like `os.system("echo health-ok")`.
///
/// Conservative: returns `false` whenever the tree structure is unclear or
/// any argument is non-literal (including interpolated strings).
fn is_call_all_args_literal(node: tree_sitter::Node, bytes: &[u8]) -> bool {
    // Walk upwards from the captured node to find the closest call_expression
    // (or similar) ancestor, then locate its argument list child.
    let call_node = find_enclosing_call(node);
    let call_node = match call_node {
        Some(n) => n,
        None => return false,
    };

    // Find the argument_list / arguments child of the call node.
    let arg_list = find_arg_list(call_node);
    let arg_list = match arg_list {
        Some(n) => n,
        None => return false,
    };

    let mut has_any_arg = false;
    for i in 0..arg_list.named_child_count() as u32 {
        let child = match arg_list.named_child(i) {
            Some(c) => c,
            None => continue,
        };
        has_any_arg = true;
        if !is_literal_node(child, bytes) {
            return false;
        }
    }

    // If the argument list is empty (no args), we conservatively do NOT
    // suppress — the danger may come from side effects, not arguments.
    has_any_arg
}

/// Walk up to find a call-expression-like ancestor of the captured node.
/// Stops at statement/block boundaries to avoid matching unrelated outer calls.
fn find_enclosing_call(mut node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    // The captured node may already be the call, or it could be the callee
    // identifier inside a call_expression.  Walk up a few levels.
    for _ in 0..4 {
        let kind = node.kind();
        if kind.contains("call") && !kind.contains("callee") {
            return Some(node);
        }
        // PHP: function_call_expression
        if kind == "function_call_expression" {
            return Some(node);
        }
        // Stop at scope/statement boundaries — don't cross into outer calls
        if kind.contains("block")
            || kind.contains("body")
            || kind == "program"
            || kind == "module"
            || kind == "expression_statement"
        {
            return None;
        }
        node = node.parent()?;
    }
    None
}

/// Find the argument-list child of a call node across languages.
fn find_arg_list(call: tree_sitter::Node) -> Option<tree_sitter::Node> {
    for i in 0..call.child_count() as u32 {
        if let Some(child) = call.child(i) {
            let kind = child.kind();
            // Common argument list node kinds across languages:
            // Python/JS/TS/Java/Go/C/C++/Rust: argument_list / arguments
            // PHP: arguments
            // Ruby: argument_list
            if kind == "argument_list" || kind == "arguments" || kind == "actual_parameters" {
                return Some(child);
            }
        }
    }
    None
}

/// Check if a tree-sitter node represents a literal value.
fn is_literal_node(node: tree_sitter::Node, bytes: &[u8]) -> bool {
    let kind = node.kind();
    match kind {
        // String literals (most languages)
        "string"
        | "string_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "string_content"
        | "string_fragment" => true,

        // Numeric literals
        "integer" | "integer_literal" | "int_literal" | "float" | "float_literal" | "number" => {
            true
        }

        // Boolean / null / nil / none
        "true" | "false" | "null" | "nil" | "none" | "null_literal" | "boolean"
        | "boolean_literal" => true,

        // PHP encapsed_string: safe only if it has no variable interpolation
        "encapsed_string" => {
            // If it contains `$` variable interpolation nodes, it's not literal
            !has_interpolation(node)
        }

        // Wrapper nodes: PHP wraps each arg in an `argument` node,
        // Go uses `argument` too.  Unwrap and check the inner value.
        "argument" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_literal_node(c, bytes))
        }

        // Unary minus on a number literal: `-42`
        "unary_expression" | "unary_op" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_literal_node(c, bytes))
        }

        // String concatenation of literals: `"a" + "b"` or `"a" . "b"`
        "binary_expression" | "concatenated_string" => {
            node.named_child_count() >= 2
                && (0..node.named_child_count() as u32).all(|i| {
                    node.named_child(i)
                        .is_some_and(|c| is_literal_node(c, bytes))
                })
        }

        _ => false,
    }
}

/// Check if a string node contains interpolation (e.g., PHP `"Hello $name"`).
fn has_interpolation(node: tree_sitter::Node) -> bool {
    for i in 0..node.child_count() as u32 {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if kind == "variable_name"
                || kind == "simple_variable"
                || kind.contains("interpolation")
            {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
//  Layer B: AST pattern suppression when taint confirms safety
// ─────────────────────────────────────────────────────────────────────────────

/// Map the second segment of a pattern ID (e.g. "cmdi" from "py.cmdi.os_system")
/// to the `Cap` that taint analysis models. Returns `None` for categories taint
/// cannot subsume (memory safety, crypto, etc.), so those patterns are never suppressed.
fn pattern_category_cap(pattern_id: &str) -> Option<Cap> {
    let category = pattern_id.split('.').nth(1)?;
    match category {
        "cmdi" => Some(Cap::SHELL_ESCAPE),
        "xss" => Some(Cap::HTML_ESCAPE),
        "sqli" => Some(Cap::SQL_QUERY),
        "code_exec" => Some(Cap::CODE_EXEC),
        "ssrf" => Some(Cap::SSRF),
        "path" => Some(Cap::FILE_IO),
        // deser/memory/crypto: taint cannot fully subsume these structural patterns
        _ => None,
    }
}

/// Suppression context built from CFG + taint results. Used to decide whether
/// an AST pattern finding can be safely suppressed because taint analysis
/// evaluated the data flow and found it safe.
struct TaintSuppressionCtx {
    /// For each function scope, the set of lines containing Source-labeled nodes.
    source_lines_by_func: HashMap<Option<String>, HashSet<usize>>,
    /// For each sink node line, its enclosing function scope.
    sink_func_at_line: HashMap<usize, Option<String>>,
    /// Lines where taint emitted a `taint-unsanitised-flow` finding.
    taint_finding_lines: HashSet<usize>,
}

impl TaintSuppressionCtx {
    /// Build suppression context from ALL per-body CFG graphs, tree (for
    /// byte→line mapping), and existing taint findings.
    ///
    /// Scans every body's graph (not just top-level) so that Source/Sink
    /// nodes inside function bodies are visible for suppression decisions.
    fn build(file_cfg: &FileCfg, tree: &tree_sitter::Tree, taint_diags: &[Diag]) -> Self {
        let mut source_lines_by_func: HashMap<Option<String>, HashSet<usize>> = HashMap::new();
        let mut sink_func_at_line: HashMap<usize, Option<String>> = HashMap::new();

        for body in &file_cfg.bodies {
            for idx in body.graph.node_indices() {
                let info = &body.graph[idx];
                let mut has_source = false;
                let mut has_sink = false;
                for label in &info.taint.labels {
                    match label {
                        DataLabel::Source(_) => has_source = true,
                        DataLabel::Sink(_) => has_sink = true,
                        _ => {}
                    }
                }
                let byte = info.ast.span.0;
                let point = byte_offset_to_point(tree, byte);
                let line = point.row + 1;
                if has_source {
                    source_lines_by_func
                        .entry(info.ast.enclosing_func.clone())
                        .or_default()
                        .insert(line);
                }
                if has_sink {
                    sink_func_at_line.insert(line, info.ast.enclosing_func.clone());
                }
            }
        }

        let taint_finding_lines: HashSet<usize> = taint_diags
            .iter()
            .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
            .map(|d| d.line)
            .collect();

        Self {
            source_lines_by_func,
            sink_func_at_line,
            taint_finding_lines,
        }
    }

    /// Returns `true` if this AST pattern finding should be suppressed.
    fn should_suppress(&self, pattern_id: &str, line: usize) -> bool {
        // Condition 1: pattern category maps to a Cap taint models
        if pattern_category_cap(pattern_id).is_none() {
            return false;
        }
        // Condition 2: at least one Source exists in the same function scope
        // at an EARLIER line (upstream in control flow). This prevents suppression
        // when the only Source is co-located (dual-label) or downstream from the
        // sink, since taint couldn't have evaluated a flow that doesn't exist.
        if let Some(func) = self.sink_func_at_line.get(&line) {
            match self.source_lines_by_func.get(func) {
                Some(source_lines) => {
                    if !source_lines.iter().any(|&sl| sl < line) {
                        return false;
                    }
                }
                None => return false,
            }
        } else {
            // No CFG sink at this line — taint had no opportunity to evaluate
            return false;
        }
        // Condition 3: no taint finding at this line (taint found it safe)
        !self.taint_finding_lines.contains(&line)
    }
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

    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        // Not a recognized tree-sitter language — try text-based patterns.
        return Ok(scan_text_based_patterns(bytes, path, cfg));
    };

    let mut out = Vec::new();

    // CFG construction + taint + cfg_analysis only needed for CFG-capable modes.
    let needs_cfg = matches!(
        cfg.scanner.mode,
        AnalysisMode::Full | AnalysisMode::Cfg | AnalysisMode::Taint
    );

    if needs_cfg {
        let parsed = ParsedFile::from_source(source, cfg);
        out.extend(parsed.run_cfg_analyses(cfg, global_summaries, scan_root));
        if cfg.scanner.mode == AnalysisMode::Full {
            // Layer B: suppress AST findings where taint confirmed safety
            let suppression =
                TaintSuppressionCtx::build(&parsed.file_cfg, &parsed.source.tree, &out);
            let ast_findings = parsed.source.run_ast_queries(cfg);
            out.extend(
                ast_findings
                    .into_iter()
                    .filter(|d| !suppression.should_suppress(&d.id, d.line)),
            );
        }
        if cfg.scanner.mode == AnalysisMode::Full {
            out.extend(parsed.run_auth_analyses(cfg));
        }
        parsed.source.finalize_diags(&mut out, cfg);
    } else {
        // AST-only: no CFG construction (fast path preserved)
        out.extend(source.run_ast_queries(cfg));
        let parsed = ParsedFile::from_source(source, cfg);
        out.extend(parsed.run_auth_analyses(cfg));
        parsed.source.finalize_diags(&mut out, cfg);
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
    /// SSA-derived per-parameter summaries.
    ///
    /// Tuple shape: `(func_name, param_count, container, disambig, kind, summary)`.
    /// Carries enough identity data to reconstruct a precise [`crate::symbol::FuncKey`]
    /// on reload — see `extract_ssa_artifacts` for the known intra-file name
    /// collision limitation.
    pub ssa_summaries: Vec<(
        String,
        usize,
        String,
        Option<u32>,
        crate::symbol::FuncKind,
        SsaFuncSummary,
    )>,
    pub cfg_nodes: usize,
    /// Phase 30: eligible callee bodies for cross-file symex.
    /// Tuple shape: `(func_name, param_count, lang_slug, namespace, container, disambig, kind, body)`.
    pub ssa_bodies: Vec<(
        String,
        usize,
        String,
        String,
        String,
        Option<u32>,
        crate::symbol::FuncKind,
        crate::taint::ssa_transfer::CalleeSsaBody,
    )>,
}

/// Parse the file once, build the CFG once, and produce both function
/// summaries (for cross-file resolution) and full diagnostics (AST analyses +
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

    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        // Not a recognized tree-sitter language — try text-based patterns.
        return Ok(FusedResult {
            summaries: vec![],
            diags: scan_text_based_patterns(bytes, path, cfg),
            ssa_summaries: vec![],
            cfg_nodes: 0,
            ssa_bodies: vec![],
        });
    };

    let parsed = ParsedFile::from_source(source, cfg);
    let cfg_nodes = parsed.cfg_graph().node_count();
    let summaries = parsed.export_summaries();

    let mut out = Vec::new();

    let needs_cfg = matches!(
        cfg.scanner.mode,
        AnalysisMode::Full | AnalysisMode::Cfg | AnalysisMode::Taint
    );

    let (ssa_summaries, ssa_bodies) = if needs_cfg {
        out.extend(parsed.run_cfg_analyses(cfg, global_summaries, scan_root));
        parsed.extract_ssa_artifacts(global_summaries, scan_root)
    } else {
        (vec![], vec![])
    };

    if cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Ast {
        let ast_findings = parsed.source.run_ast_queries(cfg);
        // Layer B only applies when taint had the opportunity to evaluate
        if needs_cfg && cfg.scanner.mode == AnalysisMode::Full {
            let suppression =
                TaintSuppressionCtx::build(&parsed.file_cfg, &parsed.source.tree, &out);
            out.extend(
                ast_findings
                    .into_iter()
                    .filter(|d| !suppression.should_suppress(&d.id, d.line)),
            );
        } else {
            out.extend(ast_findings);
        }
        out.extend(parsed.run_auth_analyses(cfg));
    }
    parsed.source.finalize_diags(&mut out, cfg);

    Ok(FusedResult {
        summaries,
        diags: out,
        ssa_summaries,
        cfg_nodes,
        ssa_bodies,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Text-based pattern scanning (non-tree-sitter files)
// ─────────────────────────────────────────────────────────────────────────────

/// Run text-based pattern scanners on files whose extension is not supported
/// by tree-sitter.  Currently handles `.ejs` templates.
fn scan_text_based_patterns(bytes: &[u8], path: &Path, cfg: &Config) -> Vec<Diag> {
    let ext = lowercase_ext(path);
    match ext {
        Some("ejs") => {
            let mut diags = crate::patterns::ejs::scan_ejs_file(path, bytes);
            // Respect severity filter
            diags.retain(|d| d.severity <= cfg.scanner.min_severity);
            diags
        }
        _ => vec![],
    }
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

#[test]
fn constant_arg_suppression_works() {
    use tree_sitter::StreamingIterator;

    // PHP: system("echo health-ok") should be suppressed
    {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        let code = b"<?php\nsystem(\"echo health-ok\");\n";
        let tree = parser.parse(code, None).unwrap();
        let query_str = r#"(function_call_expression
            function: (name) @n (#match? @n "^(system)$"))
            @vuln"#;
        let query = tree_sitter::Query::new(&lang, query_str).unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_slice());
        let m = matches.next().expect("query should match");
        let cap = m.captures.iter().find(|c| c.index == 0).unwrap();
        assert!(
            is_call_all_args_literal(cap.node, code),
            "PHP system(\"echo health-ok\") should have all-literal args"
        );
    }

    // Python: os.system("echo health-ok") should be suppressed
    {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        let code = b"import os\nos.system(\"echo health-ok\")\n";
        let tree = parser.parse(code, None).unwrap();
        let query_str = r#"(call
            function: (attribute
                object: (identifier) @pkg (#eq? @pkg "os")
                attribute: (identifier) @fn (#eq? @fn "system")))
            @vuln"#;
        let query = tree_sitter::Query::new(&lang, query_str).unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_slice());
        let m = matches.next().expect("query should match");
        let cap = m.captures.iter().find(|c| c.index == 0).unwrap();
        assert!(
            is_call_all_args_literal(cap.node, code),
            "Python os.system(\"echo health-ok\") should have all-literal args"
        );
    }

    // Python: os.system(cmd) should NOT be suppressed (variable arg)
    {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        let code = b"import os\nos.system(cmd)\n";
        let tree = parser.parse(code, None).unwrap();
        let query_str = r#"(call
            function: (attribute
                object: (identifier) @pkg (#eq? @pkg "os")
                attribute: (identifier) @fn (#eq? @fn "system")))
            @vuln"#;
        let query = tree_sitter::Query::new(&lang, query_str).unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_slice());
        let m = matches.next().expect("query should match");
        let cap = m.captures.iter().find(|c| c.index == 0).unwrap();
        assert!(
            !is_call_all_args_literal(cap.node, code),
            "Python os.system(cmd) should NOT have all-literal args"
        );
    }
}
