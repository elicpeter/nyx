mod c;
mod cpp;
mod go;
mod java;
mod javascript;
mod php;
mod python;
mod ruby;
mod rust;
mod typescript;

use bitflags::bitflags;
use once_cell::sync::Lazy;
use phf::Map;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

/// A single rule: if the AST text equals (or ends with) one of the `matchers`,
/// the node gets `label`.
#[derive(Debug, Clone, Copy)]
pub struct LabelRule {
    pub matchers: &'static [&'static str],
    pub label: DataLabel,
    pub case_sensitive: bool,
}

/// Argument-sensitive sink activation.  A call only becomes a sink when the
/// constant value at `arg_index` matches `dangerous_values` or `dangerous_prefixes`.
/// Unknown / dynamic arguments use the conservative policy (treat as dangerous).
///
/// `payload_args` specifies which argument positions carry the tainted payload.
/// When non-empty, only variables from those argument positions are checked for
/// taint at the sink.  When empty, all arguments are considered payloads
/// (backward-compatible default).
#[derive(Debug, Clone, Copy)]
pub struct SinkGate {
    pub callee_matcher: &'static str,
    pub arg_index: usize,
    pub dangerous_values: &'static [&'static str],
    pub dangerous_prefixes: &'static [&'static str],
    pub label: DataLabel,
    pub case_sensitive: bool,
    pub payload_args: &'static [usize],
    /// Optional keyword argument name for languages that support keyword args
    /// (e.g. Python `shell=True` in `subprocess.Popen`).  When set, the
    /// activation value is extracted from the named keyword argument instead
    /// of the positional argument at `arg_index`.
    pub keyword_name: Option<&'static str>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Cap: u16 {
        const ENV_VAR      = 0b0000_0000_0000_0001;  // bit 0
        const HTML_ESCAPE  = 0b0000_0000_0000_0010;  // bit 1
        const SHELL_ESCAPE = 0b0000_0000_0000_0100;  // bit 2
        const URL_ENCODE   = 0b0000_0000_0000_1000;  // bit 3
        const JSON_PARSE   = 0b0000_0000_0001_0000;  // bit 4
        const FILE_IO      = 0b0000_0000_0010_0000;  // bit 5
        const FMT_STRING   = 0b0000_0000_0100_0000;  // bit 6
        const SQL_QUERY    = 0b0000_0000_1000_0000;  // bit 7
        const DESERIALIZE  = 0b0000_0001_0000_0000;  // bit 8
        const SSRF         = 0b0000_0010_0000_0000;  // bit 9
        const CODE_EXEC    = 0b0000_0100_0000_0000;  // bit 10
        const CRYPTO       = 0b0000_1000_0000_0000;  // bit 11
    }
}

impl serde::Serialize for Cap {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u16(self.bits())
    }
}

impl<'de> serde::Deserialize<'de> for Cap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bits = u16::deserialize(d)?;
        Ok(Cap::from_bits_truncate(bits))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    If,
    InfiniteLoop,
    While,
    For,
    CallFn,
    CallMethod,
    CallMacro,
    Break,
    Continue,
    Return,
    Block,
    SourceFile,
    Function,
    Assignment,
    CallWrapper,
    Try,
    Throw,
    Trivia,
    /// Simple sequential expression (e.g. cast/type-assertion) — treated like
    /// any other sequential statement in the CFG but explicitly classified so
    /// code that inspects `Kind` can recognise it.
    Seq,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DataLabel {
    Source(Cap),
    Sanitizer(Cap),
    Sink(Cap),
}

/// Configuration for extracting parameter names from function AST nodes.
pub struct ParamConfig {
    /// Field name on the function node that holds the parameter list
    /// (e.g. "parameters", "formal_parameters").
    pub params_field: &'static str,
    /// Tree-sitter node kinds that represent individual parameters.
    pub param_node_kinds: &'static [&'static str],
    /// Node kinds representing self/this parameters (e.g. "self_parameter" in Rust).
    pub self_param_kinds: &'static [&'static str],
    /// Field names tried in order to extract the identifier from a parameter node.
    pub ident_fields: &'static [&'static str],
}

static DEFAULT_PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter", "identifier"],
    self_param_kinds: &[],
    ident_fields: &["name", "pattern"],
};

/// Describes taint propagation from input arguments to output arguments
/// for known C/C++ functions (e.g., inet_pton copies network address from arg 1 to arg 2).
pub struct ArgPropagation {
    pub callee: &'static str,
    pub from_args: &'static [usize],
    pub to_args: &'static [usize],
}

/// Look up output-parameter positions for Source-labeled C/C++ functions.
/// Returns argument indices that receive taint alongside the return value.
pub fn output_param_source_positions(lang: &str, callee: &str) -> Option<&'static [usize]> {
    let registry: &[(&str, &[usize])] = match lang {
        "c" => c::OUTPUT_PARAM_SOURCES,
        "cpp" => cpp::OUTPUT_PARAM_SOURCES,
        _ => return None,
    };
    let normalized = callee
        .rsplit("::")
        .next()
        .unwrap_or(callee)
        .rsplit('.')
        .next()
        .unwrap_or(callee);
    registry
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(normalized))
        .map(|(_, positions)| *positions)
}

/// Look up arg-to-arg propagation rules for known C/C++ functions.
pub fn arg_propagation(lang: &str, callee: &str) -> Option<&'static ArgPropagation> {
    let registry: &[ArgPropagation] = match lang {
        "c" => c::ARG_PROPAGATIONS,
        "cpp" => cpp::ARG_PROPAGATIONS,
        _ => return None,
    };
    let normalized = callee
        .rsplit("::")
        .next()
        .unwrap_or(callee)
        .rsplit('.')
        .next()
        .unwrap_or(callee);
    registry
        .iter()
        .find(|p| p.callee.eq_ignore_ascii_case(normalized))
}

static REGISTRY: Lazy<HashMap<&'static str, &'static [LabelRule]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", rust::RULES);
    m.insert("rs", rust::RULES);

    m.insert("javascript", javascript::RULES);
    m.insert("js", javascript::RULES);

    m.insert("typescript", typescript::RULES);
    m.insert("ts", typescript::RULES);

    m.insert("python", python::RULES);
    m.insert("py", python::RULES);

    m.insert("go", go::RULES);

    m.insert("java", java::RULES);

    m.insert("c", c::RULES);

    m.insert("cpp", cpp::RULES);
    m.insert("c++", cpp::RULES);

    m.insert("php", php::RULES);

    m.insert("ruby", ruby::RULES);
    m.insert("rb", ruby::RULES);

    m
});

static GATED_REGISTRY: Lazy<HashMap<&'static str, &'static [SinkGate]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("javascript", javascript::GATED_SINKS);
    m.insert("js", javascript::GATED_SINKS);
    m.insert("typescript", typescript::GATED_SINKS);
    m.insert("ts", typescript::GATED_SINKS);
    m.insert("python", python::GATED_SINKS);
    m.insert("py", python::GATED_SINKS);
    m
});

/// Per-language exclusion patterns: callee text that must never be classified.
static EXCLUDES: Lazy<HashMap<&'static str, &'static [&'static str]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("javascript", javascript::EXCLUDES);
    m.insert("js", javascript::EXCLUDES);
    m.insert("typescript", typescript::EXCLUDES);
    m.insert("ts", typescript::EXCLUDES);
    m
});

/// Check whether `text` matches a per-language exclusion pattern.
pub(crate) fn is_excluded(lang: &str, trimmed: &[u8]) -> bool {
    let excludes = match EXCLUDES.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        EXCLUDES.get(key.as_str())
    }) {
        Some(e) => *e,
        None => return false,
    };
    for &pat in excludes {
        if match_suffix_cs(trimmed, pat.as_bytes(), false) {
            return true;
        }
    }
    false
}

type FastMap = &'static Map<&'static str, Kind>;

pub(crate) static CLASSIFIERS: Lazy<HashMap<&'static str, FastMap>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", &rust::KINDS);
    m.insert("rs", &rust::KINDS);

    m.insert("javascript", &javascript::KINDS);
    m.insert("js", &javascript::KINDS);

    m.insert("typescript", &typescript::KINDS);
    m.insert("ts", &typescript::KINDS);

    m.insert("python", &python::KINDS);
    m.insert("py", &python::KINDS);

    m.insert("go", &go::KINDS);

    m.insert("java", &java::KINDS);

    m.insert("c", &c::KINDS);

    m.insert("cpp", &cpp::KINDS);
    m.insert("c++", &cpp::KINDS);

    m.insert("php", &php::KINDS);

    m.insert("ruby", &ruby::KINDS);
    m.insert("rb", &ruby::KINDS);

    m
});

static PARAM_CONFIGS: Lazy<HashMap<&'static str, &'static ParamConfig>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", &rust::PARAM_CONFIG);
    m.insert("rs", &rust::PARAM_CONFIG);

    m.insert("javascript", &javascript::PARAM_CONFIG);
    m.insert("js", &javascript::PARAM_CONFIG);

    m.insert("typescript", &typescript::PARAM_CONFIG);
    m.insert("ts", &typescript::PARAM_CONFIG);

    m.insert("python", &python::PARAM_CONFIG);
    m.insert("py", &python::PARAM_CONFIG);

    m.insert("go", &go::PARAM_CONFIG);

    m.insert("java", &java::PARAM_CONFIG);

    m.insert("c", &c::PARAM_CONFIG);

    m.insert("cpp", &cpp::PARAM_CONFIG);
    m.insert("c++", &cpp::PARAM_CONFIG);

    m.insert("php", &php::PARAM_CONFIG);

    m.insert("ruby", &ruby::PARAM_CONFIG);
    m.insert("rb", &ruby::PARAM_CONFIG);

    m
});

/// Return the parameter extraction config for the given language, with a sensible default.
pub fn param_config(lang: &str) -> &'static ParamConfig {
    PARAM_CONFIGS
        .get(lang)
        .copied()
        .unwrap_or(&DEFAULT_PARAM_CONFIG)
}

#[inline(always)]
pub fn lookup(lang: &str, raw: &str) -> Kind {
    CLASSIFIERS
        .get(lang)
        .and_then(|m| m.get(raw).copied())
        .unwrap_or(Kind::Other)
}

/// The kind of taint source, used to refine finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Direct user input (request params, argv, stdin, form data)
    UserInput,
    /// Environment variables and configuration
    EnvironmentConfig,
    /// File system reads
    FileSystem,
    /// Database query results
    Database,
    /// Caught exception — may carry user-controlled data
    CaughtException,
    /// Could not determine — treat conservatively
    Unknown,
}

/// Infer the source kind from capabilities and callee name.
pub fn infer_source_kind(caps: Cap, callee: &str) -> SourceKind {
    let cl = callee.to_ascii_lowercase();

    // User input patterns
    if cl.contains("argv")
        || cl.contains("stdin")
        || cl.contains("request")
        || cl.contains("form")
        || cl.contains("query")
        || cl.contains("params")
        || cl.contains("input")
        || cl.contains("body")
        || cl.contains("header")
        || cl.contains("cookie")
        || cl.contains("location")
        || cl.contains("document.url")
        || cl.contains("document.referrer")
    {
        return SourceKind::UserInput;
    }

    // Environment / config patterns
    if cl.contains("env")
        || cl.contains("getenv")
        || cl.contains("environ")
        || cl.contains("config")
    {
        return SourceKind::EnvironmentConfig;
    }

    // File system patterns
    if cl.contains("read") || cl.contains("fopen") || cl.contains("open") {
        // Distinguish from db reads — file reads typically have FILE_IO cap
        if caps.contains(Cap::FILE_IO) {
            return SourceKind::FileSystem;
        }
    }

    // Database patterns
    if cl.contains("fetchone")
        || cl.contains("fetchall")
        || cl.contains("fetch_row")
        || cl.contains("query")
        || cl.contains("execute")
    {
        // Queries that read back from db
        return SourceKind::Database;
    }

    SourceKind::Unknown
}

/// Map a source kind to its appropriate severity level.
pub fn severity_for_source_kind(kind: SourceKind) -> crate::patterns::Severity {
    match kind {
        SourceKind::UserInput => crate::patterns::Severity::High,
        SourceKind::EnvironmentConfig => crate::patterns::Severity::High,
        SourceKind::FileSystem => crate::patterns::Severity::Medium,
        SourceKind::Database => crate::patterns::Severity::Medium,
        SourceKind::CaughtException => crate::patterns::Severity::Medium,
        SourceKind::Unknown => crate::patterns::Severity::High,
    }
}

/// A runtime (config-derived) label rule with owned matchers.
#[derive(Debug, Clone)]
pub struct RuntimeLabelRule {
    pub matchers: Vec<String>,
    pub label: DataLabel,
    pub case_sensitive: bool,
}

/// Parse a capability name string into a `Cap` bitflag.
///
/// Prefer `CapName` enum for config values; this remains for ad-hoc string parsing.
#[allow(dead_code)]
pub fn parse_cap(s: &str) -> Option<Cap> {
    match s.to_ascii_lowercase().as_str() {
        "env_var" => Some(Cap::ENV_VAR),
        "html_escape" => Some(Cap::HTML_ESCAPE),
        "shell_escape" => Some(Cap::SHELL_ESCAPE),
        "url_encode" => Some(Cap::URL_ENCODE),
        "json_parse" => Some(Cap::JSON_PARSE),
        "file_io" => Some(Cap::FILE_IO),
        "fmt_string" => Some(Cap::FMT_STRING),
        "sql_query" => Some(Cap::SQL_QUERY),
        "deserialize" => Some(Cap::DESERIALIZE),
        "ssrf" => Some(Cap::SSRF),
        "code_exec" => Some(Cap::CODE_EXEC),
        "crypto" => Some(Cap::CRYPTO),
        "all" => Some(Cap::all()),
        _ => None,
    }
}

/// Pre-built analysis rules for a specific language, derived from config.
/// Built once per file and threaded through the pipeline.
#[derive(Debug, Clone, Default)]
pub struct LangAnalysisRules {
    pub extra_labels: Vec<RuntimeLabelRule>,
    pub terminators: Vec<String>,
    pub event_handlers: Vec<String>,
    pub frameworks: Vec<crate::utils::project::DetectedFramework>,
}

/// Build `LangAnalysisRules` from a `Config` for a given language slug.
pub fn build_lang_rules(
    config: &crate::utils::config::Config,
    lang_slug: &str,
) -> LangAnalysisRules {
    let mut extra_labels: Vec<RuntimeLabelRule> = Vec::new();
    let mut terminators = Vec::new();
    let mut event_handlers = Vec::new();

    if let Some(lang_cfg) = config.analysis.languages.get(lang_slug) {
        extra_labels.extend(lang_cfg.rules.iter().map(|r| {
            use crate::utils::config::RuleKind;
            let cap = r.cap.to_cap();
            let label = match r.kind {
                RuleKind::Source => DataLabel::Source(cap),
                RuleKind::Sanitizer => DataLabel::Sanitizer(cap),
                RuleKind::Sink => DataLabel::Sink(cap),
            };
            RuntimeLabelRule {
                matchers: r.matchers.clone(),
                label,
                case_sensitive: r.case_sensitive,
            }
        }));
        terminators = lang_cfg.terminators.clone();
        event_handlers = lang_cfg.event_handlers.clone();
    }

    // Append framework-conditional rules when frameworks are detected.
    let frameworks = if let Some(ref fw_ctx) = config.framework_ctx {
        extra_labels.extend(framework_rules_for_lang(lang_slug, fw_ctx));
        fw_ctx.frameworks.clone()
    } else {
        Vec::new()
    };

    LangAnalysisRules {
        extra_labels,
        terminators,
        event_handlers,
        frameworks,
    }
}

/// Return framework-conditional label rules for a given language.
fn framework_rules_for_lang(
    lang_slug: &str,
    ctx: &crate::utils::project::FrameworkContext,
) -> Vec<RuntimeLabelRule> {
    match lang_slug {
        "go" => go::framework_rules(ctx),
        "ruby" | "rb" => ruby::framework_rules(ctx),
        "java" => java::framework_rules(ctx),
        "php" => php::framework_rules(ctx),
        "python" | "py" => python::framework_rules(ctx),
        "rust" | "rs" => rust::framework_rules(ctx),
        "javascript" | "js" => javascript::framework_rules(ctx),
        "typescript" | "ts" => typescript::framework_rules(ctx),
        _ => Vec::new(),
    }
}

/// Suffix check with configurable case sensitivity.
#[inline]
fn ends_with_cs(haystack: &[u8], needle: &[u8], case_sensitive: bool) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let start = haystack.len() - needle.len();
    if case_sensitive {
        haystack[start..] == *needle
    } else {
        haystack[start..]
            .iter()
            .zip(needle)
            .all(|(h, n)| h.eq_ignore_ascii_case(n))
    }
}

/// Prefix check with configurable case sensitivity.
#[inline]
fn starts_with_cs(haystack: &[u8], needle: &[u8], case_sensitive: bool) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    if case_sensitive {
        haystack[..needle.len()] == *needle
    } else {
        haystack[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(h, n)| h.eq_ignore_ascii_case(n))
    }
}

/// Word-boundary suffix match with configurable case sensitivity.
#[inline]
fn match_suffix_cs(text: &[u8], matcher: &[u8], case_sensitive: bool) -> bool {
    if ends_with_cs(text, matcher, case_sensitive) {
        let start = text.len() - matcher.len();
        start == 0 || matches!(text[start - 1], b'.' | b':')
    } else {
        false
    }
}

/// Try to classify a piece of syntax text.
/// `lang` is the canonicalised language key ("rust", "javascript", ...).
///
/// If `extra` runtime rules are provided, they are checked **first** (config
/// takes priority over built-in rules).
///
/// **Two-pass matching** -- exact / suffix matches are checked across *all*
/// rules before any prefix (`foo_`) match is attempted.  This prevents a
/// greedy prefix like `sanitize_` from shadowing a more specific exact
/// match like `sanitize_shell`.
pub fn classify(lang: &str, text: &str, extra: Option<&[RuntimeLabelRule]>) -> Option<DataLabel> {
    let head = text.split(['(', '<']).next().unwrap_or("");
    let trimmed = head.trim().as_bytes();

    // Early out: exclude known-benign framework patterns.
    if is_excluded(lang, trimmed) {
        return None;
    }

    // For chained calls like `r.URL.Query().Get`, also strip internal
    // `().` segments to produce a normalized form like `r.URL.Query.Get`.
    let full_normalized = normalize_chained_call(text);
    let full_norm_bytes = full_normalized.as_bytes();

    // ── Check runtime (config) rules first — they take priority ──────
    if let Some(extras) = extra {
        // Pass 1: exact / suffix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
                {
                    return Some(rule.label);
                }
            }
        }
        // Pass 2: prefix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                {
                    return Some(rule.label);
                }
            }
        }
    }

    // ── Built-in static rules ────────────────────────────────────────
    let rules = REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        REGISTRY.get(key.as_str())
    })?;

    // Pass 1: exact / suffix matches (high confidence)
    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_') {
                continue;
            }
            if match_suffix_cs(trimmed, m, rule.case_sensitive)
                || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
            {
                return Some(rule.label);
            }
        }
    }

    // Pass 2: prefix matches (catch-all, lower priority)
    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_')
                && (starts_with_cs(trimmed, m, rule.case_sensitive)
                    || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
            {
                return Some(rule.label);
            }
        }
    }

    None
}

/// Classify a piece of syntax text, returning **all** matching labels.
///
/// Same two-pass (exact/suffix then prefix) structure as [`classify()`], but
/// collects every match instead of returning on first hit.  Deduplicates
/// exact `(variant, caps)` pairs.
pub fn classify_all(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let head = text.split(['(', '<']).next().unwrap_or("");
    let trimmed = head.trim().as_bytes();

    // Early out: exclude known-benign framework patterns.
    if is_excluded(lang, trimmed) {
        return SmallVec::new();
    }

    let full_normalized = normalize_chained_call(text);
    let full_norm_bytes = full_normalized.as_bytes();

    let mut out: SmallVec<[DataLabel; 2]> = SmallVec::new();

    // Helper: push if not already present (dedup by variant+caps equality).
    #[inline]
    fn push_dedup(out: &mut SmallVec<[DataLabel; 2]>, label: DataLabel) {
        if !out.contains(&label) {
            out.push(label);
        }
    }

    // ── Check runtime (config) rules first — they take priority ──────
    if let Some(extras) = extra {
        // Pass 1: exact / suffix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }
        // Pass 2: prefix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }
    }

    // ── Built-in static rules ────────────────────────────────────────
    let rules = REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        REGISTRY.get(key.as_str())
    });

    if let Some(rules) = rules {
        // Pass 1: exact / suffix matches (high confidence)
        for rule in *rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }

        // Pass 2: prefix matches (catch-all, lower priority)
        for rule in *rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }
    }

    out
}

/// Classify a call against gated sink rules.
///
/// Returns `Some((label, payload_args))` if the callee matches a gated rule AND the
/// activation argument is dangerous (or unknown).  `payload_args` specifies which
/// argument positions carry the tainted payload (empty = all args).
///
/// Returns `None` if callee doesn't match any gated rule, or matches but the
/// activation argument is a known-safe constant.
///
/// `const_arg_at` extracts positional argument values.
/// `const_keyword_arg` extracts keyword argument values (for languages like Python).
pub fn classify_gated_sink(
    lang: &str,
    callee_text: &str,
    const_arg_at: impl Fn(usize) -> Option<String>,
    const_keyword_arg: impl Fn(&str) -> Option<String>,
) -> Option<(DataLabel, &'static [usize])> {
    let gates = GATED_REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        GATED_REGISTRY.get(key.as_str())
    })?;

    let callee_bytes = callee_text.as_bytes();

    for gate in *gates {
        let matcher = gate.callee_matcher.as_bytes();
        if !match_suffix_cs(callee_bytes, matcher, gate.case_sensitive) {
            continue;
        }
        // Matched a gated callee — inspect the activation argument.
        // Use keyword extraction if gate has keyword_name, else positional.
        let activation_value = if let Some(kw) = gate.keyword_name {
            const_keyword_arg(kw)
        } else {
            const_arg_at(gate.arg_index)
        };

        match activation_value {
            Some(value) => {
                let lower = value.to_ascii_lowercase();
                let is_dangerous = gate
                    .dangerous_values
                    .iter()
                    .any(|v| lower == v.to_ascii_lowercase())
                    || gate
                        .dangerous_prefixes
                        .iter()
                        .any(|p| lower.starts_with(&p.to_ascii_lowercase()));
                if is_dangerous {
                    return Some((gate.label, gate.payload_args));
                }
                return None; // safe constant → suppress
            }
            None => return Some((gate.label, gate.payload_args)), // unknown → conservative
        }
    }
    None
}

/// Normalize a chained method call: strip `()` between `.` segments.
/// e.g. `r.URL.Query().Get` → `r.URL.Query.Get`
/// e.g. `r.URL.Query().Get("host")` → `r.URL.Query.Get`
fn normalize_chained_call(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                // Skip from `(` to matching `)`, but only if followed by `.`
                // This handles `Query().Get` → `Query.Get`
                let mut depth = 1u32;
                let mut j = i + 1;
                while j < bytes.len() && depth > 0 {
                    if bytes[j] == b'(' {
                        depth += 1;
                    } else if bytes[j] == b')' {
                        depth -= 1;
                    }
                    j += 1;
                }
                // If we're at end or next char is `.`, skip the parens
                if j >= bytes.len() || bytes[j] == b'.' {
                    i = j;
                } else {
                    // Keep the paren content (unusual case)
                    result.push('(');
                    i += 1;
                }
            }
            b'<' => break, // Stop at generic args
            _ => {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    result
}

// ── Rule enumeration ─────────────────────────────────────────────────────────

/// All canonical language slugs (no aliases).
const CANONICAL_LANGS: &[&str] = &[
    "javascript",
    "typescript",
    "python",
    "go",
    "java",
    "c",
    "cpp",
    "php",
    "ruby",
    "rust",
];

/// Map alias slugs to canonical language name.
pub fn canonical_lang(slug: &str) -> &str {
    // Check exact matches first (fast path, no allocation)
    match slug {
        "javascript" | "js" => "javascript",
        "typescript" | "ts" => "typescript",
        "python" | "py" => "python",
        "go" => "go",
        "java" => "java",
        "c" => "c",
        "cpp" | "c++" => "cpp",
        "php" => "php",
        "ruby" | "rb" => "ruby",
        "rust" | "rs" => "rust",
        // For unknown slugs, return as-is (the caller's borrow keeps it alive)
        _ => slug,
    }
}

/// Human-readable name for a Cap bitflag value.
pub fn cap_to_name(cap: Cap) -> &'static str {
    if cap == Cap::all() {
        return "all";
    }
    match cap {
        Cap::ENV_VAR => "env_var",
        Cap::HTML_ESCAPE => "html_escape",
        Cap::SHELL_ESCAPE => "shell_escape",
        Cap::URL_ENCODE => "url_encode",
        Cap::JSON_PARSE => "json_parse",
        Cap::FILE_IO => "file_io",
        Cap::FMT_STRING => "fmt_string",
        Cap::SQL_QUERY => "sql_query",
        Cap::DESERIALIZE => "deserialize",
        Cap::SSRF => "ssrf",
        Cap::CODE_EXEC => "code_exec",
        Cap::CRYPTO => "crypto",
        _ => "unknown",
    }
}

/// Generate a stable rule ID from language, kind, and matchers.
pub fn rule_id(lang: &str, kind: &str, matchers: &[&str]) -> String {
    let mut sorted: Vec<&str> = matchers.to_vec();
    sorted.sort_unstable();
    let joined = sorted.join("\0");
    let hash = blake3::hash(joined.as_bytes());
    let hex = hash.to_hex();
    format!("{}.{}.{}", lang, kind, &hex[..8])
}

/// Metadata-enriched view of a label rule (built-in or custom).
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub title: String,
    pub language: String,
    pub kind: String,
    pub cap: String,
    pub cap_bits: u16,
    pub matchers: Vec<String>,
    pub case_sensitive: bool,
    pub is_custom: bool,
    pub is_gated: bool,
    pub enabled: bool,
}

/// Enumerate all built-in rules across all languages.
pub fn enumerate_builtin_rules() -> Vec<RuleInfo> {
    let mut out = Vec::new();

    for &lang in CANONICAL_LANGS {
        if let Some(rules) = REGISTRY.get(lang) {
            for rule in *rules {
                let (kind_str, cap) = match rule.label {
                    DataLabel::Source(c) => ("source", c),
                    DataLabel::Sanitizer(c) => ("sanitizer", c),
                    DataLabel::Sink(c) => ("sink", c),
                };
                let matchers_strs: Vec<&str> = rule.matchers.to_vec();
                let id = rule_id(lang, kind_str, &matchers_strs);
                let first = rule.matchers.first().copied().unwrap_or("?");
                let title = format!("{} ({})", first, kind_str);
                out.push(RuleInfo {
                    id,
                    title,
                    language: lang.to_string(),
                    kind: kind_str.to_string(),
                    cap: cap_to_name(cap).to_string(),
                    cap_bits: cap.bits(),
                    matchers: rule.matchers.iter().map(|s| s.to_string()).collect(),
                    case_sensitive: rule.case_sensitive,
                    is_custom: false,
                    is_gated: false,
                    enabled: true,
                });
            }
        }

        // Include gated sink entries
        if let Some(gates) = GATED_REGISTRY.get(lang) {
            for gate in *gates {
                let cap = match gate.label {
                    DataLabel::Source(c) | DataLabel::Sanitizer(c) | DataLabel::Sink(c) => c,
                };
                let kind_str = "sink";
                let matchers_strs = &[gate.callee_matcher];
                let id = rule_id(lang, &format!("gated_{}", kind_str), matchers_strs);
                let title = format!("{} (gated {})", gate.callee_matcher, kind_str);
                out.push(RuleInfo {
                    id,
                    title,
                    language: lang.to_string(),
                    kind: kind_str.to_string(),
                    cap: cap_to_name(cap).to_string(),
                    cap_bits: cap.bits(),
                    matchers: vec![gate.callee_matcher.to_string()],
                    case_sensitive: gate.case_sensitive,
                    is_custom: false,
                    is_gated: true,
                    enabled: true,
                });
            }
        }
    }

    out
}

/// Generate a custom rule ID with `custom.` prefix.
pub fn custom_rule_id(lang: &str, kind: &str, matchers: &[String]) -> String {
    let refs: Vec<&str> = matchers.iter().map(|s| s.as_str()).collect();
    format!("custom.{}", rule_id(lang, kind, &refs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_none_extra_unchanged() {
        // Built-in rule: innerHTML → Sink(HTML_ESCAPE)
        let result = classify("javascript", "innerHTML", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));

        // Non-existent should still be None
        let result = classify("javascript", "myCustomFunc", None);
        assert_eq!(result, None);
    }

    #[test]
    fn classify_extra_rules_take_priority() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["escapeHtml".into()],
            label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
            case_sensitive: false,
        }];

        let result = classify("javascript", "escapeHtml", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE)));

        // Built-in rules still work
        let result = classify("javascript", "innerHTML", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));
    }

    #[test]
    fn classify_extra_overrides_builtin() {
        // Override innerHTML to be a sanitizer (contrived but tests priority)
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["innerHTML".into()],
            label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
            case_sensitive: false,
        }];

        let result = classify("javascript", "innerHTML", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE)));
    }

    #[test]
    fn classify_location_href_is_sink() {
        let result = classify("javascript", "location.href", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::URL_ENCODE)));
    }

    #[test]
    fn classify_bare_href_is_none() {
        // Bare "href" should NOT be a sink — only "location.href" and variants
        let result = classify("javascript", "href", None);
        assert_eq!(result, None);
    }

    #[test]
    fn classify_case_insensitive_is_default() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["myCustomSink".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        }];
        // Default case_sensitive=false: case-insensitive match
        let result = classify("javascript", "MYCUSTOMSINK", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));
    }

    #[test]
    fn classify_case_sensitive_exact_match() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["MyExactSink".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: true,
        }];
        // Exact case matches
        let result = classify("javascript", "MyExactSink", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));
        // Wrong case does NOT match
        let result = classify("javascript", "myexactsink", Some(&extras));
        assert_eq!(result, None);
    }

    #[test]
    fn classify_case_sensitive_prefix() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["Sanitize_".into()],
            label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
            case_sensitive: true,
        }];
        // Correct case prefix matches
        let result = classify("javascript", "Sanitize_input", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE)));
        // Wrong case does NOT match
        let result = classify("javascript", "sanitize_input", Some(&extras));
        assert_eq!(result, None);
    }

    #[test]
    fn classify_case_sensitive_suffix_boundary() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["RunQuery".into()],
            label: DataLabel::Sink(Cap::SQL_QUERY),
            case_sensitive: true,
        }];
        // Correct case with dot boundary
        let result = classify("javascript", "db.RunQuery", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::SQL_QUERY)));
        // Wrong case does NOT match
        let result = classify("javascript", "db.runquery", Some(&extras));
        assert_eq!(result, None);
    }

    #[test]
    fn parse_cap_works() {
        assert_eq!(parse_cap("html_escape"), Some(Cap::HTML_ESCAPE));
        assert_eq!(parse_cap("shell_escape"), Some(Cap::SHELL_ESCAPE));
        assert_eq!(parse_cap("url_encode"), Some(Cap::URL_ENCODE));
        assert_eq!(parse_cap("json_parse"), Some(Cap::JSON_PARSE));
        assert_eq!(parse_cap("env_var"), Some(Cap::ENV_VAR));
        assert_eq!(parse_cap("file_io"), Some(Cap::FILE_IO));
        assert_eq!(parse_cap("all"), Some(Cap::all()));
        assert_eq!(parse_cap("ALL"), Some(Cap::all()));
        assert_eq!(parse_cap("sql_query"), Some(Cap::SQL_QUERY));
        assert_eq!(parse_cap("deserialize"), Some(Cap::DESERIALIZE));
        assert_eq!(parse_cap("ssrf"), Some(Cap::SSRF));
        assert_eq!(parse_cap("code_exec"), Some(Cap::CODE_EXEC));
        assert_eq!(parse_cap("crypto"), Some(Cap::CRYPTO));
        assert_eq!(parse_cap("invalid"), None);
    }

    /// No-op keyword arg extractor for tests (JS/TS have no keyword gates).
    fn no_kw(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn gated_sink_dangerous_exact() {
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("href".to_string()),
            no_kw,
        );
        assert_eq!(
            result,
            Some((DataLabel::Sink(Cap::HTML_ESCAPE), [1usize].as_slice()))
        );
    }

    #[test]
    fn gated_sink_dangerous_prefix() {
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("onclick".to_string()),
            no_kw,
        );
        assert_eq!(
            result,
            Some((DataLabel::Sink(Cap::HTML_ESCAPE), [1usize].as_slice()))
        );
    }

    #[test]
    fn gated_sink_safe_suppressed() {
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("class".to_string()),
            no_kw,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn gated_sink_dynamic_conservative() {
        let result = classify_gated_sink("javascript", "setAttribute", |_| None, no_kw);
        assert_eq!(
            result,
            Some((DataLabel::Sink(Cap::HTML_ESCAPE), [1usize].as_slice()))
        );
    }

    #[test]
    fn gated_sink_no_match() {
        let result =
            classify_gated_sink("rust", "setAttribute", |_| Some("href".to_string()), no_kw);
        assert_eq!(result, None);
    }

    #[test]
    fn gated_sink_returns_payload_args() {
        // setAttribute: payload is arg 1
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("href".to_string()),
            no_kw,
        );
        let (_, payload_args) = result.unwrap();
        assert_eq!(payload_args, &[1]);

        // parseFromString: payload is arg 0
        let result = classify_gated_sink(
            "javascript",
            "parseFromString",
            |idx| {
                if idx == 1 {
                    Some("text/html".to_string())
                } else {
                    None
                }
            },
            no_kw,
        );
        let (_, payload_args) = result.unwrap();
        assert_eq!(payload_args, &[0]);
    }

    #[test]
    fn gated_sink_parse_from_string_safe_mime() {
        let result = classify_gated_sink(
            "javascript",
            "parseFromString",
            |idx| {
                if idx == 1 {
                    Some("text/xml".to_string())
                } else {
                    None
                }
            },
            no_kw,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn gated_sink_python_popen_shell_true() {
        let result = classify_gated_sink(
            "python",
            "Popen",
            |_| None,
            |kw| {
                if kw == "shell" {
                    Some("True".to_string())
                } else {
                    None
                }
            },
        );
        assert_eq!(
            result,
            Some((DataLabel::Sink(Cap::SHELL_ESCAPE), [0usize].as_slice()))
        );
    }

    #[test]
    fn gated_sink_python_popen_shell_false() {
        let result = classify_gated_sink(
            "python",
            "Popen",
            |_| None,
            |kw| {
                if kw == "shell" {
                    Some("False".to_string())
                } else {
                    None
                }
            },
        );
        assert_eq!(result, None);
    }

    #[test]
    fn gated_sink_python_popen_no_shell_conservative() {
        let result = classify_gated_sink("python", "Popen", |_| None, |_| None);
        assert_eq!(
            result,
            Some((DataLabel::Sink(Cap::SHELL_ESCAPE), [0usize].as_slice()))
        );
    }

    #[test]
    fn classify_all_single_label() {
        let result = classify_all("javascript", "innerHTML", None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], DataLabel::Sink(Cap::HTML_ESCAPE));
    }

    #[test]
    fn classify_all_dual_label_php() {
        let result = classify_all("php", "file_get_contents", None);
        assert!(result.len() >= 2, "expected dual label, got {:?}", result);
        assert!(
            result.contains(&DataLabel::Source(Cap::all())),
            "expected Source(all), got {:?}",
            result
        );
        assert!(
            result.contains(&DataLabel::Sink(Cap::SSRF)),
            "expected Sink(SSRF), got {:?}",
            result
        );
    }

    #[test]
    fn classify_all_dual_label_java() {
        let result = classify_all("java", "readObject", None);
        assert!(result.len() >= 2, "expected dual label, got {:?}", result);
        assert!(
            result.contains(&DataLabel::Source(Cap::all())),
            "expected Source(all), got {:?}",
            result
        );
        assert!(
            result.contains(&DataLabel::Sink(Cap::DESERIALIZE)),
            "expected Sink(DESERIALIZE), got {:?}",
            result
        );
    }

    #[test]
    fn classify_go_echo_sinks_with_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Echo],
        };
        let rules = go::framework_rules(&ctx);
        let extras = rules.to_vec();

        assert_eq!(
            classify("go", "c.String", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("go", "c.HTML", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("go", "c.JSON", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );

        // Without Echo framework, these should not match
        let empty = go::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("go", "c.String", Some(&empty)), None);
    }

    #[test]
    fn classify_javascript_koa_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Koa],
        };
        let extras = javascript::framework_rules(&ctx);

        assert_eq!(
            classify("javascript", "ctx.query", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("javascript", "ctx.cookies.get", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("javascript", "ctx.body", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("javascript", "ctx.redirect", Some(&extras)),
            Some(DataLabel::Sink(Cap::SSRF)),
        );

        let empty = javascript::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("javascript", "ctx.query", Some(&empty)), None);
    }

    #[test]
    fn classify_typescript_fastify_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Fastify],
        };
        let extras = typescript::framework_rules(&ctx);

        assert_eq!(
            classify("typescript", "request.query", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("typescript", "reply.send", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("typescript", "reply.redirect", Some(&extras)),
            Some(DataLabel::Sink(Cap::SSRF)),
        );

        let empty = typescript::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("typescript", "request.query", Some(&empty)), None);
    }

    #[test]
    fn classify_ruby_sinatra_template_sinks() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Sinatra],
        };
        let rules = ruby::framework_rules(&ctx);
        let extras = rules.to_vec();

        assert_eq!(
            classify("ruby", "erb", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("ruby", "haml", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );

        // Without Sinatra, erb should not match
        let empty = ruby::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("ruby", "erb", Some(&empty)), None);
    }

    #[test]
    fn classify_rust_axum_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Axum],
        };
        let extras = rust::framework_rules(&ctx);

        assert_eq!(
            classify("rust", "Path<String>", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "HeaderMap.get(\"x-user\")", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "Html(name)", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("rust", "Redirect::to(next)", Some(&extras)),
            Some(DataLabel::Sink(Cap::SSRF)),
        );

        let empty = rust::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("rust", "Html(name)", Some(&empty)), None);
    }

    #[test]
    fn classify_rust_actix_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::ActixWeb],
        };
        let extras = rust::framework_rules(&ctx);

        assert_eq!(
            classify("rust", "web::Json<String>", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "HttpRequest.match_info()", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "HttpResponse.body(payload)", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
    }

    #[test]
    fn classify_rust_rocket_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Rocket],
        };
        let extras = rust::framework_rules(&ctx);

        assert_eq!(
            classify("rust", "CookieJar.get_private(\"sid\")", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "content::RawHtml(name)", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("rust", "Redirect::to(next)", Some(&extras)),
            Some(DataLabel::Sink(Cap::SSRF)),
        );
    }
}
