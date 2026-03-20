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
use std::collections::HashMap;

/// A single rule: if the AST text equals (or ends with) one of the `matchers`,
/// the node gets `label`.
#[derive(Debug, Clone, Copy)]
pub struct LabelRule {
    pub matchers: &'static [&'static str],
    pub label: DataLabel,
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
    Trivia,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// Direct user input (request params, argv, stdin, form data)
    UserInput,
    /// Environment variables and configuration
    EnvironmentConfig,
    /// File system reads
    FileSystem,
    /// Database query results
    Database,
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
        SourceKind::Unknown => crate::patterns::Severity::High,
    }
}

/// A runtime (config-derived) label rule with owned matchers.
#[derive(Debug, Clone)]
pub struct RuntimeLabelRule {
    pub matchers: Vec<String>,
    pub label: DataLabel,
}

/// Parse a capability name string into a `Cap` bitflag.
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
}

/// Build `LangAnalysisRules` from a `Config` for a given language slug.
pub fn build_lang_rules(
    config: &crate::utils::config::Config,
    lang_slug: &str,
) -> LangAnalysisRules {
    let Some(lang_cfg) = config.analysis.languages.get(lang_slug) else {
        return LangAnalysisRules::default();
    };

    let extra_labels = lang_cfg
        .rules
        .iter()
        .filter_map(|r| {
            let cap = parse_cap(&r.cap)?;
            let label = match r.kind.as_str() {
                "source" => DataLabel::Source(cap),
                "sanitizer" => DataLabel::Sanitizer(cap),
                "sink" => DataLabel::Sink(cap),
                _ => return None,
            };
            Some(RuntimeLabelRule {
                matchers: r.matchers.clone(),
                label,
            })
        })
        .collect();

    LangAnalysisRules {
        extra_labels,
        terminators: lang_cfg.terminators.clone(),
        event_handlers: lang_cfg.event_handlers.clone(),
    }
}

/// Case-insensitive suffix check (ASCII).
#[inline]
fn ends_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let start = haystack.len() - needle.len();
    haystack[start..]
        .iter()
        .zip(needle)
        .all(|(h, n)| h.eq_ignore_ascii_case(n))
}

/// Case-insensitive prefix check (ASCII).
#[inline]
fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack[..needle.len()]
        .iter()
        .zip(needle)
        .all(|(h, n)| h.eq_ignore_ascii_case(n))
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
                if match_suffix(trimmed, m) || match_suffix(full_norm_bytes, m) {
                    return Some(rule.label);
                }
            }
        }
        // Pass 2: prefix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_ignore_case(trimmed, m)
                        || starts_with_ignore_case(full_norm_bytes, m))
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
            if match_suffix(trimmed, m) || match_suffix(full_norm_bytes, m) {
                return Some(rule.label);
            }
        }
    }

    // Pass 2: prefix matches (catch-all, lower priority)
    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_')
                && (starts_with_ignore_case(trimmed, m)
                    || starts_with_ignore_case(full_norm_bytes, m))
            {
                return Some(rule.label);
            }
        }
    }

    None
}

/// Check if `text` ends with `matcher` at a word boundary (`.` or `:`).
#[inline]
fn match_suffix(text: &[u8], matcher: &[u8]) -> bool {
    if ends_with_ignore_case(text, matcher) {
        let start = text.len() - matcher.len();
        start == 0 || matches!(text[start - 1], b'.' | b':')
    } else {
        false
    }
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
}
