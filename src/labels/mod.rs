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
    pub struct Cap: u8 {
        const ENV_VAR      = 0b0000_0001;
        const HTML_ESCAPE  = 0b0000_0010;
        const SHELL_ESCAPE = 0b0000_0100;
        const URL_ENCODE   = 0b0000_1000;
        const JSON_PARSE   = 0b0001_0000;
        const FILE_IO      = 0b0010_0000;
        const FMT_STRING   = 0b0100_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    If,
    InfiniteLoop,
    While,
    For,
    LoopBody,
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

    // ── Check runtime (config) rules first — they take priority ──────
    if let Some(extras) = extra {
        // Pass 1: exact / suffix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if ends_with_ignore_case(trimmed, m) {
                    let start = trimmed.len() - m.len();
                    let ok = start == 0 || matches!(trimmed[start - 1], b'.' | b':');
                    if ok {
                        return Some(rule.label);
                    }
                }
            }
        }
        // Pass 2: prefix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') && starts_with_ignore_case(trimmed, m) {
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
            if ends_with_ignore_case(trimmed, m) {
                let start = trimmed.len() - m.len();
                let ok = start == 0 || matches!(trimmed[start - 1], b'.' | b':');
                if ok {
                    return Some(rule.label);
                }
            }
        }
    }

    // Pass 2: prefix matches (catch-all, lower priority)
    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_') && starts_with_ignore_case(trimmed, m) {
                return Some(rule.label);
            }
        }
    }

    None
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
        assert_eq!(parse_cap("invalid"), None);
    }
}
