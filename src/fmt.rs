//! Console output formatting for scan diagnostics.
//!
//! Produces professional, security-tool-grade aligned output with a clear
//! severity hierarchy, normalised taint flow rendering, and stable wrapping.

use crate::commands::scan::Diag;
use crate::patterns::Severity;
use console::style;
use std::collections::BTreeMap;

/// Default maximum line width when terminal size is unknown.
const DEFAULT_WIDTH: usize = 100;

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Render all diagnostics as grouped, formatted console output with a summary.
pub fn render_console(diags: &[Diag], project_name: &str) -> String {
    let width = terminal_width();
    let mut out = String::new();

    let mut grouped: BTreeMap<&str, Vec<&Diag>> = BTreeMap::new();
    for d in diags {
        grouped.entry(&d.path).or_default().push(d);
    }

    for (path, issues) in &grouped {
        // File path header — dim blue, never brighter than severity.
        out.push_str(&format!("{}\n", style(path).blue().dim().underlined()));
        for d in issues {
            out.push_str(&render_diag(d, width));
            out.push('\n'); // blank line between findings
        }
    }

    out.push_str(&format!(
        "{} '{}' generated {} {}.\n\n",
        style("warning").yellow().bold(),
        style(project_name).white().bold(),
        style(diags.len()).bold(),
        if diags.len() == 1 { "issue" } else { "issues" },
    ));

    out
}

/// Normalise a code snippet for display: collapse whitespace, join lines,
/// clean up method-chain spacing, trim, and truncate.
pub fn normalize_snippet(s: &str) -> String {
    // Strip newlines/carriage returns with no replacement, then collapse
    // runs of spaces into a single space.
    let no_newlines: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    let collapsed: String = no_newlines.split_whitespace().collect::<Vec<_>>().join(" ");
    // Clean up `) .foo(` → `).foo(` and similar spacing around dots in chains.
    let cleaned = collapse_chain_spacing(&collapsed);
    let trimmed = cleaned.trim();
    if trimmed.len() > 120 {
        format!("{}…", &trimmed[..120])
    } else {
        trimmed.to_string()
    }
}

/// Truncate method chains: keep constructor + first balanced `(...)`, then `…`.
///
/// E.g. `Command::new("sh").arg("-c").arg(&cmd)` → `Command::new("sh")…`
#[allow(dead_code)] // public API, used by consumers
pub fn shorten_callee(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }

    let Some(open) = s.find('(') else {
        return s.to_string();
    };

    let mut depth = 0u32;
    let mut close = None;
    for (i, ch) in s[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }

    let Some(close_idx) = close else {
        return s.to_string();
    };

    let end = close_idx + 1;
    if end < s.len() {
        format!("{}…", &s[..end])
    } else {
        s.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Indentation for body/evidence lines (spaces).
const BODY_INDENT: usize = 6;

/// Render a single diagnostic block.
fn render_diag(d: &Diag, width: usize) -> String {
    let mut out = String::new();

    // ── Header line ──────────────────────────────────────────────────────
    // Format: `  98:5  ⚠ [MEDIUM] taint-unsanitised-flow (source 41:5)  Score: 87`
    let loc = format!("{}:{}", d.line, d.col);
    let sev = severity_tag(d.severity);
    let score_suffix = match d.rank_score {
        Some(s) => format!("  {}", style(format!("Score: {}", s as u32)).dim()),
        None => String::new(),
    };
    out.push_str(&format!(
        "  {}  {} {}{}\n",
        style(&loc).dim(),
        sev,
        style(&d.id).dim(),
        score_suffix,
    ));

    // ── Message body ─────────────────────────────────────────────────────
    let indent_str = " ".repeat(BODY_INDENT);
    if let Some(msg) = &d.message {
        let capitalized = capitalize_first(msg);
        let wrapped = wrap_text(&capitalized, width, BODY_INDENT);
        out.push_str(&format!("{indent_str}{wrapped}\n"));
    }

    // ── Evidence (Source, Sink, Path guard) ───────────────────────────────
    if !d.evidence.is_empty() {
        out.push('\n');
        let max_label = d.evidence.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        let key_width = max_label + 1; // +1 for ':'
        for (label, value) in &d.evidence {
            let key_str = format!("{label}:");
            let value_indent = BODY_INDENT + key_width + 1; // key + space
            let wrapped_val = wrap_text(value, width, value_indent);
            if label == "Path guard" {
                out.push_str(&format!(
                    "{indent_str}{:<kw$} {}\n",
                    style(&key_str).dim(),
                    style(&wrapped_val).cyan(),
                    kw = key_width,
                ));
            } else {
                out.push_str(&format!(
                    "{indent_str}{:<kw$} {}\n",
                    style(&key_str).dim(),
                    wrapped_val,
                    kw = key_width,
                ));
            }
        }
    } else if let Some(guard) = &d.guard_kind {
        out.push_str(&format!(
            "{indent_str}{}  {}\n",
            style("Path guard:").dim(),
            style(guard).cyan(),
        ));
    }

    out
}

/// Colored severity tag with icon. The tag is the visual anchor of each finding.
///
/// - HIGH:   bold red
/// - MEDIUM: bold 208 (orange) — distinct from yellow
/// - LOW:    dim 67 (muted blue-gray)
fn severity_tag(sev: Severity) -> String {
    match sev {
        Severity::High => format!(
            "{} [{}]",
            style("✖").red().bold(),
            style("HIGH").red().bold(),
        ),
        Severity::Medium => format!(
            "{} [{}]",
            style("⚠").color256(208).bold(),
            style("MEDIUM").color256(208).bold(),
        ),
        Severity::Low => format!(
            "{} [{}]",
            style("●").color256(67),
            style("LOW").color256(67),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Text utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Collapse spacing artefacts in method chains.
///
/// - `") .foo("` → `").foo("` (space between `)` and `.`)
/// - Multiple spaces → single space
fn collapse_chain_spacing(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Pattern: `)` followed by whitespace then `.`
        if chars[i] == ')' {
            out.push(')');
            i += 1;
            // Skip whitespace between `)` and `.`
            let ws_start = i;
            while i < len && chars[i] == ' ' {
                i += 1;
            }
            if i < len && chars[i] == '.' {
                // Collapse: emit `.` directly after `)`
                continue;
            } else {
                // Not a chain continuation — emit the whitespace we skipped
                for c in &chars[ws_start..i] {
                    out.push(*c);
                }
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Word-wrap text to fit within `max_width`, with continuation lines indented
/// to `indent` spaces. The first line is NOT indented (caller handles that).
fn wrap_text(text: &str, max_width: usize, indent: usize) -> String {
    let available_first = max_width.saturating_sub(indent);
    let available_cont = max_width.saturating_sub(indent);
    if available_first == 0 || text.len() <= available_first {
        return text.to_string();
    }

    let indent_str = " ".repeat(indent);
    let mut result = String::new();
    let mut line_len = 0usize;
    let mut first_line = true;

    for word in text.split_whitespace() {
        let wlen = word.len();
        let avail = if first_line {
            available_first
        } else {
            available_cont
        };

        if line_len == 0 {
            result.push_str(word);
            line_len = wlen;
        } else if line_len + 1 + wlen > avail {
            result.push('\n');
            result.push_str(&indent_str);
            result.push_str(word);
            line_len = wlen;
            first_line = false;
        } else {
            result.push(' ');
            result.push_str(word);
            line_len += 1 + wlen;
        }
    }

    result
}

/// Get terminal width, falling back to DEFAULT_WIDTH.
fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(DEFAULT_WIDTH)
}

/// Capitalise the first character of a string.
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => {
            let mut out = String::with_capacity(s.len());
            for upper in c.to_uppercase() {
                out.push(upper);
            }
            out.push_str(chars.as_str());
            out
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Strip ANSI escape codes for testing visible content.
    fn strip_ansi(s: &str) -> String {
        let mut result = String::new();
        let mut in_escape = false;
        for ch in s.chars() {
            if ch == '\x1b' {
                in_escape = true;
            } else if in_escape {
                if ch == 'm' {
                    in_escape = false;
                }
            } else {
                result.push(ch);
            }
        }
        result
    }

    // ── normalize_snippet ────────────────────────────────────────────────

    #[test]
    fn normalize_snippet_strips_newlines_no_space() {
        // Newlines are removed with no whitespace inserted in their place.
        assert_eq!(normalize_snippet("foo\nbar\rbaz"), "foobarbaz");
    }

    #[test]
    fn normalize_snippet_collapses_whitespace() {
        assert_eq!(
            normalize_snippet("Command::new(\"tar\")        .arg(\"-czf\")"),
            "Command::new(\"tar\").arg(\"-czf\")"
        );
    }

    #[test]
    fn normalize_snippet_trims() {
        assert_eq!(normalize_snippet("  hello  "), "hello");
    }

    #[test]
    fn normalize_snippet_truncates_at_120() {
        let long = "a".repeat(200);
        let result = normalize_snippet(&long);
        // 120 chars + '…' (3 bytes UTF-8)
        assert!(result.len() > 120);
        assert!(result.ends_with('…'));
    }

    #[test]
    fn normalize_snippet_short_unchanged() {
        assert_eq!(normalize_snippet("short"), "short");
    }

    // ── collapse_chain_spacing ───────────────────────────────────────────

    #[test]
    fn collapse_chain_removes_space_before_dot() {
        assert_eq!(
            collapse_chain_spacing("foo() .bar() .baz()"),
            "foo().bar().baz()"
        );
    }

    #[test]
    fn collapse_chain_preserves_non_chain_spacing() {
        assert_eq!(
            collapse_chain_spacing("foo() + bar()"),
            "foo() + bar()"
        );
    }

    #[test]
    fn collapse_chain_multiple_spaces() {
        assert_eq!(
            collapse_chain_spacing("cmd()     .arg(\"-c\")"),
            "cmd().arg(\"-c\")"
        );
    }

    // ── shorten_callee ───────────────────────────────────────────────────

    #[test]
    fn shorten_callee_truncates_chain() {
        assert_eq!(
            shorten_callee("Command::new(\"sh\").arg(\"-c\").arg(&cmd)"),
            "Command::new(\"sh\")…"
        );
    }

    #[test]
    fn shorten_callee_no_chain_unchanged() {
        assert_eq!(shorten_callee("env::var(\"HOME\")"), "env::var(\"HOME\")");
    }

    #[test]
    fn shorten_callee_nested_parens() {
        assert_eq!(
            shorten_callee("foo(bar(1, 2)).baz()"),
            "foo(bar(1, 2))…"
        );
    }

    #[test]
    fn shorten_callee_no_parens() {
        assert_eq!(shorten_callee("simple_name"), "simple_name");
    }

    #[test]
    fn shorten_callee_empty() {
        assert_eq!(shorten_callee(""), "");
    }

    // ── wrap_text ────────────────────────────────────────────────────────

    #[test]
    fn wrap_short_text_unchanged() {
        assert_eq!(wrap_text("short text", 80, 4), "short text");
    }

    #[test]
    fn wrap_breaks_at_boundary() {
        let text = "word1 word2 word3 word4 word5";
        let result = wrap_text(text, 20, 4);
        assert!(result.contains('\n'));
        for line in result.lines().skip(1) {
            assert!(line.starts_with("    "));
        }
    }

    // ── severity_tag ─────────────────────────────────────────────────────

    #[test]
    fn severity_tags_contain_level_name() {
        let h = strip_ansi(&severity_tag(Severity::High));
        let m = strip_ansi(&severity_tag(Severity::Medium));
        let l = strip_ansi(&severity_tag(Severity::Low));
        assert!(h.contains("HIGH"), "got: {h}");
        assert!(m.contains("MEDIUM"), "got: {m}");
        assert!(l.contains("LOW"), "got: {l}");
    }

    #[test]
    fn severity_tags_have_icons() {
        let h = strip_ansi(&severity_tag(Severity::High));
        let m = strip_ansi(&severity_tag(Severity::Medium));
        let l = strip_ansi(&severity_tag(Severity::Low));
        assert!(h.contains('✖'), "HIGH should have ✖");
        assert!(m.contains('⚠'), "MEDIUM should have ⚠");
        assert!(l.contains('●'), "LOW should have ●");
    }

    // ── render_console ───────────────────────────────────────────────────

    #[test]
    fn render_console_groups_by_file() {
        let diags = vec![
            Diag {
                path: "src/a.rs".into(),
                line: 10,
                col: 5,
                severity: Severity::High,
                id: "test-rule".into(),
                path_validated: false,
                guard_kind: None,
                message: Some("test message".into()),
                evidence: vec![],
                rank_score: None,
                rank_reason: None,
            },
            Diag {
                path: "src/b.rs".into(),
                line: 20,
                col: 1,
                severity: Severity::Low,
                id: "another-rule".into(),
                path_validated: false,
                guard_kind: None,
                message: None,
                evidence: vec![],
                rank_score: None,
                rank_reason: None,
            },
        ];
        let output = render_console(&diags, "test-project");
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("src/a.rs"));
        assert!(stripped.contains("src/b.rs"));
        assert!(stripped.contains("2 issues"));
        assert!(stripped.contains("test-project"));
    }

    #[test]
    fn render_console_evidence_displayed() {
        let diags = vec![Diag {
            path: "src/main.rs".into(),
            line: 42,
            col: 5,
            severity: Severity::High,
            id: "taint-unsanitised-flow (source 12:3)".into(),
            path_validated: false,
            guard_kind: None,
            message: Some("unsanitised input".into()),
            evidence: vec![
                ("Source".into(), "env::var(\"HOME\") at 12:3".into()),
                ("Sink".into(), "Command::new(\"sh\")".into()),
            ],
            rank_score: None,
            rank_reason: None,
        }];
        let output = render_console(&diags, "proj");
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("Source:"), "should contain Source label");
        assert!(stripped.contains("Sink:"), "should contain Sink label");
        // No backticks in output
        assert!(!stripped.contains('`'), "should not contain backticks in evidence");
    }

    #[test]
    fn render_console_blank_line_between_findings() {
        let diags = vec![
            Diag {
                path: "src/a.rs".into(),
                line: 1,
                col: 1,
                severity: Severity::High,
                id: "rule-a".into(),
                path_validated: false,
                guard_kind: None,
                message: Some("first".into()),
                evidence: vec![],
                rank_score: None,
                rank_reason: None,
            },
            Diag {
                path: "src/a.rs".into(),
                line: 10,
                col: 1,
                severity: Severity::Medium,
                id: "rule-b".into(),
                path_validated: false,
                guard_kind: None,
                message: Some("second".into()),
                evidence: vec![],
                rank_score: None,
                rank_reason: None,
            },
        ];
        let output = render_console(&diags, "proj");
        let stripped = strip_ansi(&output);
        // There should be a blank line between the two findings
        assert!(stripped.contains("First\n\n"), "blank line between findings: {stripped}");
    }

    #[test]
    fn json_omits_empty_evidence() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::Low,
            id: "test".into(),
            path_validated: false,
            guard_kind: None,
            message: None,
            evidence: vec![],
            rank_score: None,
            rank_reason: None,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            !json.contains("evidence"),
            "empty evidence should be omitted from JSON"
        );
    }

    #[test]
    fn json_omits_rank_fields_when_none() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::Low,
            id: "test".into(),
            path_validated: false,
            guard_kind: None,
            message: None,
            evidence: vec![],
            rank_score: None,
            rank_reason: None,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("rank_score"), "rank_score should be omitted when None");
        assert!(!json.contains("rank_reason"), "rank_reason should be omitted when None");
    }

    #[test]
    fn json_includes_rank_score_when_set() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            path_validated: false,
            guard_kind: None,
            message: None,
            evidence: vec![],
            rank_score: Some(120.0),
            rank_reason: None,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("rank_score"), "rank_score should be present when set");
        assert!(json.contains("120"), "rank_score value should appear");
    }

    // ── capitalize_first ─────────────────────────────────────────────────

    #[test]
    fn capitalize_first_works() {
        assert_eq!(capitalize_first("hello"), "Hello");
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("A"), "A");
        assert_eq!(capitalize_first("unsanitised"), "Unsanitised");
    }

    // ── taint flow rendering (integration-style) ─────────────────────────

    #[test]
    fn taint_flow_no_broken_backticks_or_weird_spacing() {
        let raw_sink = "Command::new(\"tar\")        .arg(\"-czf\")        .arg(\"/backups/nightly.tar.gz\")        .arg(\"/var/data\")        .output()";
        let normalised = normalize_snippet(raw_sink);
        // Chain spacing should be collapsed
        assert!(
            !normalised.contains(") ."),
            "chain spacing should be collapsed: {normalised}"
        );
        assert!(
            !normalised.contains("  "),
            "no double-spaces: {normalised}"
        );
        // Should not contain backticks
        assert!(!normalised.contains('`'), "no backticks: {normalised}");
    }

    #[test]
    fn multiline_sink_joined_and_normalised() {
        let raw = "Command::new(\"tar\")\n        .arg(\"-czf\")\n        .arg(\"/backups/nightly.tar.gz\")\n        .arg(\"/var/data\")\n        .output()";
        let normalised = normalize_snippet(raw);
        assert_eq!(
            normalised,
            "Command::new(\"tar\").arg(\"-czf\").arg(\"/backups/nightly.tar.gz\").arg(\"/var/data\").output()"
        );
    }
}
