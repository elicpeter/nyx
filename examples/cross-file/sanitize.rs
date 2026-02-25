// ─────────────────────────────────────────────────────────────────────────────
// examples/cross-file/sanitize.rs — Sanitizers
//
// Functions that clean specific taint capabilities.  After passing through
// one of these, the corresponding Cap bit is stripped.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  FuncSummary produced by pass 1:                                       │
// │                                                                        │
// │  sanitize_shell  → sanitizer_caps: SHELL_ESCAPE, propagates: true      │
// │  sanitize_html   → sanitizer_caps: HTML_ESCAPE,  propagates: true      │
// │  passthrough     → sanitizer: 0, source: 0, sink: 0, propagates: true  │
// └─────────────────────────────────────────────────────────────────────────┘
// ─────────────────────────────────────────────────────────────────────────────

/// Escapes shell metacharacters.  Strips the SHELL_ESCAPE cap bit.
pub fn sanitize_shell(input: &str) -> String {
    shell_escape::unix::escape(input.into()).to_string()
}

/// Escapes HTML entities.  Strips the HTML_ESCAPE cap bit.
pub fn sanitize_html(input: &str) -> String {
    html_escape::encode_safe(input).to_string()
}

/// Does nothing security-relevant — just returns a copy.
/// Taint passes straight through (propagates_taint = true).
pub fn passthrough(input: &str) -> String {
    input.to_string()
}
