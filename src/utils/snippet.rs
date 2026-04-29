//! UTF-8-safe truncation for diagnostic strings.
//!
//! Two related shapes live here:
//!
//! 1. [`line_snippet`] — extracts the trimmed source line containing
//!    a byte offset, capped at ~120 bytes.  Used by [`crate::ast`]
//!    (per-finding evidence) and [`crate::summary`] (cross-file
//!    `SinkSite`).
//! 2. [`truncate_at_char_boundary`] — the underlying primitive: cap a
//!    string at `max_bytes`, rounded down to the nearest UTF-8 char
//!    boundary.
//!
//! Both arose from the same family of panics: real-world Ruby/JS/Go
//! test suites carry literal Cyrillic / CJK / emoji / Devanagari /
//! Gurmukhi inside string and regex constants.  Naive
//! `&s[..MAX].to_string()` truncation panics whenever the cap lands
//! inside a multi-byte UTF-8 sequence, killing the rayon worker that
//! happens to lower that file.  Earlier sessions fixed `line_snippet`
//! (mastodon / discourse / gitlabhq, Cyrillic in RSpec strings); the
//! gogs scan still tripped because the CFG condition-text path
//! (`src/cfg/conditions.rs`, `src/cfg/mod.rs`) carried a third copy
//! of the same byte-slice idiom.  The Gurmukhi `'ਖ'` regex literal in
//! gogs's localised Gherkin keyword list lands byte 256 mid-character
//! and panics.  Centralising the safe-truncation primitive prevents
//! the next bytes-vs-chars site from re-introducing the same bug.

const MAX_SNIPPET_BYTES: usize = 120;

/// Truncate `s` to at most `max_bytes` bytes, rounding the cut point
/// down to the nearest UTF-8 character boundary so the returned slice
/// is always valid UTF-8.  When `s.len() <= max_bytes` the slice is
/// returned unchanged.  When `max_bytes == 0` an empty slice is
/// returned.  Never panics on multi-byte input.
pub fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Extract the trimmed source line containing `byte_offset`, capped
/// at ~120 bytes (rounded down to the nearest UTF-8 char boundary).
/// Returns `None` when the offset is out of range or the line is
/// blank after trimming.
pub fn line_snippet(src: &[u8], byte_offset: usize) -> Option<String> {
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
    if trimmed.len() > MAX_SNIPPET_BYTES {
        Some(format!(
            "{}...",
            truncate_at_char_boundary(trimmed, MAX_SNIPPET_BYTES)
        ))
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{line_snippet, truncate_at_char_boundary};

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate_at_char_boundary("hello", 10), "hello");
        assert_eq!(truncate_at_char_boundary("", 10), "");
    }

    #[test]
    fn truncate_zero_max_returns_empty() {
        assert_eq!(truncate_at_char_boundary("hello", 0), "");
        assert_eq!(truncate_at_char_boundary("ਖਖਖ", 0), "");
    }

    #[test]
    fn truncate_ascii_clean_at_byte_max() {
        assert_eq!(truncate_at_char_boundary("hello world", 5), "hello");
    }

    #[test]
    fn truncate_inside_multibyte_rounds_down() {
        // 'ਖ' (Gurmukhi LETTER KHA, U+0A16) is 3 bytes in UTF-8.
        // Build a string where byte 5 lands inside the 'ਖ'.
        let s = "abcdਖef";
        // bytes: 0..4 = "abcd", 4..7 = 'ਖ', 7.. = "ef"
        // Truncating at 5 must not panic; result is "abcd".
        assert_eq!(truncate_at_char_boundary(s, 5), "abcd");
        assert_eq!(truncate_at_char_boundary(s, 6), "abcd");
        assert_eq!(truncate_at_char_boundary(s, 7), "abcdਖ");
    }

    #[test]
    fn truncate_devanagari_gherkin_regex_literal() {
        // Reproduces the gogs panic shape: long regex string that
        // contains Devanagari / Gurmukhi / CJK / Thai keywords with
        // byte 256 landing mid-character.
        let regex_body = "stream.match(/(機能|功能|フィーチャ|기능|โครงหลัก|ความสามารถ|ความต้องการทางธุรกิจ|ಹೆಚ್ಚಳ|గుణము|ਮੁਹਾਂਦਰਾ|ਨਕਸ਼ ਨੁਹਾਰ|".to_string();
        assert!(regex_body.len() > 256);
        // Must not panic.
        let truncated = truncate_at_char_boundary(&regex_body, 256);
        // Must be valid UTF-8 (it's already a `&str`, but the cut point
        // landing on a boundary is the actual property under test).
        assert!(regex_body.is_char_boundary(truncated.len()));
        assert!(truncated.len() <= 256);
    }

    #[test]
    fn ascii_short_line_returned_verbatim() {
        let src = b"let x = 1;\nlet y = 2;\n";
        assert_eq!(line_snippet(src, 0).as_deref(), Some("let x = 1;"));
        assert_eq!(line_snippet(src, 11).as_deref(), Some("let y = 2;"));
    }

    #[test]
    fn blank_line_returns_none() {
        let src = b"x\n   \n";
        assert_eq!(line_snippet(src, 2), None);
    }

    #[test]
    fn out_of_range_returns_none() {
        let src = b"abc";
        assert_eq!(line_snippet(src, 10), None);
    }

    #[test]
    fn long_ascii_line_truncated_at_120_with_ellipsis() {
        let long = "x".repeat(200);
        let src = long.as_bytes();
        let out = line_snippet(src, 0).unwrap();
        assert!(out.ends_with("..."));
        assert_eq!(out.len(), 123); // 120 + "..."
    }

    #[test]
    fn long_line_with_multibyte_char_at_boundary_does_not_panic() {
        // Cyrillic chars are 2 bytes each; build a string where byte
        // 120 lands inside a 2-byte sequence.  This is the regression
        // shape that crashed mastodon/discourse/gitlabhq scans.
        let prefix = "a".repeat(119);
        let line = format!("expect(text).to eq('{}тест огромный текст ' * 50)", prefix);
        // Pad to ensure the line is > 120 bytes.
        let line = format!("{} {}", line, "тест ".repeat(50));
        let src = line.as_bytes();
        let out = line_snippet(src, 0).unwrap();
        assert!(out.ends_with("..."));
        // Truncation must produce valid UTF-8 (no panic, no replacement).
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        // And the prefix preceding "..." must end on a char boundary.
        let stripped = out.strip_suffix("...").unwrap();
        assert!(stripped.is_char_boundary(stripped.len()));
    }

    #[test]
    fn truncation_at_emoji_boundary_safe() {
        // 4-byte emoji.  Build line so byte 120 lands inside the emoji.
        let mut line = "x".repeat(118);
        line.push_str("🦀🦀🦀🦀🦀"); // 4 bytes each
        // Repeat to ensure > 120 bytes and the 120th byte is mid-emoji.
        let src = line.as_bytes();
        assert!(src.len() > 120);
        let out = line_snippet(src, 0).unwrap();
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        assert!(out.ends_with("..."));
    }

    #[test]
    fn picks_correct_line_for_offset_in_middle() {
        let src = b"first\nsecond line here\nthird\n";
        // Offset 6 is the 's' of "second".
        assert_eq!(line_snippet(src, 6).as_deref(), Some("second line here"));
    }
}
