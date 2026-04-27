//! Source-line snippet extraction for diagnostics.
//!
//! Both [`crate::ast`] (per-finding evidence) and [`crate::summary`]
//! (cross-file `SinkSite`) need to grab the source line containing a
//! given byte offset, trim it, and cap it at a fixed character budget.
//! The two callers used to carry private copies of this routine; the
//! truncation step performed a raw byte slice (`&trimmed[..MAX]`) which
//! panics whenever the cap lands inside a multi-byte UTF-8 character.
//! Real-world Ruby/JS test suites with Cyrillic / CJK / emoji string
//! literals tripped this on `mastodon`, `discourse`, and `gitlabhq`.
//!
//! This shared helper truncates at the nearest preceding char
//! boundary, so any UTF-8 input is safe.

const MAX_SNIPPET_BYTES: usize = 120;

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
        let mut end = MAX_SNIPPET_BYTES;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        Some(format!("{}...", &trimmed[..end]))
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::line_snippet;

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
