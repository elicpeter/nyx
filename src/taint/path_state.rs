// ─── PredicateKind ───────────────────────────────────────────────────────────

/// Classification of what an if-condition tests.
///
/// Determined by heuristic analysis of the raw condition text.
/// Classification is conservative: prefer [`Unknown`](PredicateKind::Unknown)
/// over a wrong guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateKind {
    /// `x.is_none()`, `x == null`, `x == nil`, `x is None`
    NullCheck,
    /// `x.is_empty()`, `x.len() == 0`, `x == ""`
    EmptyCheck,
    /// `x.is_err()`, `x.is_ok()`, `err != nil`
    ErrorCheck,
    /// Call to a validation/guard function: `validate(x)`, `is_safe(x)`
    ValidationCall,
    /// Call to a sanitizer function: `sanitize(x)`, `escape(x)`
    SanitizerCall,
    /// Comparison operators: `x == 5`, `x > threshold`
    Comparison,
    /// Generic boolean test — cannot classify further.
    Unknown,
}

/// Classify a raw condition text into a [`PredicateKind`].
///
/// # Rules
///
/// - Empty/None text → [`Unknown`](PredicateKind::Unknown).
/// - `ValidationCall` / `SanitizerCall` require a `(` in the text **and** a
///   matching callee token. This avoids misclassifying comparisons like
///   `x_valid == true`.
/// - Prefers [`Unknown`](PredicateKind::Unknown) over false positives.
pub fn classify_condition(text: &str) -> PredicateKind {
    if text.is_empty() {
        return PredicateKind::Unknown;
    }

    let lower = text.to_ascii_lowercase();

    // ── Error checks (before null checks: `err != nil` is an error check,
    //    not a null check, even though it contains `!= nil`) ──────────────
    if lower.contains("is_err")
        || lower.contains("is_ok")
        || lower.contains("err != nil")
        || lower.contains("err == nil")
        || lower.contains("error != nil")
        || lower.contains("error == nil")
    {
        return PredicateKind::ErrorCheck;
    }

    // ── Null checks ──────────────────────────────────────────────────────
    if lower.contains("is_none")
        || lower.contains("is_some")
        || lower.contains("== none")
        || lower.contains("!= none")
        || lower.contains("is none")
        || lower.contains("is not none")
        || lower.contains("== null")
        || lower.contains("!= null")
        || lower.contains("=== null")
        || lower.contains("!== null")
        || lower.contains("== nil")
        || lower.contains("!= nil")
    {
        return PredicateKind::NullCheck;
    }

    // ── Empty checks ─────────────────────────────────────────────────────
    if lower.contains("is_empty")
        || lower.contains(".len() == 0")
        || lower.contains(".len() != 0")
        || lower.contains(".length == 0")
        || lower.contains(".length === 0")
        || lower.contains(".length != 0")
        || lower.contains(".length !== 0")
        || lower.contains("== \"\"")
        || lower.contains("== ''")
    {
        return PredicateKind::EmptyCheck;
    }

    // ── Call-based kinds (require `(` to be present) ─────────────────────
    if lower.contains('(') {
        // Extract a rough callee token: everything before the first `(`
        // that looks like an identifier (letters, digits, underscores, dots).
        let callee_part = lower.split('(').next().unwrap_or("");
        // Take the last segment (after `.` or `::`) as the bare name.
        let bare = callee_part
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(callee_part)
            .trim();

        // Validation
        if bare.contains("valid")
            || bare.contains("check")
            || bare.contains("verify")
            || bare.starts_with("is_safe")
            || bare.starts_with("is_authorized")
            || bare.starts_with("is_authenticated")
        {
            return PredicateKind::ValidationCall;
        }

        // Sanitizer
        if bare.contains("sanitiz") || bare.contains("escape") || bare.contains("encode") {
            return PredicateKind::SanitizerCall;
        }
    }

    // ── Comparison operators ─────────────────────────────────────────────
    if lower.contains("==")
        || lower.contains("!=")
        || lower.contains(">=")
        || lower.contains("<=")
        || lower.contains(" > ")
        || lower.contains(" < ")
    {
        return PredicateKind::Comparison;
    }

    PredicateKind::Unknown
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_condition ────────────────────────────────────────────────

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(classify_condition(""), PredicateKind::Unknown);
    }

    #[test]
    fn classify_null_checks() {
        assert_eq!(classify_condition("x.is_none()"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x == null"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x != nil"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x is None"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x === null"), PredicateKind::NullCheck);
    }

    #[test]
    fn classify_error_checks() {
        assert_eq!(classify_condition("x.is_err()"), PredicateKind::ErrorCheck);
        assert_eq!(classify_condition("err != nil"), PredicateKind::ErrorCheck);
        assert_eq!(classify_condition("x.is_ok()"), PredicateKind::ErrorCheck);
    }

    #[test]
    fn classify_empty_checks() {
        assert_eq!(
            classify_condition("x.is_empty()"),
            PredicateKind::EmptyCheck
        );
        assert_eq!(
            classify_condition("x.len() == 0"),
            PredicateKind::EmptyCheck
        );
        assert_eq!(
            classify_condition("x.length === 0"),
            PredicateKind::EmptyCheck
        );
    }

    #[test]
    fn classify_validation_call() {
        assert_eq!(
            classify_condition("validate(x)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("is_safe(input)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("check_auth(req)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("input.verify(sig)"),
            PredicateKind::ValidationCall
        );
    }

    #[test]
    fn classify_validation_requires_paren() {
        // `x_valid == true` should NOT be ValidationCall — no `(` call syntax.
        assert_eq!(
            classify_condition("x_valid == true"),
            PredicateKind::Comparison
        );
        assert_eq!(
            classify_condition("is_valid && ready"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_sanitizer_call() {
        assert_eq!(
            classify_condition("sanitize(x)"),
            PredicateKind::SanitizerCall
        );
        assert_eq!(
            classify_condition("html_escape(s)"),
            PredicateKind::SanitizerCall
        );
        assert_eq!(
            classify_condition("url_encode(path)"),
            PredicateKind::SanitizerCall
        );
    }

    #[test]
    fn classify_comparison() {
        assert_eq!(classify_condition("x == 5"), PredicateKind::Comparison);
        assert_eq!(classify_condition("x != y"), PredicateKind::Comparison);
        assert_eq!(classify_condition("a >= b"), PredicateKind::Comparison);
    }

    #[test]
    fn classify_unknown_fallback() {
        assert_eq!(classify_condition("flag"), PredicateKind::Unknown);
        assert_eq!(classify_condition("a && b"), PredicateKind::Unknown);
    }
}
