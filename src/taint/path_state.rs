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

/// Classify a condition AND extract the specific validated variable target.
///
/// For `ValidationCall`/`SanitizerCall`, tries to extract the first argument
/// or method receiver as the validated variable:
/// - `validate(x, ...)` → target = `"x"`
/// - `x.validate(...)` → target = `"x"`
///
/// Returns `(kind, None)` when the target cannot be determined (falls back
/// to existing behavior of marking all condition_vars).
pub fn classify_condition_with_target(text: &str) -> (PredicateKind, Option<String>) {
    let kind = classify_condition(text);

    match kind {
        PredicateKind::ValidationCall | PredicateKind::SanitizerCall => {
            if let Some(target) = extract_validation_target(text) {
                (kind, Some(target))
            } else {
                (kind, None)
            }
        }
        _ => (kind, None),
    }
}

/// Extract the validated variable from a condition text.
///
/// Handles two patterns:
/// - Function call: `validate(x, ...)` → `"x"`
/// - Method call: `x.validate(...)` → `"x"`
fn extract_validation_target(text: &str) -> Option<String> {
    let trimmed = text.trim();

    // Check for negation prefix
    let trimmed = trimmed.strip_prefix('!').unwrap_or(trimmed).trim();

    // Find the first `(` which separates callee from args
    let paren_pos = trimmed.find('(')?;
    let callee_part = &trimmed[..paren_pos];
    let args_part = &trimmed[paren_pos + 1..];

    // Check for method call pattern: `x.method(...)` or `x.method_name(...)`
    if let Some(dot_pos) = callee_part.rfind('.') {
        let receiver = callee_part[..dot_pos].trim();
        if !receiver.is_empty() && is_identifier(receiver) {
            return Some(receiver.to_string());
        }
    }

    // Function call pattern: `func(x, ...)` — extract first argument
    // Strip closing paren if present
    let args_inner = args_part.trim_end().strip_suffix(')').unwrap_or(args_part);
    // Take text up to first comma (first argument)
    let first_arg = args_inner.split(',').next()?.trim();

    // Strip reference operators (e.g. `&x` → `x`)
    let first_arg = first_arg.strip_prefix('&').unwrap_or(first_arg).trim();

    if !first_arg.is_empty() && is_identifier(first_arg) {
        Some(first_arg.to_string())
    } else {
        None
    }
}

/// Check if a string is a simple identifier (letters, digits, underscores, dots).
fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && !s.starts_with(|c: char| c.is_ascii_digit())
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

    // ── classify_condition_with_target ──────────────────────────────────

    #[test]
    fn target_function_call_first_arg() {
        let (kind, target) = classify_condition_with_target("validate(x, config)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_method_call_receiver() {
        let (kind, target) = classify_condition_with_target("x.isValid()");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_sanitizer_first_arg() {
        let (kind, target) = classify_condition_with_target("sanitize(input)");
        assert_eq!(kind, PredicateKind::SanitizerCall);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_negated_validation() {
        let (kind, target) = classify_condition_with_target("!validate(&x)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_non_validation_returns_none() {
        let (kind, target) = classify_condition_with_target("x == 5");
        assert_eq!(kind, PredicateKind::Comparison);
        assert_eq!(target, None);
    }

    #[test]
    fn target_check_auth_first_arg() {
        let (kind, target) = classify_condition_with_target("check_auth(req)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("req"));
    }

    #[test]
    fn target_method_with_args() {
        let (kind, target) = classify_condition_with_target("input.verify(sig)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("input"));
    }
}
