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
    /// Allowlist/membership check: `.includes(x)`, `x in ALLOWED`, `in_array(x, ...)`
    AllowlistCheck,
    /// Type-check guard: `typeof x`, `isinstance(x, int)`, `is_numeric(x)`
    TypeCheck,
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

    // ── Allowlist / membership checks ────────────────────────────────────
    if lower.contains(".includes(")
        || lower.contains(".include?(")
        || lower.contains(".contains(")
        || lower.contains(".indexof(")
        || lower.contains(".has(")
        || lower.contains("in_array(")
        || lower.contains(" in ")
        || (lower.contains('[') && !lower.contains('('))
    {
        return PredicateKind::AllowlistCheck;
    }

    // ── Type-check guards ──────────────────────────────────────────────
    if lower.contains("typeof ")
        || lower.contains("isinstance(")
        || lower.contains(" instanceof ")
        || lower.contains(".matches(")
        || lower.contains("is_numeric(")
        || lower.contains("is_int(")
        || lower.contains("is_string(")
        || lower.contains("is_float(")
        || lower.contains("ctype_")
        || lower.contains(".is_a?(")
        || lower.contains(".kind_of?(")
    {
        return PredicateKind::TypeCheck;
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
        PredicateKind::AllowlistCheck => {
            let target = extract_allowlist_target(text);
            (kind, target)
        }
        PredicateKind::TypeCheck => {
            let target = extract_type_check_target(text);
            (kind, target)
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

/// Extract the target variable from an allowlist/membership check.
///
/// Handles:
/// - `.includes(cmd)` → `cmd` (first argument)
/// - `in_array($cmd, $allowed)` → `cmd` (first arg, strip `$`)
/// - `cmd not in ALLOWED` / `cmd in ALLOWED` → `cmd` (left of ` in `)
/// - `allowed[cmd]` → `cmd` (inside brackets)
fn extract_allowlist_target(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Method call pattern: something.includes(arg) / .contains(arg) / .has(arg) / .indexof(arg)
    for method in &[
        ".includes(",
        ".include?(",
        ".contains(",
        ".indexof(",
        ".has(",
    ] {
        if let Some(pos) = lower.find(method) {
            let args_start = pos + method.len();
            let args_part = &trimmed[args_start..];
            let inner = args_part.strip_suffix(')').unwrap_or(args_part);
            let first_arg = inner.split(',').next()?.trim();
            let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
    }

    // in_array($cmd, $allowed) → cmd
    if let Some(pos) = lower.find("in_array(") {
        let args_start = pos + "in_array(".len();
        let args_part = &trimmed[args_start..];
        let inner = args_part.strip_suffix(')').unwrap_or(args_part);
        let first_arg = inner.split(',').next()?.trim();
        let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
        if !first_arg.is_empty() && is_identifier(first_arg) {
            return Some(first_arg.to_string());
        }
    }

    // Python `in` operator: `cmd in ALLOWED` / `cmd not in ALLOWED`
    if lower.contains(" in ") {
        // Find the leftmost ` in ` — everything before it is the target expression
        // Handle `not in` by looking for ` not in ` first
        let target_part = if let Some(pos) = lower.find(" not in ") {
            &trimmed[..pos]
        } else if let Some(pos) = lower.find(" in ") {
            &trimmed[..pos]
        } else {
            return None;
        };
        let target = target_part.trim();
        let target = target.strip_prefix('!').unwrap_or(target).trim();
        let target = target.strip_prefix('$').unwrap_or(target);
        if !target.is_empty() && is_identifier(target) {
            return Some(target.to_string());
        }
    }

    // Go map lookup: `allowed[cmd]`
    if let Some(open) = trimmed.find('[') {
        if let Some(close) = trimmed.find(']') {
            if close > open + 1 {
                let inner = trimmed[open + 1..close].trim();
                let inner = inner.strip_prefix('$').unwrap_or(inner);
                if !inner.is_empty() && is_identifier(inner) {
                    return Some(inner.to_string());
                }
            }
        }
    }

    None
}

/// Extract the target variable from a type-check guard.
///
/// Handles:
/// - `typeof input !== 'number'` → `input` (word after `typeof`)
/// - `isinstance(user_id, int)` → `user_id` (first arg)
/// - `input.matches("\\d+")` → `input` (receiver)
/// - `is_numeric($id)` → `id` (first arg, strip `$`)
fn extract_type_check_target(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();

    // typeof: `typeof input !== 'number'`
    if let Some(pos) = lower.find("typeof ") {
        let after = &trimmed[pos + "typeof ".len()..];
        // The target is the next identifier-like word
        let target: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !target.is_empty() {
            return Some(target);
        }
    }

    // isinstance(user_id, int) → user_id
    if let Some(pos) = lower.find("isinstance(") {
        let args_start = pos + "isinstance(".len();
        let args_part = &trimmed[args_start..];
        let inner = args_part.strip_suffix(')').unwrap_or(args_part);
        let first_arg = inner.split(',').next()?.trim();
        let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
        if !first_arg.is_empty() && is_identifier(first_arg) {
            return Some(first_arg.to_string());
        }
    }

    // Java/TS instanceof: "x instanceof String" → "x"
    if let Some(pos) = lower.find(" instanceof ") {
        let var_part = trimmed[..pos].trim();
        if !var_part.is_empty() && is_identifier(var_part) {
            return Some(var_part.to_string());
        }
    }

    // .matches("...") → receiver
    if let Some(pos) = lower.find(".matches(") {
        let receiver = trimmed[..pos].trim();
        let receiver = receiver.strip_prefix('!').unwrap_or(receiver).trim();
        if !receiver.is_empty() && is_identifier(receiver) {
            return Some(receiver.to_string());
        }
    }

    // PHP type checks: is_numeric($id), is_int($x), is_string($x), is_float($x)
    for func in &["is_numeric(", "is_int(", "is_string(", "is_float("] {
        if let Some(pos) = lower.find(func) {
            let args_start = pos + func.len();
            let args_part = &trimmed[args_start..];
            let inner = args_part.strip_suffix(')').unwrap_or(args_part);
            let first_arg = inner.split(',').next()?.trim();
            let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
    }

    // Ruby type checks: user_id.is_a?(Integer), x.kind_of?(String) → receiver
    for method in &[".is_a?(", ".kind_of?("] {
        if let Some(pos) = lower.find(method) {
            let receiver = trimmed[..pos].trim();
            let receiver = receiver.strip_prefix('!').unwrap_or(receiver).trim();
            if !receiver.is_empty() && is_identifier(receiver) {
                return Some(receiver.to_string());
            }
        }
    }

    // ctype_ functions: ctype_digit($x)
    if let Some(pos) = lower.find("ctype_") {
        // Find the `(` after ctype_xxx
        if let Some(paren_pos) = trimmed[pos..].find('(') {
            let args_start = pos + paren_pos + 1;
            let args_part = &trimmed[args_start..];
            let inner = args_part.strip_suffix(')').unwrap_or(args_part);
            let first_arg = inner.split(',').next()?.trim();
            let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
    }

    None
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

    // ── AllowlistCheck classification ─────────────────────────────────

    #[test]
    fn classify_allowlist_includes() {
        assert_eq!(
            classify_condition("ALLOWED.includes(cmd)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_in_array() {
        assert_eq!(
            classify_condition("in_array($cmd, $allowed)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_python_not_in() {
        assert_eq!(
            classify_condition("cmd not in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_python_in() {
        assert_eq!(
            classify_condition("cmd in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_map_lookup() {
        assert_eq!(
            classify_condition("allowed[cmd]"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_contains() {
        assert_eq!(
            classify_condition("whitelist.contains(value)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_has() {
        assert_eq!(
            classify_condition("allowedSet.has(key)"),
            PredicateKind::AllowlistCheck
        );
    }

    // ── TypeCheck classification ──────────────────────────────────────

    #[test]
    fn classify_type_check_typeof() {
        assert_eq!(
            classify_condition("typeof input !== 'number'"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_isinstance() {
        assert_eq!(
            classify_condition("isinstance(user_id, int)"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_matches() {
        assert_eq!(
            classify_condition("input.matches(\"\\\\d+\")"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_is_numeric() {
        assert_eq!(
            classify_condition("is_numeric($id)"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_is_int() {
        assert_eq!(classify_condition("is_int($x)"), PredicateKind::TypeCheck);
    }

    #[test]
    fn classify_type_check_ctype() {
        assert_eq!(
            classify_condition("ctype_digit($x)"),
            PredicateKind::TypeCheck
        );
    }

    // ── Allowlist target extraction ───────────────────────────────────

    #[test]
    fn target_allowlist_includes() {
        let (kind, target) = classify_condition_with_target("ALLOWED.includes(cmd)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_in_array() {
        let (kind, target) = classify_condition_with_target("in_array($cmd, $allowed)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_python_in() {
        let (kind, target) = classify_condition_with_target("cmd in ALLOWED");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_python_not_in() {
        let (kind, target) = classify_condition_with_target("cmd not in ALLOWED");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_map_lookup() {
        let (kind, target) = classify_condition_with_target("allowed[cmd]");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    // ── TypeCheck target extraction ───────────────────────────────────

    #[test]
    fn target_type_check_typeof() {
        let (kind, target) = classify_condition_with_target("typeof input !== 'number'");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_type_check_isinstance() {
        let (kind, target) = classify_condition_with_target("isinstance(user_id, int)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("user_id"));
    }

    #[test]
    fn target_type_check_matches() {
        let (kind, target) = classify_condition_with_target("input.matches(\"\\\\d+\")");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_type_check_is_numeric() {
        let (kind, target) = classify_condition_with_target("is_numeric($id)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("id"));
    }

    #[test]
    fn target_type_check_ctype() {
        let (kind, target) = classify_condition_with_target("ctype_digit($x)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn classify_type_check_is_a() {
        assert_eq!(
            classify_condition("user_id.is_a?(Integer)"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn target_type_check_is_a() {
        let (kind, target) = classify_condition_with_target("user_id.is_a?(Integer)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("user_id"));
    }

    #[test]
    fn classify_allowlist_include_question() {
        assert_eq!(
            classify_condition("ALLOWED.include?(cmd)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn target_allowlist_include_question() {
        let (kind, target) = classify_condition_with_target("ALLOWED.include?(cmd)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    // ── instanceof classification and target ─────────────────────────────

    #[test]
    fn classify_instanceof_is_type_check() {
        assert_eq!(
            classify_condition("x instanceof String"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn target_instanceof_x_string() {
        let (kind, target) = classify_condition_with_target("x instanceof String");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_instanceof_obj_integer() {
        let (kind, target) = classify_condition_with_target("obj instanceof Integer");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("obj"));
    }
}
