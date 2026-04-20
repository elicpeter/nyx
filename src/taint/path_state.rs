#![allow(clippy::collapsible_if)]

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
    /// Negative-validation of shell metacharacters:
    /// `x.contains(";")`, `x.match(/[;|&]/)`, `";" in x`, etc.
    ///
    /// The **true branch is the REJECT path** (early return / panic / throw)
    /// and the **false branch is the validated path**.  Use inverted polarity
    /// when applying branch predicates.
    ShellMetaValidated,
    /// Bounded-length rejection: `x.len() > N` / `x.length < N` with N >= 2.
    ///
    /// Commonly paired with [`ShellMetaValidated`] in OR-chain rejection
    /// idioms (`if x.len() > MAX || x.contains(";") { reject }`).  Counts as
    /// a dominator guard for `cfg-unguarded-sink` purposes, but intentionally
    /// does **not** mark variables as validated — the rejection direction is
    /// ambiguous from the condition alone (a `.len() > 5 { sink(x) }`
    /// gate is a precondition, not a rejection).
    BoundedLength,
    /// Comparison operators: `x == 5`, `x > threshold`
    Comparison,
    /// Generic boolean test — cannot classify further.
    Unknown,
}

/// Single-character shell metacharacters that a rejection check commonly
/// guards against before constructing a shell command.
///
/// Presence of any of these in user input is sufficient to enable shell
/// injection, so rejecting input that contains them is a real sanitizer.
/// `"foo"` or other non-metachar needles don't qualify — a rejection of
/// those is business logic, not security.
const SHELL_METACHARS: &[&str] = &[";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\0"];

/// Check whether `text` matches a shell-metachar rejection idiom.
///
/// Recognizes:
/// - Rust / Java / Go: `x.contains("<METACHAR>")`
/// - JS / TS:          `x.includes("<METACHAR>")`
/// - Python:           `"<METACHAR>" in x`
/// - Ruby:             `x.include?("<METACHAR>")`
/// - Regex form:       `x.match(/[;|&]/)` / `re.search(r"[;|&]", x)` with a
///   character class containing only metacharacters.
///
/// Returns `false` if the needle is a non-metachar literal or cannot be
/// extracted — falls through to broader classification.
fn is_shell_metachar_rejection(text: &str) -> bool {
    // Method-call form: `.contains(…)` / `.includes(…)` / `.include?(…)`
    for method in [".contains(", ".includes(", ".include?("] {
        if let Some(idx) = text.find(method) {
            let args_start = idx + method.len();
            if let Some(needle) = extract_first_string_arg(&text[args_start..]) {
                if SHELL_METACHARS.contains(&needle.as_str()) {
                    return true;
                }
            }
        }
    }
    // Python membership form: `"<METACHAR>" in x` (but not `x in ALLOWED`)
    if let Some(needle) = extract_python_in_needle(text) {
        if SHELL_METACHARS.contains(&needle.as_str()) {
            return true;
        }
    }
    // Regex character-class form: `.match(/[;|&]/)` / `re.search(r"[…]", …)`
    if is_metachar_regex_class(text) {
        return true;
    }
    false
}

/// Extract the first string literal argument from a slice starting just after
/// an opening `(` in a call expression.  Returns the raw inner text of the
/// literal (without surrounding quotes).
///
/// Handles `"..."`, `'...'`, and simple escapes `\"`, `\'`, `\\`.
fn extract_first_string_arg(after_open: &str) -> Option<String> {
    let bytes = after_open.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    i += 1;
    let mut out = Vec::new();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'0' => out.push(b'\0'),
                c => out.push(c),
            }
            i += 2;
            continue;
        }
        if b == quote {
            return String::from_utf8(out).ok();
        }
        out.push(b);
        i += 1;
    }
    None
}

/// For Python `"<METACHAR>" in x` (needle on the left side of ` in `), return
/// the needle.  Returns `None` for `x in ALLOWED` (identifier on the left) —
/// that is an allowlist check, not a rejection.
fn extract_python_in_needle(text: &str) -> Option<String> {
    let pos = text.find(" in ")?;
    let left = text[..pos].trim();
    // Strip leading `!` / `not` for rejection contexts
    let left = left.strip_prefix('!').unwrap_or(left).trim();
    let bytes = left.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    if bytes.last() != Some(&quote) || bytes.len() < 2 {
        return None;
    }
    let inner = &left[1..left.len() - 1];
    Some(inner.to_string())
}

/// Detect regex character classes that contain only shell metacharacters:
/// `[;|&]`, `[;&`$]`, etc.  Missing: escape-class metacharacters inside the
/// class (e.g. `[\n]`) — conservative, returns false there.
fn is_metachar_regex_class(text: &str) -> bool {
    // Find `[` followed by content and `]`, anywhere in the text.
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        if let Some(close) = after.find(']') {
            let inner = &after[..close];
            if !inner.is_empty()
                && inner
                    .chars()
                    .all(|c| SHELL_METACHARS.iter().any(|m| m.starts_with(c)))
            {
                return true;
            }
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    false
}

/// Check whether `text` looks like a bounded-length rejection:
/// `x.len() > N`, `x.len() < N`, `x.length >= N`, etc. where `N` is an
/// integer literal >= 2.  Excludes `> 0` / `>= 1` / `< 1` — those are
/// non-empty checks, which are not length-bound validations.
fn is_bounded_length_check(lower: &str) -> bool {
    const PROBES: &[&str] = &[
        ".len()", ".length", // JS/TS/Java `.length` property (no parens)
    ];
    for probe in PROBES {
        let mut rest = lower;
        while let Some(pos) = rest.find(probe) {
            let after = &rest[pos + probe.len()..];
            // Skip the optional `()` that `.length` never has but `.len` does.
            let after = after.trim_start();
            let after = after.strip_prefix("()").unwrap_or(after);
            let after = after.trim_start();
            for op in [">=", "<=", ">", "<"] {
                if let Some(tail) = after.strip_prefix(op) {
                    let tail = tail.trim_start();
                    if let Some(n) = parse_leading_uint(tail) {
                        if n >= 2 {
                            return true;
                        }
                    }
                    break;
                }
            }
            rest = &rest[pos + probe.len()..];
        }
    }
    false
}

/// Parse a leading non-negative integer literal (decimal only).
fn parse_leading_uint(s: &str) -> Option<u64> {
    let mut n: u64 = 0;
    let mut any = false;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            n = n.checked_mul(10)?.checked_add(d as u64)?;
            any = true;
        } else {
            break;
        }
    }
    any.then_some(n)
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

    // ── Shell-metachar negative validation ───────────────────────────────
    //
    // Matched BEFORE AllowlistCheck so that `x.contains(";")` is recognized
    // as a rejection idiom rather than a membership test.  Checked on the
    // raw (non-lowercased) text so metacharacter comparisons stay
    // case-accurate — `;` / `|` / `&` have no case.
    if is_shell_metachar_rejection(text) {
        return PredicateKind::ShellMetaValidated;
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
        // Rust character-class validation: `.chars().all(|c| c.is_ascii_*())`
        // and similar per-character validations.  Presence of `is_ascii_`
        // inside an `.all(…)` / `.iter().all(…)` call is a strong validation
        // signal equivalent to a TypeCheck.
        || (lower.contains(".all(") && lower.contains("is_ascii_"))
        || (lower.contains(".all(") && lower.contains("is_alphanumeric"))
        || (lower.contains(".all(") && lower.contains("is_numeric("))
    {
        return PredicateKind::TypeCheck;
    }

    // ── Bounded-length rejection ─────────────────────────────────────────
    //
    // `.len() > N` / `.length < N` with N >= 2.  Pairs with
    // ShellMetaValidated in OR-chain rejection patterns.  Kept as its own
    // kind (not TypeCheck) because the rejection direction is ambiguous: a
    // `.len() > 5 { sink(x) }` gate is a precondition, not a rejection, so
    // marking condition vars as validated on the true branch would silence
    // legitimate findings.  `cfg-unguarded-sink` still treats this as a
    // dominator guard (structural intent), just without SSA-level validation.
    if is_bounded_length_check(&lower) {
        return PredicateKind::BoundedLength;
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
        PredicateKind::ShellMetaValidated => {
            // The receiver of `.contains(…)` / `.includes(…)` is the value
            // being validated.  Reuses the validation extractor which already
            // handles `x.method(arg)` → `"x"`.
            let target = extract_validation_target(text);
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

    // ── ShellMetaValidated classification ─────────────────────────────────

    #[test]
    fn classify_shell_metachar_contains_rust() {
        assert_eq!(
            classify_condition("input.contains(\";\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("cmd.contains(\"|\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("s.contains(\"&\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("s.contains(\"`\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("s.contains(\"$\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_includes_js() {
        assert_eq!(
            classify_condition("input.includes(';')"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("cmd.includes(\"|\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_include_question_ruby() {
        assert_eq!(
            classify_condition("cmd.include?(\";\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_python_in() {
        assert_eq!(
            classify_condition("\";\" in cmd"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("'|' in cmd"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_regex_class() {
        assert_eq!(
            classify_condition("cmd.match(/[;|&]/)"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("re.search(\"[;|&]\", cmd)"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_non_metachar_contains_stays_allowlist() {
        // `x.contains("foo")` must NOT be credited as a shell-metachar
        // rejection.  It falls back to the existing AllowlistCheck behavior.
        assert_eq!(
            classify_condition("input.contains(\"foo\")"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("path.contains(\"..\")"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("name.contains(\"admin\")"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_membership_unaffected() {
        // `x in ALLOWED` (identifier on left) remains AllowlistCheck.
        // Only a quoted metachar on the LEFT of ` in ` triggers ShellMeta.
        assert_eq!(
            classify_condition("cmd in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("cmd not in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn target_shell_metachar_receiver() {
        let (kind, target) = classify_condition_with_target("input.contains(\";\")");
        assert_eq!(kind, PredicateKind::ShellMetaValidated);
        assert_eq!(target.as_deref(), Some("input"));
    }

    // ── Bounded-length TypeCheck ──────────────────────────────────────────

    #[test]
    fn classify_bounded_length_rust_len() {
        assert_eq!(
            classify_condition("input.len() > 100"),
            PredicateKind::BoundedLength
        );
        assert_eq!(
            classify_condition("s.len() >= 256"),
            PredicateKind::BoundedLength
        );
        assert_eq!(
            classify_condition("s.len() < 4096"),
            PredicateKind::BoundedLength
        );
    }

    #[test]
    fn classify_bounded_length_js_length() {
        assert_eq!(
            classify_condition("input.length > 100"),
            PredicateKind::BoundedLength
        );
    }

    #[test]
    fn classify_non_empty_len_stays_comparison() {
        // `.len() > 0` is a non-empty check, NOT a bounded-length validation.
        // Must fall through to Comparison.
        assert_eq!(
            classify_condition("input.len() > 0"),
            PredicateKind::Comparison
        );
        assert_eq!(
            classify_condition("s.len() >= 1"),
            PredicateKind::Comparison
        );
    }

    // ── Helper sanity ─────────────────────────────────────────────────────

    #[test]
    fn shell_metachar_rejection_detects_common_chars() {
        for m in &[";", "|", "&", "`", "$", ">", "<"] {
            let text = format!("x.contains(\"{m}\")");
            assert!(
                is_shell_metachar_rejection(&text),
                "should detect metachar {m:?} in {text:?}"
            );
        }
    }

    #[test]
    fn shell_metachar_rejection_rejects_non_metachar() {
        assert!(!is_shell_metachar_rejection("x.contains(\"foo\")"));
        assert!(!is_shell_metachar_rejection("x.contains(\"admin\")"));
        assert!(!is_shell_metachar_rejection("x.contains(\"..\")"));
    }

    #[test]
    fn shell_metachar_rejection_handles_escapes() {
        assert!(is_shell_metachar_rejection("x.contains(\"\\n\")"));
    }

    #[test]
    fn bounded_length_rejects_zero_and_one() {
        assert!(!is_bounded_length_check("x.len() > 0"));
        assert!(!is_bounded_length_check("x.len() >= 1"));
        assert!(!is_bounded_length_check("x.len() < 1"));
    }

    #[test]
    fn bounded_length_accepts_small_bounds() {
        assert!(is_bounded_length_check("x.len() > 2"));
        assert!(is_bounded_length_check("x.len() <= 256"));
    }
}
