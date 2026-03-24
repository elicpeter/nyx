//! String method recognition, concrete evaluation, and sanitizer detection
//! for Phase 22: Symbolic String Theory.
//!
//! Maps callee names to semantic string operations across languages, enabling
//! structured symbolic modeling instead of opaque `Call` nodes.

use crate::labels::Cap;
use crate::symbol::Lang;

use super::value::SymbolicValue;

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// Recognized string operation semantic.
#[derive(Clone, Debug, PartialEq)]
pub enum StringMethod {
    Trim,
    ToLower,
    ToUpper,
    Replace { pattern: String, replacement: String },
    Substr,
    StrLen,
}

/// Where the string operand comes from in the call.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StringOperandSource {
    /// `receiver.method()` — JS, Java, Ruby, Rust
    Receiver,
    /// `func(string, ...)` — Python `len()`, Go `strings.*`, PHP `strlen()`
    FirstArg,
}

/// Result of classifying a callee as a string method.
#[derive(Clone, Debug)]
pub struct StringMethodInfo {
    pub method: StringMethod,
    pub operand_source: StringOperandSource,
}

/// Information about a Replace operation that acts as a sanitizer.
#[derive(Clone, Debug)]
pub struct SanitizerInfo {
    /// Which capability bits this replace sanitizes.
    pub sanitized_caps: Cap,
    /// Whether the replacement is global (replaces all occurrences).
    pub is_global: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
//  String method classification
// ─────────────────────────────────────────────────────────────────────────────

/// Classify a callee as a recognized string method.
///
/// Returns `None` for unrecognized methods (fall through to opaque `Call`).
/// For `Replace`, only classifies when pattern and replacement args are concrete
/// strings — dynamic patterns produce `None`.
pub fn classify_string_method(
    callee: &str,
    args: &[SymbolicValue],
    lang: Lang,
) -> Option<StringMethodInfo> {
    let method = callee.rsplit('.').next().unwrap_or(callee);

    match lang {
        Lang::JavaScript | Lang::TypeScript => classify_js(method, args),
        Lang::Python => classify_python(method, callee, args),
        Lang::Ruby => classify_ruby(method, args),
        Lang::Java => classify_java(method, args),
        Lang::Go => classify_go(method, callee, args),
        Lang::Php => classify_php(method, callee, args),
        Lang::Rust => classify_rust(method, args),
        Lang::C | Lang::Cpp => classify_c(method),
    }
}

fn classify_js(method: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "trim" | "trimStart" | "trimEnd" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "toLowerCase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "toUpperCase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "replace" | "replaceAll" => {
            // args layout: [receiver_sym, pattern_arg, replacement_arg]
            // receiver is prepended by transfer.rs when present
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        "substring" | "substr" | "slice" => {
            // Only model when indices are concrete
            if has_concrete_index(args, 1) {
                Some(StringMethodInfo {
                    method: Substr,
                    operand_source: Receiver,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn classify_python(
    method: &str,
    callee: &str,
    args: &[SymbolicValue],
) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    // Python builtins: len(s) — no receiver
    if callee == "len" {
        return Some(StringMethodInfo {
            method: StrLen,
            operand_source: FirstArg,
        });
    }

    match method {
        "strip" | "lstrip" | "rstrip" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "lower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "upper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "replace" => {
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        _ => None,
    }
}

fn classify_ruby(method: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "strip" | "lstrip" | "rstrip" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "downcase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "upcase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "gsub" | "sub" => {
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        "length" | "size" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: Receiver,
        }),
        _ => None,
    }
}

fn classify_java(method: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "trim" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "toLowerCase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "toUpperCase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "replace" | "replaceAll" => {
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        "substring" => {
            if has_concrete_index(args, 1) {
                Some(StringMethodInfo {
                    method: Substr,
                    operand_source: Receiver,
                })
            } else {
                None
            }
        }
        "length" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: Receiver,
        }),
        _ => None,
    }
}

fn classify_go(
    method: &str,
    callee: &str,
    args: &[SymbolicValue],
) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    // Go uses package functions: strings.TrimSpace(s), strings.ToLower(s)
    // The full callee is needed to check the package prefix.
    match callee {
        "strings.TrimSpace" => Some(StringMethodInfo {
            method: Trim,
            operand_source: FirstArg,
        }),
        "strings.ToLower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: FirstArg,
        }),
        "strings.ToUpper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: FirstArg,
        }),
        "strings.Replace" | "strings.ReplaceAll" => {
            // Go: strings.Replace(s, old, new, n) or strings.ReplaceAll(s, old, new)
            // args[0] = string, args[1] = pattern, args[2] = replacement
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: FirstArg,
            })
        }
        _ => {
            // Fallback: check method name for len()
            if method == "len" {
                Some(StringMethodInfo {
                    method: StrLen,
                    operand_source: FirstArg,
                })
            } else {
                None
            }
        }
    }
}

fn classify_php(
    method: &str,
    callee: &str,
    args: &[SymbolicValue],
) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    // PHP uses free functions: trim($s), strtolower($s)
    match callee {
        "trim" | "ltrim" | "rtrim" => Some(StringMethodInfo {
            method: Trim,
            operand_source: FirstArg,
        }),
        "strtolower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: FirstArg,
        }),
        "strtoupper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: FirstArg,
        }),
        "str_replace" => {
            // PHP: str_replace($search, $replace, $subject) — string is arg[2]
            // But in our callee model, receiver is not present for free functions.
            // args[0] = pattern, args[1] = replacement, args[2] = subject
            let (pat, rep) = extract_replace_args(args, 0)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: FirstArg,
            })
        }
        "strlen" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: FirstArg,
        }),
        "substr" => {
            if has_concrete_index(args, 1) {
                Some(StringMethodInfo {
                    method: Substr,
                    operand_source: FirstArg,
                })
            } else {
                None
            }
        }
        _ => {
            // Fallback: check method name only
            match method {
                "trim" => Some(StringMethodInfo {
                    method: Trim,
                    operand_source: Receiver,
                }),
                _ => None,
            }
        }
    }
}

fn classify_rust(method: &str, _args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "trim" | "trim_start" | "trim_end" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "to_lowercase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "to_uppercase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "len" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: Receiver,
        }),
        _ => None,
    }
}

fn classify_c(method: &str) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "tolower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: FirstArg,
        }),
        "toupper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: FirstArg,
        }),
        "strlen" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Arg extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract concrete pattern and replacement strings from args at given offset.
///
/// `offset` is the index of the pattern arg (replacement is offset+1).
/// Returns `None` if either is not `ConcreteStr`.
fn extract_replace_args(
    args: &[SymbolicValue],
    offset: usize,
) -> Option<(String, String)> {
    let pat = args.get(offset)?.as_concrete_str()?;
    let rep = args.get(offset + 1)?.as_concrete_str()?;
    Some((pat.to_owned(), rep.to_owned()))
}

/// Check that the arg at `offset` is a concrete integer (for Substr indices).
fn has_concrete_index(args: &[SymbolicValue], offset: usize) -> bool {
    args.get(offset)
        .map(|a| a.as_concrete_int().is_some())
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Concrete evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate a string operation on a concrete receiver string.
///
/// Returns the folded result, or `None` if the receiver is not concrete.
pub fn evaluate_string_op_concrete(
    method: &StringMethod,
    receiver: &str,
) -> Option<SymbolicValue> {
    match method {
        StringMethod::Trim => Some(SymbolicValue::ConcreteStr(receiver.trim().to_owned())),
        StringMethod::ToLower => {
            Some(SymbolicValue::ConcreteStr(receiver.to_lowercase()))
        }
        StringMethod::ToUpper => {
            Some(SymbolicValue::ConcreteStr(receiver.to_uppercase()))
        }
        StringMethod::Replace { pattern, replacement } => Some(SymbolicValue::ConcreteStr(
            receiver.replace(pattern.as_str(), replacement.as_str()),
        )),
        StringMethod::StrLen => Some(SymbolicValue::Concrete(receiver.len() as i64)),
        StringMethod::Substr => {
            // Substr needs index args — concrete evaluation handled in smart constructor
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sanitizer detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect whether a Replace operation acts as a security sanitizer.
///
/// Returns `None` if the pattern is not security-relevant. This is conservative:
/// Phase 22 does NOT clear taint via Replace — detection is informational only
/// for witness quality.
pub fn detect_replace_sanitizer(
    pattern: &str,
    _replacement: &str,
    callee: &str,
    lang: Lang,
) -> Option<SanitizerInfo> {
    let is_global = is_global_replace(callee, lang);

    let mut caps = Cap::empty();

    // XSS: HTML entity escaping patterns
    if pattern == "<" || pattern == ">" || pattern == "\"" || pattern == "'"
        || pattern.contains("<script")
        || pattern.contains("<img")
        || pattern.contains("<svg")
    {
        caps |= Cap::HTML_ESCAPE;
    }

    // SQLi: quote escaping patterns
    if pattern == "'" || pattern == "\"" || pattern == "--" || pattern == ";" {
        caps |= Cap::SQL_QUERY;
    }

    // CMDi: shell metachar escaping patterns
    if pattern == "$" || pattern == "`" || pattern == "|" || pattern == ";"
        || pattern == "&"
    {
        caps |= Cap::SHELL_ESCAPE;
    }

    if caps.is_empty() {
        None
    } else {
        Some(SanitizerInfo {
            sanitized_caps: caps,
            is_global,
        })
    }
}

/// Determine whether a replace call is global (replaces all occurrences).
fn is_global_replace(callee: &str, lang: Lang) -> bool {
    let method = callee.rsplit('.').next().unwrap_or(callee);
    match lang {
        // JS: replace() is NOT global; replaceAll() IS global
        Lang::JavaScript | Lang::TypeScript => method == "replaceAll",
        // Python: str.replace() is always global
        Lang::Python => true,
        // Ruby: gsub is global, sub is not
        Lang::Ruby => method == "gsub",
        // Java: both replace() and replaceAll() are global for CharSequence
        Lang::Java => true,
        // Go: strings.ReplaceAll is global, strings.Replace with n=-1 is global
        // (conservative: assume not global for strings.Replace)
        Lang::Go => callee == "strings.ReplaceAll",
        // PHP: str_replace() is always global
        Lang::Php => true,
        // Rust: str.replace() is always global
        Lang::Rust => true,
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_js_trim() {
        let info = classify_string_method("input.trim", &[], Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
        assert_eq!(info.operand_source, StringOperandSource::Receiver);
    }

    #[test]
    fn test_classify_js_to_lower() {
        let info = classify_string_method("s.toLowerCase", &[], Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
    }

    #[test]
    fn test_classify_js_to_upper() {
        let info = classify_string_method("s.toUpperCase", &[], Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::ToUpper);
    }

    #[test]
    fn test_classify_js_replace_concrete() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::ConcreteStr("<".into()),              // pattern
            SymbolicValue::ConcreteStr("&lt;".into()),           // replacement
        ];
        let info = classify_string_method("s.replace", &args, Lang::JavaScript).unwrap();
        match &info.method {
            StringMethod::Replace { pattern, replacement } => {
                assert_eq!(pattern, "<");
                assert_eq!(replacement, "&lt;");
            }
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_js_replace_dynamic_pattern() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(1)), // dynamic pattern
            SymbolicValue::ConcreteStr("".into()),               // replacement
        ];
        assert!(classify_string_method("s.replace", &args, Lang::JavaScript).is_none());
    }

    #[test]
    fn test_classify_js_substring_concrete_index() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::Concrete(0),                          // start
        ];
        let info = classify_string_method("s.substring", &args, Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::Substr);
    }

    #[test]
    fn test_classify_js_substring_dynamic_index() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(1)), // dynamic index
        ];
        assert!(classify_string_method("s.substring", &args, Lang::JavaScript).is_none());
    }

    #[test]
    fn test_classify_python_strip() {
        let info = classify_string_method("s.strip", &[], Lang::Python).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
        assert_eq!(info.operand_source, StringOperandSource::Receiver);
    }

    #[test]
    fn test_classify_python_lower() {
        let info = classify_string_method("s.lower", &[], Lang::Python).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
    }

    #[test]
    fn test_classify_python_len() {
        let info = classify_string_method("len", &[], Lang::Python).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_ruby_downcase() {
        let info = classify_string_method("s.downcase", &[], Lang::Ruby).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
    }

    #[test]
    fn test_classify_ruby_gsub() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)),
            SymbolicValue::ConcreteStr("<".into()),
            SymbolicValue::ConcreteStr("&lt;".into()),
        ];
        let info = classify_string_method("s.gsub", &args, Lang::Ruby).unwrap();
        match &info.method {
            StringMethod::Replace { .. } => {}
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_java_trim() {
        let info = classify_string_method("s.trim", &[], Lang::Java).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
    }

    #[test]
    fn test_classify_java_length() {
        let info = classify_string_method("s.length", &[], Lang::Java).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
    }

    #[test]
    fn test_classify_go_trim_space() {
        let info = classify_string_method("strings.TrimSpace", &[], Lang::Go).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_go_to_lower() {
        let info = classify_string_method("strings.ToLower", &[], Lang::Go).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_php_strtolower() {
        let info = classify_string_method("strtolower", &[], Lang::Php).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_php_strlen() {
        let info = classify_string_method("strlen", &[], Lang::Php).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
    }

    #[test]
    fn test_classify_rust_trim() {
        let info = classify_string_method("s.trim", &[], Lang::Rust).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
    }

    #[test]
    fn test_classify_c_strlen() {
        let info = classify_string_method("strlen", &[], Lang::C).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
    }

    #[test]
    fn test_classify_unknown_method_returns_none() {
        assert!(classify_string_method("foo.bar", &[], Lang::JavaScript).is_none());
        assert!(classify_string_method("unknown", &[], Lang::Python).is_none());
    }

    // ── Concrete evaluation ────────────────────────────────────────────────

    #[test]
    fn test_evaluate_trim() {
        let result = evaluate_string_op_concrete(&StringMethod::Trim, "  hello  ");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("hello".into())));
    }

    #[test]
    fn test_evaluate_to_lower() {
        let result = evaluate_string_op_concrete(&StringMethod::ToLower, "ABC");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("abc".into())));
    }

    #[test]
    fn test_evaluate_to_upper() {
        let result = evaluate_string_op_concrete(&StringMethod::ToUpper, "abc");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("ABC".into())));
    }

    #[test]
    fn test_evaluate_replace() {
        let method = StringMethod::Replace {
            pattern: "<script>".into(),
            replacement: "".into(),
        };
        let result = evaluate_string_op_concrete(&method, "a<script>b");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("ab".into())));
    }

    #[test]
    fn test_evaluate_strlen() {
        let result = evaluate_string_op_concrete(&StringMethod::StrLen, "hello");
        assert_eq!(result, Some(SymbolicValue::Concrete(5)));
    }

    #[test]
    fn test_evaluate_substr_returns_none() {
        // Substr needs index args — concrete eval handled in smart constructor
        let result = evaluate_string_op_concrete(&StringMethod::Substr, "hello");
        assert_eq!(result, None);
    }

    // ── Sanitizer detection ────────────────────────────────────────────────

    #[test]
    fn test_detect_xss_sanitizer() {
        let info =
            detect_replace_sanitizer("<", "&lt;", "s.replaceAll", Lang::JavaScript).unwrap();
        assert!(info.sanitized_caps.contains(Cap::HTML_ESCAPE));
        assert!(info.is_global);
    }

    #[test]
    fn test_detect_xss_non_global() {
        let info =
            detect_replace_sanitizer("<", "&lt;", "s.replace", Lang::JavaScript).unwrap();
        assert!(info.sanitized_caps.contains(Cap::HTML_ESCAPE));
        assert!(!info.is_global);
    }

    #[test]
    fn test_detect_sqli_sanitizer() {
        let info =
            detect_replace_sanitizer("'", "''", "s.replace", Lang::Python).unwrap();
        assert!(info.sanitized_caps.contains(Cap::SQL_QUERY));
        assert!(info.is_global); // Python replace is global
    }

    #[test]
    fn test_detect_cmdi_sanitizer() {
        let info =
            detect_replace_sanitizer("|", "", "s.replace", Lang::Python).unwrap();
        assert!(info.sanitized_caps.contains(Cap::SHELL_ESCAPE));
    }

    #[test]
    fn test_detect_no_sanitizer_for_neutral_pattern() {
        assert!(detect_replace_sanitizer("foo", "bar", "s.replace", Lang::JavaScript).is_none());
    }

    #[test]
    fn test_global_replace_ruby_gsub() {
        assert!(is_global_replace("s.gsub", Lang::Ruby));
        assert!(!is_global_replace("s.sub", Lang::Ruby));
    }

    #[test]
    fn test_global_replace_go() {
        assert!(is_global_replace("strings.ReplaceAll", Lang::Go));
        assert!(!is_global_replace("strings.Replace", Lang::Go));
    }
}
