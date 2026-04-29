use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// C++ AST patterns.
///
/// Inherits C banned-function concerns plus C++-specific patterns like
/// `reinterpret_cast` and `const_cast`.  Taint rules overlap with C rules
/// for `system`/`sprintf`/`strcpy`/`strcat`.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Banned C functions (inherited) ─────────────────────────
    Pattern {
        id: "cpp.memory.gets",
        description: "gets() has no bounds checking and is always exploitable",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "gets")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "cpp.memory.strcpy",
        description: "strcpy() does not bounds-check the destination buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "strcpy")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "cpp.memory.strcat",
        description: "strcat() does not bounds-check the destination buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "strcat")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "cpp.memory.sprintf",
        description: "sprintf() does not limit the output buffer length",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "sprintf")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "cpp.cmdi.system",
        description: "system() runs a shell command",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "system")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "cpp.cmdi.popen",
        description: "popen() runs a shell command",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "popen")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Dangerous casts ────────────────────────────────────────
    // C++ casts are parsed as call_expression with template_function
    Pattern {
        id: "cpp.memory.reinterpret_cast",
        description: "reinterpret_cast performs a type-punning cast",
        query: r#"(call_expression
                     function: (template_function
                       name: (identifier) @n (#eq? @n "reinterpret_cast")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "cpp.memory.const_cast",
        description: "const_cast removes the const/volatile qualifier",
        query: r#"(call_expression
                     function: (template_function
                       name: (identifier) @n (#eq? @n "const_cast")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    // ── Tier B: Format-string (variable first arg) ─────────────────────
    Pattern {
        id: "cpp.memory.printf_no_fmt",
        description: "printf(var) is a format-string vulnerability when the first arg is not a literal",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "printf")
                     arguments: (argument_list
                       . (identifier) @arg))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::B,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::Medium,
    },
];
