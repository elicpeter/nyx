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
        description: "gets() — no bounds checking, always exploitable",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "gets")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    Pattern {
        id: "cpp.memory.strcpy",
        description: "strcpy() — no bounds checking on destination buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "strcpy")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    Pattern {
        id: "cpp.memory.strcat",
        description: "strcat() — no bounds checking on destination buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "strcat")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    Pattern {
        id: "cpp.memory.sprintf",
        description: "sprintf() — no length limit on output buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "sprintf")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "cpp.cmdi.system",
        description: "system() — shell command execution",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "system")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
    },
    // ── Tier A: Dangerous casts ────────────────────────────────────────
    // C++ casts are parsed as call_expression with template_function
    Pattern {
        id: "cpp.memory.reinterpret_cast",
        description: "reinterpret_cast — type-punning cast",
        query: r#"(call_expression
                     function: (template_function
                       name: (identifier) @n (#eq? @n "reinterpret_cast")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    Pattern {
        id: "cpp.memory.const_cast",
        description: "const_cast — removes const/volatile qualifier",
        query: r#"(call_expression
                     function: (template_function
                       name: (identifier) @n (#eq? @n "const_cast")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    // ── Tier B: Format-string (variable first arg) ─────────────────────
    Pattern {
        id: "cpp.memory.printf_no_fmt",
        description: "printf(var) — format-string vulnerability when first arg is not literal",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "printf")
                     arguments: (argument_list
                       . (identifier) @arg))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::B,
        category: PatternCategory::MemorySafety,
    },
];
