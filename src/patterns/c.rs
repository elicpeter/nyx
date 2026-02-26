use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// C AST patterns.
///
/// Taint rules cover `system`/`popen`/`exec*` (command injection),
/// `sprintf`/`strcpy`/`strcat` (buffer overflow sinks), and `printf`/`fprintf`
/// (format-string sinks).  AST patterns here focus on **banned-by-default
/// functions** (`gets`, `scanf %s`) and **format-string** variants not covered
/// by taint, since these are dangerous regardless of data origin.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Banned functions (always dangerous) ────────────────────
    Pattern {
        id: "c.memory.gets",
        description: "gets() — no bounds checking, always exploitable",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "gets")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "c.memory.strcpy",
        description: "strcpy() — no bounds checking on destination buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "strcpy")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "c.memory.strcat",
        description: "strcat() — no bounds checking on destination buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "strcat")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "c.memory.sprintf",
        description: "sprintf() — no length limit on output buffer",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "sprintf")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "c.memory.scanf_percent_s",
        description: "scanf(\"%s\") — unbounded string read",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "scanf")
                     arguments: (argument_list
                       (string_literal) @fmt (#match? @fmt "%s")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "c.cmdi.system",
        description: "system() — shell command execution",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "system")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "c.cmdi.popen",
        description: "popen() — shell command execution with pipe",
        query: r#"(call_expression function: (identifier) @id (#eq? @id "popen")) @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Format-string ──────────────────────────────────────────
    Pattern {
        id: "c.memory.printf_no_fmt",
        description: "printf(var) — format-string vulnerability when first arg is not literal",
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
