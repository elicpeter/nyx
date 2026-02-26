use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// PHP AST patterns.
///
/// Taint rules cover `system`/`exec`/`passthru`/`shell_exec` (command
/// injection), `echo`/`print` (XSS sinks), and `mysqli_query`/`pg_query`
/// (SQL sinks).  AST patterns here focus on **eval**, **deserialization**,
/// **deprecated dangerous functions**, **include with variable**, and
/// **SQL concatenation** (Tier B).
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "php.code_exec.eval",
        description: "eval() — dynamic code execution",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "eval"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "php.code_exec.create_function",
        description: "create_function() — deprecated eval-like constructor",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "create_function"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "php.code_exec.preg_replace_e",
        description: "preg_replace with /e modifier — code execution via regex",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "preg_replace")
                     arguments: (arguments
                       (argument
                         (string) @pat (#match? @pat "/[^/]*/[a-zA-Z]*e"))))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "php.code_exec.assert_string",
        description: "assert() with string argument — evaluates PHP code",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "assert")
                     arguments: (arguments
                       (argument (string) @code)))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "php.cmdi.system",
        description: "system/shell_exec/exec/passthru — shell command execution",
        query: r#"(function_call_expression
                     function: (name) @n (#match? @n "^(system|shell_exec|exec|passthru|proc_open|popen)$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "php.deser.unserialize",
        description: "unserialize() — PHP object injection",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "unserialize"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier B: SQL injection (concatenation heuristic) ────────────────
    Pattern {
        id: "php.sqli.query_concat",
        description: "mysql_query/mysqli_query with concatenated SQL string",
        query: r#"(function_call_expression
                     function: (name) @n (#match? @n "^(mysql_query|mysqli_query)$")
                     arguments: (arguments
                       (argument (binary_expression) @concat)))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
        confidence: Confidence::Medium,
    },
    // ── Tier B: Path traversal (include with variable) ─────────────────
    Pattern {
        id: "php.path.include_variable",
        description: "include/require with variable path — file inclusion vulnerability",
        query: r#"(include_expression (variable_name)) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::B,
        category: PatternCategory::PathTraversal,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Crypto ─────────────────────────────────────────────────
    Pattern {
        id: "php.crypto.md5",
        description: "md5() — weak hash function",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "md5"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "php.crypto.sha1",
        description: "sha1() — weak hash function",
        query: r#"(function_call_expression
                     function: (name) @n (#eq? @n "sha1"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "php.crypto.rand",
        description: "rand()/mt_rand() — not cryptographically secure",
        query: r#"(function_call_expression
                     function: (name) @n (#match? @n "^(rand|mt_rand)$"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
];
