use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Go AST patterns.
///
/// Taint rules cover `exec.Command` (command injection), `db.Query`/`db.Exec`
/// (SQL sinks).  AST patterns here focus on **TLS misconfiguration**,
/// **weak crypto**, **unsafe.Pointer**, and **hardcoded secrets**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "go.cmdi.exec_command",
        description: "exec.Command() — arbitrary process execution",
        query: r#"(call_expression
                     function: (selector_expression
                       field: (field_identifier) @f (#eq? @f "Command")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
    },
    // ── Tier A: Unsafe pointer ─────────────────────────────────────────
    Pattern {
        id: "go.memory.unsafe_pointer",
        description: "unsafe.Pointer — bypasses Go type system",
        query: r#"(call_expression
                     function: (selector_expression
                       operand: (identifier) @pkg (#eq? @pkg "unsafe")
                       field: (field_identifier) @f (#eq? @f "Pointer")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
    },
    // ── Tier A: TLS misconfiguration ───────────────────────────────────
    Pattern {
        id: "go.transport.insecure_skip_verify",
        description: "InsecureSkipVerify: true — disables TLS certificate validation",
        query: r#"(keyed_element
                     (literal_element
                       (identifier) @k (#eq? @k "InsecureSkipVerify"))
                     (literal_element (true)))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::InsecureTransport,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "go.crypto.md5",
        description: "md5.New() / md5.Sum() — weak hash algorithm",
        query: r#"(call_expression
                     function: (selector_expression
                       operand: (identifier) @pkg (#eq? @pkg "md5")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
    },
    Pattern {
        id: "go.crypto.sha1",
        description: "sha1.New() / sha1.Sum() — weak hash algorithm",
        query: r#"(call_expression
                     function: (selector_expression
                       operand: (identifier) @pkg (#eq? @pkg "sha1")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
    },
    // ── Tier B: SQL injection (concatenation heuristic) ────────────────
    Pattern {
        id: "go.sqli.query_concat",
        description: "db.Query/Exec with concatenated string argument",
        query: r#"(call_expression
                     function: (selector_expression
                       field: (field_identifier) @f (#match? @f "^(Query|Exec|QueryRow)$"))
                     arguments: (argument_list
                       (binary_expression) @concat))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
    },
    // ── Tier A: Hardcoded secrets ──────────────────────────────────────
    Pattern {
        id: "go.secrets.hardcoded_key",
        description: "Variable with secret-like name assigned a string literal",
        query: r#"(short_var_declaration
                     left: (expression_list
                       (identifier) @name (#match? @name "(?i)(password|secret|api_?key|token|private_?key)"))
                     right: (expression_list
                       (interpreted_string_literal) @val))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Secrets,
    },
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "go.deser.gob_decode",
        description: "gob.NewDecoder — Go binary deserialization",
        query: r#"(call_expression
                     function: (selector_expression
                       operand: (identifier) @pkg (#eq? @pkg "gob")
                       field: (field_identifier) @f (#eq? @f "NewDecoder")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
    },
];
