use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Java AST patterns.
///
/// Taint rules cover `Runtime.exec` (command injection) and
/// `executeQuery`/`executeUpdate`/`prepareStatement` (SQL sinks).
/// AST patterns here focus on **deserialization**, **reflection**,
/// **SQL with concatenation** (Tier B heuristic), and **weak crypto**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "java.deser.readobject",
        description: "ObjectInputStream.readObject() — unsafe deserialization",
        // Match any .readObject() call — the method name is specific enough.
        query: r#"(method_invocation
                     name: (identifier) @id (#eq? @id "readObject"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "java.cmdi.runtime_exec",
        description: "Runtime.getRuntime().exec() — shell command execution",
        query: r#"(method_invocation
                     object: (method_invocation
                       name: (identifier) @n (#eq? @n "getRuntime"))
                     name: (identifier) @id (#eq? @id "exec"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Reflection ─────────────────────────────────────────────
    Pattern {
        id: "java.reflection.class_forname",
        description: "Class.forName() — dynamic class loading",
        query: r#"(method_invocation
                     object: (identifier) @c (#eq? @c "Class")
                     name: (identifier) @id (#eq? @id "forName"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Reflection,
        confidence: Confidence::High,
    },
    Pattern {
        id: "java.reflection.method_invoke",
        description: "Method.invoke() — reflective method invocation",
        query: r#"(method_invocation
                     name: (identifier) @id (#eq? @id "invoke"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Reflection,
        confidence: Confidence::High,
    },
    // ── Tier B: SQL injection (concatenation heuristic) ────────────────
    Pattern {
        id: "java.sqli.execute_concat",
        description: "SQL execute with concatenated string argument",
        query: r#"(method_invocation
                     name: (identifier) @id (#match? @id "^execute(Query|Update)?$")
                     arguments: (argument_list
                       (binary_expression) @concat))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "java.crypto.insecure_random",
        description: "new Random() — java.util.Random is not cryptographically secure",
        query: r#"(object_creation_expression
                     type: (type_identifier) @t (#eq? @t "Random"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "java.crypto.weak_digest",
        description: "MessageDigest.getInstance(\"MD5\"/\"SHA1\") — weak hash algorithm",
        query: r#"(method_invocation
                     object: (identifier) @c (#eq? @c "MessageDigest")
                     name: (identifier) @id (#eq? @id "getInstance")
                     arguments: (argument_list
                       (string_literal) @alg (#match? @alg "(?i)(md5|sha-?1)")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    // ── Tier A: XSS (servlet) ──────────────────────────────────────────
    Pattern {
        id: "java.xss.getwriter_print",
        description: "response.getWriter().print/println — direct output without encoding",
        query: r#"(method_invocation
                     object: (method_invocation
                       name: (identifier) @gw (#eq? @gw "getWriter"))
                     name: (identifier) @id (#match? @id "^(print|println|write)$"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
];
