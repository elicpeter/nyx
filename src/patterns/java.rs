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
        description: "ObjectInputStream.readObject() performs unsafe deserialization",
        // Match any .readObject() call — the method name is specific enough.
        query: r#"(method_invocation
                     name: (identifier) @id (#eq? @id "readObject"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier A: SnakeYAML deserialization (CVE-2022-1471) ──────────────
    // `new Yaml()` constructed without a `SafeConstructor` argument
    // accepts arbitrary YAML tags (`!!javax.script.ScriptEngineManager`,
    // `!!java.net.URLClassLoader`, …) and instantiates any class via
    // reflection. SnakeYAML 2.0 swapped the default to SafeConstructor
    // but pre-2.0 deployments stay vulnerable until call sites are
    // patched. We match the empty-arg form `new Yaml()` only, so the
    // explicit-SafeConstructor remediation form
    // `new Yaml(new SafeConstructor(new LoaderOptions()))` is silent.
    Pattern {
        id: "java.deser.snakeyaml_unsafe_constructor",
        description: "new Yaml() without SafeConstructor accepts arbitrary class tags (CVE-2022-1471)",
        query: r#"(object_creation_expression
                     type: (type_identifier) @t (#eq? @t "Yaml")
                     arguments: (argument_list) @args (#eq? @args "()"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier A: Apache Commons Text Text4Shell (CVE-2022-42889) ────────
    // `StringSubstitutor.createInterpolator()` enables `script:`,
    // `dns:`, and `url:` lookups by default — `${script:js:…}`
    // evaluates JavaScript via the JSR-223 ScriptEngineManager. The
    // factory call is itself the structural bug; the recommended app-
    // side mitigation builds a `StringSubstitutor` directly with a
    // restricted lookup map.
    Pattern {
        id: "java.code_exec.text4shell_interpolator",
        description: "StringSubstitutor.createInterpolator() enables script:/dns:/url: evaluation (CVE-2022-42889)",
        query: r#"(method_invocation
                     object: (identifier) @c (#eq? @c "StringSubstitutor")
                     name: (identifier) @id (#eq? @id "createInterpolator"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "java.cmdi.runtime_exec",
        description: "Runtime.getRuntime().exec() runs a shell command",
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
        description: "Class.forName() performs dynamic class loading",
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
        description: "Method.invoke() is a reflective method invocation",
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
        description: "new Random() (java.util.Random) is not cryptographically secure",
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
        description: "MessageDigest.getInstance(\"MD5\"/\"SHA1\") uses a weak hash algorithm",
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
        description: "response.getWriter().print/println writes output without encoding",
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
