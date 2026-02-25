use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Ruby AST patterns.
///
/// Taint rules cover `system`/`exec` (command injection), `eval` (code
/// execution), and `puts`/`print` (output sinks).  AST patterns here focus on
/// **deserialization** (YAML.load, Marshal.load), **instance_eval/class_eval**,
/// **backtick shell**, **send with dynamic arg**, and **constantize**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "rb.code_exec.eval",
        description: "Kernel#eval — dynamic code execution",
        query: r#"(call (identifier) @id (#eq? @id "eval")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    Pattern {
        id: "rb.code_exec.instance_eval",
        description: "instance_eval — evaluates string in object context",
        query: r#"(call
                     method: (identifier) @id (#eq? @id "instance_eval"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    Pattern {
        id: "rb.code_exec.class_eval",
        description: "class_eval / module_eval — evaluates string in class context",
        query: r#"(call
                     method: (identifier) @id (#match? @id "^(class_eval|module_eval)$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "rb.cmdi.backtick",
        description: "Backtick shell execution",
        query: r#"(subshell) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
    },
    // ── Tier B: Shell with interpolation ───────────────────────────────
    Pattern {
        id: "rb.cmdi.system_interp",
        description: "system/exec with string interpolation — command injection risk",
        query: r#"(call
                     method: (identifier) @m (#match? @m "^(system|exec)$")
                     arguments: (argument_list
                       (string
                         (interpolation)+ @vuln)))
        "#,
        severity: Severity::High,
        tier: PatternTier::B,
        category: PatternCategory::CommandExec,
    },
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "rb.deser.yaml_load",
        description: "YAML.load — arbitrary object deserialization (use safe_load instead)",
        query: r#"(call
                     receiver: (constant) @recv (#match? @recv "^(YAML|Psych)$")
                     method: (identifier) @m (#eq? @m "load"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
    },
    Pattern {
        id: "rb.deser.marshal_load",
        description: "Marshal.load — arbitrary Ruby object deserialization",
        query: r#"(call
                     receiver: (constant) @recv (#eq? @recv "Marshal")
                     method: (identifier) @m (#eq? @m "load"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
    },
    // ── Tier A: Reflection ─────────────────────────────────────────────
    Pattern {
        id: "rb.reflection.send_dynamic",
        description: "send() with non-symbol argument — arbitrary method dispatch",
        query: r#"(call
                     method: (identifier) @m (#eq? @m "send")
                     arguments: (argument_list
                       [(identifier) (string (interpolation)+)] @vuln))
        "#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::Reflection,
    },
    Pattern {
        id: "rb.reflection.constantize",
        description: "constantize / safe_constantize — dynamic class resolution",
        query: r#"(call
                     method: (identifier) @m (#match? @m "^(constantize|safe_constantize)$"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Reflection,
    },
    // ── Tier A: SSRF ───────────────────────────────────────────────────
    Pattern {
        id: "rb.ssrf.open_uri",
        description: "Kernel#open with HTTP URL — SSRF via open-uri",
        query: r#"(call
                     method: (identifier) @m (#eq? @m "open")
                     arguments: (argument_list
                       (string) @url (#match? @url "^\"https?://")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::InsecureTransport,
    },
    // ── Tier A: Crypto ─────────────────────────────────────────────────
    Pattern {
        id: "rb.crypto.md5",
        description: "Digest::MD5 — weak hash algorithm",
        query: r#"(scope_resolution
                     name: (constant) @c (#eq? @c "MD5"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
    },
];
