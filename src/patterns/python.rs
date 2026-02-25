use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Python AST patterns.
///
/// Taint rules cover `eval`/`exec`, `os.system`/`os.popen`/`subprocess.*`,
/// and `cursor.execute`. AST patterns here add coverage for **deserialization**,
/// **subprocess shell=True** (Tier B — taint doesn't check keyword args), and
/// **code execution** sinks that taint cannot structurally verify.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "py.code_exec.eval",
        description: "eval() — dynamic code execution",
        query: r#"(call function: (identifier) @id (#eq? @id "eval")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    Pattern {
        id: "py.code_exec.exec",
        description: "exec() — dynamic code execution",
        query: r#"(call function: (identifier) @id (#eq? @id "exec")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    Pattern {
        id: "py.code_exec.compile",
        description: "compile() with exec/eval mode — code compilation from string",
        query: r#"(call function: (identifier) @id (#eq? @id "compile")) @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "py.cmdi.os_system",
        description: "os.system() — shell command execution",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "os")
                       attribute: (identifier) @fn (#eq? @fn "system")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
    },
    Pattern {
        id: "py.cmdi.os_popen",
        description: "os.popen() — shell command execution",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "os")
                       attribute: (identifier) @fn (#eq? @fn "popen")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
    },
    // ── Tier B: subprocess with shell=True ─────────────────────────────
    Pattern {
        id: "py.cmdi.subprocess_shell",
        description: "subprocess call with shell=True",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "subprocess"))
                     arguments: (argument_list
                       (keyword_argument
                         name: (identifier) @k (#eq? @k "shell")
                         value: (true))))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::B,
        category: PatternCategory::CommandExec,
    },
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "py.deser.pickle_loads",
        description: "pickle.loads/load — arbitrary object deserialization",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "pickle")
                       attribute: (identifier) @fn (#match? @fn "^loads?$")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
    },
    Pattern {
        id: "py.deser.yaml_load",
        description: "yaml.load() without SafeLoader — arbitrary object instantiation",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "yaml")
                       attribute: (identifier) @fn (#eq? @fn "load")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
    },
    Pattern {
        id: "py.deser.shelve_open",
        description: "shelve.open() — pickle-backed deserialization",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "shelve")
                       attribute: (identifier) @fn (#eq? @fn "open")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
    },
    // ── Tier B: SQL injection (format/concat heuristic) ────────────────
    Pattern {
        id: "py.sqli.execute_format",
        description: "cursor.execute with string concatenation — SQL injection risk",
        query: r#"(call
                     function: (attribute
                       attribute: (identifier) @fn (#eq? @fn "execute"))
                     arguments: (argument_list
                       (binary_operator) @arg))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "py.crypto.md5",
        description: "hashlib.md5() — weak hash algorithm",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "hashlib")
                       attribute: (identifier) @fn (#eq? @fn "md5")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
    },
    Pattern {
        id: "py.crypto.sha1",
        description: "hashlib.sha1() — weak hash algorithm",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "hashlib")
                       attribute: (identifier) @fn (#eq? @fn "sha1")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
    },
    // ── Tier A: Template injection ─────────────────────────────────────
    Pattern {
        id: "py.xss.jinja_from_string",
        description: "jinja2.Template from string — potential template injection",
        query: r#"(call
                     function: (attribute
                       attribute: (identifier) @fn (#eq? @fn "from_string")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
    },
];
