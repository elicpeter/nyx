use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// TypeScript AST patterns.
///
/// TypeScript shares most patterns with JavaScript. Taint rules cover `eval`,
/// `innerHTML`, and `child_process.*` sinks. AST patterns here mirror JS
/// patterns plus TS-specific `any` type-safety escapes.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "ts.code_exec.eval",
        description: "eval() — dynamic code execution",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "eval"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    Pattern {
        id: "ts.code_exec.new_function",
        description: "new Function() constructor — eval equivalent",
        query: r#"(new_expression
                     constructor: (identifier) @id (#eq? @id "Function"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    Pattern {
        id: "ts.code_exec.settimeout_string",
        description: "setTimeout/setInterval with string argument — implicit eval",
        query: r#"(call_expression
                     function: (identifier) @id (#match? @id "^(setTimeout|setInterval)$")
                     arguments: (arguments (string) @code))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
    },
    // ── Tier A: XSS sinks ──────────────────────────────────────────────
    Pattern {
        id: "ts.xss.document_write",
        description: "document.write() — XSS sink",
        query: r#"(call_expression
                     function: (member_expression
                       object: (identifier) @obj (#eq? @obj "document")
                       property: (property_identifier) @prop (#match? @prop "^(write|writeln)$")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
    },
    Pattern {
        id: "ts.xss.outer_html",
        description: "Assignment to .outerHTML — XSS sink",
        query: r#"(assignment_expression
                     left: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "outerHTML")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
    },
    Pattern {
        id: "ts.xss.insert_adjacent_html",
        description: "insertAdjacentHTML() — XSS sink",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "insertAdjacentHTML")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "ts.crypto.math_random",
        description: "Math.random() — not cryptographically secure",
        query: r#"(call_expression
                     function: (member_expression
                       object: (identifier) @obj (#eq? @obj "Math")
                       property: (property_identifier) @prop (#eq? @prop "random")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
    },
    // ── Tier A: TypeScript-specific type-safety escapes ────────────────
    Pattern {
        id: "ts.quality.any_annotation",
        description: "Type annotation of `any` — disables type checking",
        query: r#"(type_annotation (predefined_type) @t (#eq? @t "any")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
    },
    Pattern {
        id: "ts.quality.as_any",
        description: "Type assertion `as any` — type-safety escape hatch",
        query: r#"(as_expression (predefined_type) @t (#eq? @t "any")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
    },
    // ── Tier A: Prototype pollution ────────────────────────────────────
    Pattern {
        id: "ts.prototype.proto_assignment",
        description: "Assignment to __proto__ — prototype pollution",
        query: r#"(assignment_expression
                     left: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "__proto__")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Prototype,
    },
    // ── Tier A: Open redirect ──────────────────────────────────────────
    Pattern {
        id: "ts.xss.location_assign",
        description: "Assignment to location/location.href — open redirect",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (identifier) @obj (#match? @obj "^(window|location|document)$")
                       property: (property_identifier) @prop (#match? @prop "^(location|href)$")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
    },
    // ── Tier A: Cookie manipulation ────────────────────────────────────
    Pattern {
        id: "ts.xss.cookie_write",
        description: "Write to document.cookie",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (identifier) @obj (#eq? @obj "document")
                       property: (property_identifier) @prop (#eq? @prop "cookie")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
    },
];
