use crate::evidence::Confidence;
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
        confidence: Confidence::High,
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
        confidence: Confidence::High,
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
        confidence: Confidence::High,
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
        confidence: Confidence::High,
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
        confidence: Confidence::High,
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
        confidence: Confidence::High,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "ts.crypto.weak_hash",
        description: "crypto.createHash with weak algorithm (md5/sha1)",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "createHash"))
                     arguments: (arguments
                       (string) @alg (#match? @alg "\"(md5|sha1)\"")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "ts.crypto.weak_hash_import",
        description: "Direct md5()/sha1() call — weak hash from imported package",
        query: r#"(call_expression
                     function: (identifier) @id (#match? @id "^(md5|sha1)$"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
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
        confidence: Confidence::Medium,
    },
    // ── Tier A: Hardcoded secrets ───────────────────────────────────────
    Pattern {
        id: "ts.secrets.hardcoded_secret",
        description: "Hardcoded secret/password/API key in source code",
        query: r#"(pair
                     key: (property_identifier) @key
                       (#match? @key "^(secret|password|api_key|apiKey|apiSecret|api_secret|SESSION_SECRET|secretKey|secret_key|privateKey|private_key)$")
                     value: (string) @val)
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Secrets,
        confidence: Confidence::Medium,
    },
    // ── Tier A: TypeScript-specific type-safety escapes ────────────────
    Pattern {
        id: "ts.quality.any_annotation",
        description: "Type annotation of `any` — disables type checking",
        query: r#"(type_annotation (predefined_type) @t (#eq? @t "any")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "ts.quality.as_any",
        description: "Type assertion `as any` — type-safety escape hatch",
        query: r#"(as_expression (predefined_type) @t (#eq? @t "any")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::Medium,
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
        confidence: Confidence::High,
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
        confidence: Confidence::High,
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
        confidence: Confidence::Medium,
    },
];
