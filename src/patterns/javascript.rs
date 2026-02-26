use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// JavaScript AST patterns.
///
/// Taint rules cover `eval` (code injection), `innerHTML` (XSS),
/// `location.href` (open redirect), and `child_process.exec/spawn` (command
/// injection).  AST patterns here add **new Function()**, **document.write**,
/// **setTimeout with string**, **deserialization**, **prototype pollution**,
/// **XSS sinks** not covered by taint, and **weak crypto**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "js.code_exec.eval",
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
        id: "js.code_exec.new_function",
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
        id: "js.code_exec.settimeout_string",
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
        id: "js.xss.document_write",
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
        id: "js.xss.outer_html",
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
        id: "js.xss.insert_adjacent_html",
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
    // ── Tier A: Prototype pollution ────────────────────────────────────
    Pattern {
        id: "js.prototype.proto_assignment",
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
    Pattern {
        id: "js.prototype.extend_object",
        description: "Assignment to Object.prototype — prototype mutation",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (member_expression
                         object: (identifier) @obj (#eq? @obj "Object")
                         property: (property_identifier) @mid (#eq? @mid "prototype"))))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Prototype,
        confidence: Confidence::High,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "js.crypto.weak_hash",
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
        id: "js.crypto.math_random",
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
    // ── Tier A: Open redirect ──────────────────────────────────────────
    Pattern {
        id: "js.xss.location_assign",
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
    // ── Tier A: Insecure transport ─────────────────────────────────────
    Pattern {
        id: "js.transport.fetch_http",
        description: "fetch() over plain HTTP",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "fetch")
                     arguments: (arguments
                       (string) @url (#match? @url "^\"http://")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::InsecureTransport,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Cookie manipulation ────────────────────────────────────
    Pattern {
        id: "js.xss.cookie_write",
        description: "Write to document.cookie",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (identifier) @obj (#eq? @obj "document")
                       property: (property_identifier) @prop (#eq? @prop "cookie")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
];
