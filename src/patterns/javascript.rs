use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
    Pattern {
        id: "eval_call",
        description: "Use of eval()",
        query: "(call_expression function: (identifier) @id (#eq? @id \"eval\")) @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "new_function",
        description: "new Function() constructor",
        query: "(new_expression constructor: (identifier) @id (#eq? @id \"Function\")) @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "document_write",
        description: "document.write() call",
        query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"document\") property: (property_identifier) @prop (#eq? @prop \"write\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "settimeout_string",
        description: "setTimeout / setInterval with a string argument",
        query: "(call_expression function: (identifier) @id (#match? @id \"setTimeout|setInterval\") arguments: (arguments (string) @code . _)) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "json_parse",
        description: "JSON.parse on dynamic string",
        query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"JSON\") property: (property_identifier) @prop (#eq? @prop \"parse\"))) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "outer_html_assignment",
        description: "Assignment to element.outerHTML",
        query: "(assignment_expression
               left: (member_expression
                        property: (property_identifier) @prop
                        (#eq? @prop \"outerHTML\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "insert_adjacent_html",
        description: "insertAdjacentHTML() call",
        query: "(call_expression
               function: (member_expression
                           property: (property_identifier) @prop
                           (#eq? @prop \"insertAdjacentHTML\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "location_href_assignment",
        description: "Assignment to window.location / location.href",
        query: "(assignment_expression
               left: (member_expression
                        object: (identifier)? @obj
                        property: (property_identifier) @prop
                        (#match? @prop \"location|href\"))) @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "cookie_assignment",
        description: "Write to document.cookie",
        query: "(assignment_expression
               left: (member_expression
                        object: (identifier) @obj
                        (#eq? @obj \"document\")
                        property: (property_identifier) @prop
                        (#eq? @prop \"cookie\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "proto_pollution",
        description: "Assignment to __proto__ (prototype pollution)",
        query: "(assignment_expression
               left: (member_expression
                        property: (property_identifier) @prop
                        (#eq? @prop \"__proto__\"))) @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "weak_hash_md5",
        description: "crypto.createHash(\"md5\")",
        query: "(call_expression
               function: (member_expression
                           object: (identifier) @obj
                           (#eq? @obj \"crypto\")
                           property: (property_identifier) @prop
                           (#eq? @prop \"createHash\"))
               arguments: (arguments
                            (string) @alg
                            (#eq? @alg \"md5\"))) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "regexp_constructor_string",
        description: "new RegExp() with a dynamic string",
        query: "(new_expression
               constructor: (identifier) @id
               (#eq? @id \"RegExp\")
               arguments: (arguments (string) @pattern)) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "dangerous_extend_builtin",
        description: "Extending Object.prototype (may lead to collisions/pollution)",
        query: "(assignment_expression
               left: (member_expression
                        object: (identifier) @obj
                        (#eq? @obj \"Object\")
                        property: (property_identifier) @prop
                        (#eq? @prop \"prototype\"))) @vuln",
        severity: Severity::Medium,
    },
];
