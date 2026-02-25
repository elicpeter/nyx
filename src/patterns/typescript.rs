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
        id: "any_type",
        description: "Type annotation of `any`",
        query: "(type_annotation (predefined_type) @t (#eq? @t \"any\")) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "json_parse",
        description: "JSON.parse on dynamic string",
        query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"JSON\") property: (property_identifier) @prop (#eq? @prop \"parse\"))) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "as_any_assertion",
        description: "Type assertion to `any` using `as any`",
        query: "(as_expression type: (predefined_type) @t (#eq? @t \"any\")) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "type_assertion_any",
        description: "Type assertion to `any` using `<any>` syntax",
        query: "(type_assertion type: (predefined_type) @t (#eq? @t \"any\")) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "outer_html_assignment",
        description: "Assignment to element.outerHTML",
        query: "(assignment_expression left: (member_expression property: (property_identifier) @prop (#eq? @prop \"outerHTML\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "insert_adjacent_html",
        description: "insertAdjacentHTML() call",
        query: "(call_expression function: (member_expression property: (property_identifier) @prop (#eq? @prop \"insertAdjacentHTML\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "document_cookie_write",
        description: "Write to document.cookie",
        query: "(assignment_expression left: (member_expression object: (identifier) @obj (#eq? @obj \"document\") property: (property_identifier) @prop (#eq? @prop \"cookie\"))) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "onclick_setattribute",
        description: "Element.setAttribute('onclick', …)",
        query: "(call_expression function: (member_expression property: (property_identifier) @prop (#eq? @prop \"setAttribute\")) arguments: (arguments (string) @name (#eq? @name \"\\\"onclick\\\"\") . (string) @handler)) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "math_random_call",
        description: "Use of Math.random() for security-sensitive randomness",
        query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"Math\") property: (property_identifier) @prop (#eq? @prop \"random\"))) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "crypto_createhash_md5",
        description: "Insecure hash algorithm: crypto.createHash('md5')",
        query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"crypto\") property: (property_identifier) @prop (#eq? @prop \"createHash\")) arguments: (arguments (string) @alg (#match? @alg \"(?i)\\\"md5\\\"\"))) @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "fetch_http_url",
        description: "fetch() over plain HTTP",
        query: "(call_expression function: (identifier) @id (#eq? @id \"fetch\") arguments: (arguments (string) @url (#match? @url \"^\\\"http://\"))) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "xhr_eval_response",
        description: "eval() of XMLHttpRequest.responseText",
        query: "(call_expression function: (identifier) @id (#eq? @id \"eval\") arguments: (arguments (member_expression property: (property_identifier) @prop (#eq? @prop \"responseText\")))) @vuln",
        severity: Severity::High,
    },
];
