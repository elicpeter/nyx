use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig, SinkGate};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &[
            "document.location",
            "window.location",
            "req.body",
            "req.query",
            "req.params",
            "req.headers",
            "req.cookies",
            "req.hostname",
            "req.ip",
            "req.path",
            "req.protocol",
            "req.url",
            "req.get",
            "req.header",
            "process.env",
            "location.search",
            "location.hash",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["encodeURIComponent", "encodeURI"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["DOMPurify.sanitize"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["xss"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["sanitizeHtml"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["eval"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["innerHTML"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["fetch", "axios.get", "axios.post", "axios.request", "http.request", "https.request"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "location.href",
            "window.location.href",
            "document.location.href",
        ],
        label: DataLabel::Sink(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // Express response sinks
    LabelRule {
        matchers: &["res.send", "res.json", "res.render"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["res.redirect"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["res.sendFile"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["res.set", "res.header"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // DOM XSS sinks
    LabelRule {
        matchers: &["document.write", "document.writeln", "outerHTML", "insertAdjacentHTML"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Navigation / open-redirect sinks
    LabelRule {
        matchers: &["location.assign", "location.replace", "window.open"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Node.js file-system write sinks
    LabelRule {
        matchers: &["fs.writeFile", "fs.writeFileSync"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Node.js network sinks
    LabelRule {
        matchers: &["net.createConnection"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
];

pub static GATED_SINKS: &[SinkGate] = &[
    SinkGate {
        callee_matcher: "setAttribute",
        arg_index: 0,
        dangerous_values: &["href", "src", "action", "formaction", "srcdoc"],
        dangerous_prefixes: &["on"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
        payload_args: &[1],
    },
    SinkGate {
        callee_matcher: "parseFromString",
        arg_index: 1,
        dangerous_values: &["text/html", "application/xhtml+xml"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,
    "for_in_statement"      => Kind::For,
    "do_statement"          => Kind::While,

    "return_statement"      => Kind::Return,
    "throw_statement"       => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "program"               => Kind::SourceFile,
    "statement_block"       => Kind::Block,
    "else_clause"           => Kind::Block,
    "function_declaration"  => Kind::Function,
    "function_expression"   => Kind::Function,
    "arrow_function"        => Kind::Function,
    "method_definition"     => Kind::Function,
    "generator_function_declaration" => Kind::Function,
    "generator_function"    => Kind::Function,
    "switch_statement"              => Kind::Block,
    "switch_body"                   => Kind::Block,
    "switch_case"                   => Kind::Block,
    "switch_default"                => Kind::Block,
    "try_statement"                 => Kind::Block,
    "catch_clause"                  => Kind::Block,
    "finally_clause"                => Kind::Block,
    "class_declaration"             => Kind::Block,
    "class"                         => Kind::Block,
    "class_body"                    => Kind::Block,
    "abstract_class_declaration"    => Kind::Block,
    "export_statement"              => Kind::Block,
    "enum_declaration"              => Kind::Trivia,

    // data-flow
    "call_expression"       => Kind::CallFn,
    "new_expression"        => Kind::CallFn,
    "assignment_expression" => Kind::Assignment,
    "variable_declaration"  => Kind::CallWrapper,
    "lexical_declaration"   => Kind::CallWrapper,
    "expression_statement"  => Kind::CallWrapper,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_statement"      => Kind::Trivia,
    "type_alias_declaration" => Kind::Trivia,
    "interface_declaration" => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["required_parameter", "optional_parameter", "identifier"],
    self_param_kinds: &[],
    ident_fields: &["name", "pattern"],
};
