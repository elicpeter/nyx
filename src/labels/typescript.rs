use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
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
            "process.env",
        ],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["encodeURIComponent", "encodeURI"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
    },
    LabelRule {
        matchers: &["DOMPurify.sanitize"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["eval"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
    LabelRule {
        matchers: &["innerHTML"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &[
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,
    "for_in_statement"      => Kind::For,
    "for_of_statement"      => Kind::For,

    "return_statement"      => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "program"               => Kind::SourceFile,
    "statement_block"       => Kind::Block,
    "function_declaration"  => Kind::Function,
    "arrow_function"        => Kind::Function,
    "method_definition"     => Kind::Function,

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
