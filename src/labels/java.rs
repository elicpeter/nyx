use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["System.getenv"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &["getParameter", "getInputStream", "getHeader", "getCookies"],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["HtmlUtils.htmlEscape", "StringEscapeUtils.escapeHtml4"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["Runtime.exec"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
    LabelRule {
        matchers: &["executeQuery", "executeUpdate", "prepareStatement"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"                 => Kind::If,
    "while_statement"              => Kind::While,
    "for_statement"                => Kind::For,
    "enhanced_for_statement"       => Kind::For,

    "return_statement"             => Kind::Return,
    "break_statement"              => Kind::Break,
    "continue_statement"           => Kind::Continue,

    // structure
    "program"                      => Kind::SourceFile,
    "block"                        => Kind::Block,
    "class_declaration"            => Kind::Block,
    "class_body"                   => Kind::Block,
    "interface_body"               => Kind::Block,
    "method_declaration"           => Kind::Function,
    "constructor_declaration"      => Kind::Function,

    // data-flow
    "method_invocation"            => Kind::CallMethod,
    "object_creation_expression"   => Kind::CallFn,
    "assignment_expression"        => Kind::Assignment,
    "local_variable_declaration"   => Kind::CallWrapper,
    "expression_statement"         => Kind::CallWrapper,

    // trivia
    "line_comment"                 => Kind::Trivia,
    "block_comment"                => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_declaration"           => Kind::Trivia,
    "package_declaration"          => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["formal_parameter", "spread_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};
