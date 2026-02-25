use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &["file_get_contents", "fread"],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["htmlspecialchars", "htmlentities"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["escapeshellarg", "escapeshellcmd"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["system", "exec", "passthru", "shell_exec"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
    LabelRule {
        matchers: &["echo", "print"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["mysqli_query", "pg_query"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"                  => Kind::If,
    "while_statement"               => Kind::While,
    "for_statement"                 => Kind::For,
    "foreach_statement"             => Kind::For,

    "return_statement"              => Kind::Return,
    "break_statement"               => Kind::Break,
    "continue_statement"            => Kind::Continue,

    // structure
    "program"                       => Kind::SourceFile,
    "compound_statement"            => Kind::Block,
    "function_definition"           => Kind::Function,
    "method_declaration"            => Kind::Function,

    // data-flow
    "function_call_expression"      => Kind::CallFn,
    "member_call_expression"        => Kind::CallMethod,
    "assignment_expression"         => Kind::Assignment,
    "expression_statement"          => Kind::CallWrapper,

    // trivia
    "comment"                       => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "php_tag"                       => Kind::Trivia,
    "namespace_definition"          => Kind::Trivia,
    "namespace_use_declaration"     => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["simple_parameter", "variadic_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};
