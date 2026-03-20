use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    // Note: PHP `$` prefix is stripped by collect_idents, so match without `$`.
    LabelRule {
        matchers: &[
            "$_GET",
            "_GET",
            "$_POST",
            "_POST",
            "$_REQUEST",
            "_REQUEST",
            "$_COOKIE",
            "_COOKIE",
            "$_FILES",
            "_FILES",
            "$_SERVER",
            "_SERVER",
            "$_ENV",
            "_ENV",
        ],
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
    LabelRule {
        matchers: &["basename"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "system",
            "exec",
            "passthru",
            "shell_exec",
            "proc_open",
            "popen",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
    LabelRule {
        matchers: &["eval", "assert"],
        label: DataLabel::Sink(Cap::all()),
    },
    LabelRule {
        matchers: &["include", "include_once", "require", "require_once"],
        label: DataLabel::Sink(Cap::FILE_IO),
    },
    LabelRule {
        matchers: &["unserialize"],
        label: DataLabel::Sink(Cap::all()),
    },
    LabelRule {
        matchers: &["move_uploaded_file", "copy", "file_put_contents", "fwrite"],
        label: DataLabel::Sink(Cap::FILE_IO),
    },
    LabelRule {
        matchers: &["echo", "print"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["mysqli_query", "pg_query", "query"],
        label: DataLabel::Sink(Cap::all()),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"                  => Kind::If,
    "while_statement"               => Kind::While,
    "for_statement"                 => Kind::For,
    "foreach_statement"             => Kind::For,
    "do_statement"                  => Kind::While,

    "return_statement"              => Kind::Return,
    "throw_expression"              => Kind::Return,
    "break_statement"               => Kind::Break,
    "continue_statement"            => Kind::Continue,

    // structure
    "program"                       => Kind::SourceFile,
    "compound_statement"            => Kind::Block,
    "else_clause"                   => Kind::Block,
    "else_if_clause"                => Kind::Block,
    "function_definition"           => Kind::Function,
    "method_declaration"            => Kind::Function,
    "switch_statement"              => Kind::Block,
    "switch_block"                  => Kind::Block,
    "case_statement"                => Kind::Block,
    "default_statement"             => Kind::Block,
    "try_statement"                 => Kind::Block,
    "catch_clause"                  => Kind::Block,
    "finally_clause"                => Kind::Block,
    "colon_block"                   => Kind::Block,
    "class_declaration"             => Kind::Block,

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
