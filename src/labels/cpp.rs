use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["getenv"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &["std::cin", "std::getline", "fgets", "scanf", "gets"],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["sanitize_"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["system", "popen", "execve", "execvp"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
    LabelRule {
        matchers: &["sprintf", "strcpy", "strcat"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["printf", "fprintf"],
        label: DataLabel::Sink(Cap::FMT_STRING),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,
    "for_range_loop"        => Kind::For,
    "do_statement"          => Kind::While,
    "switch_statement"      => Kind::Block,
    "case_statement"        => Kind::Block,
    "labeled_statement"     => Kind::Block,

    "return_statement"      => Kind::Return,
    "throw_statement"       => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "translation_unit"      => Kind::SourceFile,
    "compound_statement"    => Kind::Block,
    "else_clause"           => Kind::Block,
    "function_definition"   => Kind::Function,
    "try_statement"         => Kind::Block,
    "catch_clause"          => Kind::Block,
    "lambda_expression"     => Kind::Block,

    // data-flow
    "call_expression"       => Kind::CallFn,
    "assignment_expression" => Kind::Assignment,
    "declaration"           => Kind::CallWrapper,
    "expression_statement"  => Kind::CallWrapper,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "preproc_include"       => Kind::Trivia,
    "preproc_def"           => Kind::Trivia,
    "using_declaration"     => Kind::Trivia,
    "namespace_definition"  => Kind::Block,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["declarator", "name"],
};
