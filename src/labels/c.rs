use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["getenv"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &["fgets", "scanf", "fscanf", "gets", "read"],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["sanitize_"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "system", "popen", "exec", "execl", "execlp", "execle", "execve", "execvp",
        ],
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
    LabelRule {
        matchers: &["fopen", "open"],
        label: DataLabel::Sink(Cap::FILE_IO),
    },
    LabelRule {
        matchers: &["curl_easy_perform"],
        label: DataLabel::Sink(Cap::SSRF),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,
    "do_statement"          => Kind::While,
    "switch_statement"      => Kind::Block,
    "case_statement"        => Kind::Block,
    "labeled_statement"     => Kind::Block,

    "return_statement"      => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "translation_unit"      => Kind::SourceFile,
    "compound_statement"    => Kind::Block,
    "else_clause"           => Kind::Block,
    "function_definition"   => Kind::Function,

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
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["declarator", "name"],
};
