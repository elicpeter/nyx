use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig, RuntimeLabelRule};
use crate::utils::project::FrameworkContext;
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["std::env::var", "env::var", "source_env"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["source_file"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["fs::read_to_string", "fs::read"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html_escape::encode_safe", "sanitize_", "sanitize_html"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["shell_escape::unix::escape", "sanitize_shell"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "command::new",
            "std::process::command::new",
            "command::arg",
            "command::args",
            "command::status",
            "command::output",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["sink_html"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "fs::read_to_string",
            "fs::write",
            "fs::read",
            "File::open",
            "File::create",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["reqwest::get", "reqwest::Client.execute"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_expression"        => Kind::If,
    "loop_expression"      => Kind::InfiniteLoop,
    "while_statement"      => Kind::While,
    "while_expression"     => Kind::While,
    "for_statement"        => Kind::For,
    "for_expression"       => Kind::For,

    "return_statement"     => Kind::Return,
    "return_expression"    => Kind::Return,
    "break_expression"     => Kind::Break,
    "break_statement"      => Kind::Break,
    "continue_expression"  => Kind::Continue,
    "continue_statement"   => Kind::Continue,

    // structure
    "source_file"          => Kind::SourceFile,
    "block"                => Kind::Block,
    "else_clause"          => Kind::Block,
    "match_expression"     => Kind::Block,
    "match_block"          => Kind::Block,
    "match_arm"            => Kind::Block,
    "unsafe_block"         => Kind::Block,
    "function_item"        => Kind::Function,
    "closure_expression"   => Kind::Function,
    "async_block"          => Kind::Block,
    "impl_item"            => Kind::Block,
    "trait_item"           => Kind::Block,
    "declaration_list"     => Kind::Block,

    // data-flow
    "call_expression"        => Kind::CallFn,
    "method_call_expression" => Kind::CallMethod,
    "macro_invocation"       => Kind::CallMacro,
    "let_declaration"        => Kind::CallWrapper,
    "expression_statement"   => Kind::CallWrapper,
    "assignment_expression"  => Kind::Assignment,

    // struct expressions — recurse so env::var() calls inside field
    // initialisers produce Source-labelled CFG nodes (needed for summaries).
    "struct_expression"       => Kind::Block,
    "field_initializer_list"  => Kind::Block,
    "field_initializer"       => Kind::CallWrapper,

    // trivia
    "line_comment"     => Kind::Trivia,
    "block_comment"    => Kind::Trivia,
    ";" => Kind::Trivia, "," => Kind::Trivia,
    "(" => Kind::Trivia, ")" => Kind::Trivia,
    "{" => Kind::Trivia, "}" => Kind::Trivia, "\n" => Kind::Trivia,
    "use_declaration"  => Kind::Trivia,
    "attribute_item"   => Kind::Trivia,
    "mod_item"         => Kind::Trivia,
    "type_item"        => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter"],
    self_param_kinds: &["self_parameter"],
    ident_fields: &["pattern"],
};

/// Framework-conditional rules for Rust.
///
/// Rust web framework source detection requires parameter-type analysis
/// (e.g. `web::Json<T>` in actix-web), which is not yet supported.
/// Sink detection for chained builders like `HttpResponse::Ok().body()`
/// also requires deeper receiver resolution. This scaffolding exists
/// for future expansion once those capabilities are added.
pub fn framework_rules(_ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    Vec::new()
}
