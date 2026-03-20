use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["ENV", "gets"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["params"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["CGI.escapeHTML", "ERB::Util.html_escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Shellwords.escape", "Shellwords.shellescape"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["system", "exec"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["eval"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["puts", "print"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // URI.open is the network-capable Kernel#open wrapper — more specific than
    // plain `open` (excluded to avoid file I/O false positives).
    LabelRule {
        matchers: &["Net::HTTP.get", "URI.open", "HTTParty.get"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Marshal.load", "Marshal.restore", "YAML.load"],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if"                    => Kind::If,
    "unless"                => Kind::If,
    "while"                 => Kind::While,
    "until"                 => Kind::While,
    "for"                   => Kind::For,

    "return"                => Kind::Return,
    "break"                 => Kind::Break,
    "next"                  => Kind::Continue,

    // structure
    "program"               => Kind::SourceFile,
    "body_statement"        => Kind::Block,
    "do_block"              => Kind::Function,
    "then"                  => Kind::Block,
    "else"                  => Kind::Block,
    "elsif"                 => Kind::If,

    "begin"                 => Kind::Block,
    "rescue"                => Kind::Block,
    "ensure"                => Kind::Block,
    "case"                  => Kind::Block,
    "when"                  => Kind::Block,
    "class"                 => Kind::Block,
    "module"                => Kind::Block,
    "do"                    => Kind::Block,
    "block"                 => Kind::Function,

    // data-flow
    "call"                  => Kind::CallMethod,
    "assignment"            => Kind::Assignment,
    "method"                => Kind::Function,
    "singleton_method"      => Kind::Function,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "\n" => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["identifier"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};
