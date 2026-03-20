use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.Getenv"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &[
            "http.Request",
            "r.FormValue",
            "r.URL",
            "r.Body",
            "r.Header",
            "r.URL.Query",
            "r.URL.Query.Get",
            "Request.FormValue",
            "Request.URL",
        ],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html.EscapeString", "template.HTMLEscapeString"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["url.QueryEscape", "url.PathEscape"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
    },
    LabelRule {
        matchers: &["filepath.Clean", "filepath.Base"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["exec.Command"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
    LabelRule {
        matchers: &["db.Query", "db.Exec", "db.QueryRow", "db.Prepare"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
    },
    LabelRule {
        matchers: &["fmt.Fprintf", "fmt.Sprintf", "fmt.Printf"],
        label: DataLabel::Sink(Cap::FMT_STRING),
    },
    LabelRule {
        matchers: &[
            "os.Open",
            "os.OpenFile",
            "os.Create",
            "ioutil.ReadFile",
            "os.ReadFile",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
    },
    LabelRule {
        matchers: &["template.HTML"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["http.Get", "http.Post", "http.NewRequest"],
        label: DataLabel::Sink(Cap::SSRF),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"             => Kind::If,
    "for_statement"            => Kind::For,

    "return_statement"         => Kind::Return,
    "break_statement"          => Kind::Break,
    "continue_statement"       => Kind::Continue,

    // structure
    "source_file"              => Kind::SourceFile,
    "block"                    => Kind::Block,
    "statement_list"           => Kind::Block,
    "function_declaration"     => Kind::Function,
    "method_declaration"       => Kind::Function,
    "func_literal"             => Kind::Function,
    "expression_switch_statement"  => Kind::Block,
    "type_switch_statement"        => Kind::Block,
    "expression_case"              => Kind::Block,
    "type_case"                    => Kind::Block,
    "default_case"                 => Kind::Block,
    "select_statement"             => Kind::Block,
    "communication_case"           => Kind::Block,
    "go_statement"                 => Kind::Block,
    "defer_statement"              => Kind::Block,

    // data-flow
    "call_expression"          => Kind::CallFn,
    "assignment_statement"     => Kind::Assignment,
    "short_var_declaration"    => Kind::CallWrapper,
    "expression_statement"     => Kind::CallWrapper,
    "var_declaration"          => Kind::CallWrapper,

    // trivia
    "comment"                  => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_declaration"       => Kind::Trivia,
    "package_clause"           => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};
