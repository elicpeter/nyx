use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig, RuntimeLabelRule};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.Getenv"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
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
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html.EscapeString", "template.HTMLEscapeString", "template.HTMLEscaper"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["url.QueryEscape", "url.PathEscape"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["filepath.Clean", "filepath.Base"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Type conversion sanitizers
    LabelRule {
        matchers: &["strconv.Atoi", "strconv.ParseInt", "strconv.ParseFloat", "strconv.ParseBool"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["exec.Command"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["db.Query", "db.Exec", "db.QueryRow", "db.Prepare"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // fmt.Printf/Sprintf write to stdout or build strings in memory — not
    // security sinks.  fmt.Fprintf writes to an io.Writer (often http.ResponseWriter)
    // so it IS a security sink for XSS.
    LabelRule {
        matchers: &["fmt.Fprintf"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
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
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["template.HTML", "template.JS", "template.CSS"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["http.Get", "http.Post", "http.NewRequest", "http.NewRequestWithContext", "net.Dial", "net.DialTimeout"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "md5.New", "md5.Sum",
            "sha1.New", "sha1.Sum",
            "des.NewCipher", "rc4.NewCipher",
        ],
        label: DataLabel::Sink(Cap::CRYPTO),
        case_sensitive: false,
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
    "type_assertion_expression" => Kind::Seq,

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

/// Framework-conditional rules for Go.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Gin) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "c.Param".into(), "c.Query".into(), "c.PostForm".into(),
                "c.DefaultQuery".into(), "c.DefaultPostForm".into(),
                "c.GetHeader".into(), "c.Cookie".into(),
                "c.BindJSON".into(), "c.ShouldBindJSON".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["c.HTML".into(), "c.String".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    if ctx.has(DetectedFramework::Echo) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "c.QueryParam".into(), "c.FormValue".into(),
                "c.Param".into(), "c.Bind".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
    }

    rules
}
