use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.getenv", "os.environ"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "request.args",
            "request.form",
            "request.json",
            "request.headers",
            "request.cookies",
            "request.files",
            "request.data",
            "request.values",
            "request.environ",
            "request.url",
            "request.base_url",
            "request.host",
            "input",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Django-specific sources (case-sensitive to avoid request.get() dict method FP)
    LabelRule {
        matchers: &["request.GET", "request.POST", "request.META", "request.body"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["sys.argv"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["open"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "argparse.parse_args",
            "urllib.request.urlopen",
            "requests.get",
            "requests.post",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["shlex.quote"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["bleach.clean", "markupsafe.escape", "django.utils.html.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    // Flask sinks
    LabelRule {
        matchers: &["render_template_string"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    // Jinja2 / string.Template — tainted template string enables SSTI
    LabelRule {
        matchers: &["Template"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["make_response"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["redirect"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Django sinks
    LabelRule {
        matchers: &["HttpResponse", "mark_safe"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["eval", "exec"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "os.system",
            "os.popen",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.check_output",
            "subprocess.check_call",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["cursor.execute", "cursor.executemany"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["send_file", "send_from_directory"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["os.path.realpath"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["urllib.request.urlopen", "requests.get", "requests.post", "requests.request", "httpx.get", "httpx.request"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "pickle.loads",
            "pickle.load",
            "yaml.load", // unsafe unless SafeLoader
            "yaml.unsafe_load",
            "yaml.full_load",
            "shelve.open",
        ],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,

    "return_statement"      => Kind::Return,
    "raise_statement"       => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "module"                => Kind::SourceFile,
    "block"                 => Kind::Block,
    "else_clause"           => Kind::Block,
    "elif_clause"           => Kind::Block,
    "with_statement"        => Kind::Block,
    "with_clause"           => Kind::Block,
    "with_item"             => Kind::CallWrapper,
    "function_definition"   => Kind::Function,
    "try_statement"         => Kind::Block,
    "except_clause"         => Kind::Block,
    "finally_clause"        => Kind::Block,
    "class_definition"      => Kind::Block,
    "decorated_definition"  => Kind::Block,
    "match_statement"       => Kind::Block,
    "case_clause"           => Kind::Block,

    // data-flow
    "call"                  => Kind::CallFn,
    "assignment"            => Kind::Assignment,
    "expression_statement"  => Kind::CallWrapper,

    // trivia
    "comment"               => Kind::Trivia,
    ":"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_statement"      => Kind::Trivia,
    "import_from_statement" => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["identifier"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};
