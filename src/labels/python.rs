use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.getenv", "os.environ"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &[
            "request.args",
            "request.form",
            "request.json",
            "request.headers",
            "request.cookies",
            "input",
        ],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &["sys.argv"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &["open"],
        label: DataLabel::Source(Cap::all()),
    },
    LabelRule {
        matchers: &[
            "argparse.parse_args",
            "urllib.request.urlopen",
            "requests.get",
            "requests.post",
        ],
        label: DataLabel::Source(Cap::all()),
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
    },
    LabelRule {
        matchers: &["shlex.quote"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["eval", "exec"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
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
    },
    LabelRule {
        matchers: &["cursor.execute", "cursor.executemany"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,

    "return_statement"      => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "module"                => Kind::SourceFile,
    "block"                 => Kind::Block,
    "function_definition"   => Kind::Function,

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
