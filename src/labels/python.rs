use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
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
            // Common alias: from flask import request as flask_request
            "flask_request.args",
            "flask_request.form",
            "flask_request.json",
            "flask_request.headers",
            "flask_request.cookies",
            "flask_request.files",
            "flask_request.data",
            "flask_request.values",
            // Flask request methods (method-call form of the attributes above)
            "request.get_data",
            "request.get_json",
            "flask_request.get_data",
            "flask_request.get_json",
            "input",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Django-specific sources (case-sensitive to avoid request.get() dict method FP)
    LabelRule {
        matchers: &[
            "request.GET",
            "request.POST",
            "request.META",
            "request.body",
        ],
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
        matchers: &["html.escape", "cgi.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["shlex.quote"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "bleach.clean",
            "markupsafe.escape",
            "django.utils.html.escape",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Type coercion sanitizers
    LabelRule {
        matchers: &["int", "float", "bool"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["urllib.parse.quote", "urllib.parse.quote_plus"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // SQLAlchemy bound-parameter sanitizer.  Values passed as keyword
    // arguments to `text("…:name…").bindparams(name=value)` are bound
    // by the driver, so injection cannot break out of the literal
    // context.  The accompanying SQL-string check (py.sqli.text_format)
    // already flags the `text(f"…")` shape at construction, so this
    // sanitizer only clears flow when the SQL is a literal and the
    // values reach the engine via bindparams.  Recognises both the
    // method form (`text(…).bindparams(...)`) and the bare call form.
    LabelRule {
        matchers: &["bindparams", ".bindparams"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Path canonicalization
    LabelRule {
        matchers: &["os.path.abspath", "os.path.normpath"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
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
    // Flask Markup — bypasses auto-escaping
    LabelRule {
        matchers: &["Markup"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: true,
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
            "subprocess.check_output",
            "subprocess.check_call",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["cursor.execute", "cursor.executemany", "sqlalchemy.text"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Django ORM raw SQL execution
    LabelRule {
        matchers: &["objects.raw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // SQL injection: sqlite3 / SQLAlchemy / generic DB connection execute.
    LabelRule {
        matchers: &[
            "conn.execute",
            "connection.execute",
            "session.execute",
            "engine.execute",
            "db.execute",
        ],
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
        matchers: &[
            "urllib.request.urlopen",
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "requests.head",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.delete",
            "httpx.patch",
            "httpx.head",
            "httpx.request",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // aiohttp HTTP client — SSRF sinks
    LabelRule {
        matchers: &[
            "aiohttp.get",
            "aiohttp.post",
            "aiohttp.put",
            "aiohttp.delete",
            "aiohttp.request",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Type-qualified SSRF sinks: when the receiver is tracked as
    // TypeKind::HttpClient (e.g. `client = requests.Session()`,
    // `client = httpx.Client()`, or `s = aiohttp.ClientSession()`),
    // resolve_type_qualified_labels() constructs `"HttpClient.<method>"`
    // call texts so the receiver-name is no longer load-bearing.  Matches
    // the existing Rust HttpClient.<method> sink set so both languages
    // stay in step on the type-aware SSRF model.  Motivated by the
    // upstream LMDeploy CVE-2026-33626 shape:
    //   client = requests.Session()
    //   response = client.get(url, ...)
    LabelRule {
        matchers: &[
            "HttpClient.get",
            "HttpClient.post",
            "HttpClient.put",
            "HttpClient.delete",
            "HttpClient.patch",
            "HttpClient.head",
            "HttpClient.request",
            "HttpClient.send",
        ],
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

pub static GATED_SINKS: &[SinkGate] = &[
    // Legacy single-kwarg gate retained for back-compat: Popen(cmd, shell=True).
    SinkGate {
        callee_matcher: "Popen",
        arg_index: 0,
        dangerous_values: &["True", "true"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: Some("shell"),
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // subprocess.run(cmd, shell=True) — multi-kwarg gate using the new
    // presence-aware mechanism.  Payload is arg 1 (after receiver offset
    // applied by the CFG layer when the call is modelled method-style).
    SinkGate {
        callee_matcher: "subprocess.run",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[("shell", &["True", "true"])],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "subprocess.call",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[("shell", &["True", "true"])],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "subprocess.Popen",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[("shell", &["True", "true"])],
        activation: GateActivation::ValueMatch,
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,

    "return_statement"      => Kind::Return,
    "raise_statement"       => Kind::Throw,
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
    "lambda"                => Kind::Function,
    "try_statement"         => Kind::Try,
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
    // Python parameters: bare identifiers, typed (`x: T`), defaulted
    // (`x=42`), and typed-with-default (`x: T = ...`).  Without the
    // typed forms, type-annotated handlers register zero arity and
    // their parameter taint never participates in summaries.
    param_node_kinds: &[
        "identifier",
        "typed_parameter",
        "default_parameter",
        "typed_default_parameter",
    ],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for Python.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Django) {
        // QuerySet.extra() — raw SQL injection risk.
        // Framework-conditional because `extra` is too generic as a static matcher.
        rules.push(RuntimeLabelRule {
            matchers: vec!["extra".into()],
            label: DataLabel::Sink(Cap::SQL_QUERY),
            case_sensitive: false,
        });
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::KINDS;
    use crate::labels::Kind;

    #[test]
    fn lambda_classified_as_function() {
        assert_eq!(KINDS.get("lambda"), Some(&Kind::Function));
    }

    #[test]
    fn function_definition_classified_as_function() {
        assert_eq!(KINDS.get("function_definition"), Some(&Kind::Function));
    }

    #[test]
    fn lambda_distinct_from_other_kinds() {
        // Ensure lambda doesn't accidentally map to Block or Other
        let kind = KINDS.get("lambda").unwrap();
        assert_ne!(*kind, Kind::Block);
        assert_ne!(*kind, Kind::Other);
    }
}
