use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig, RuntimeLabelRule};
use crate::utils::project::{DetectedFramework, FrameworkContext};
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
    // Rails request object — user-controlled HTTP request data.
    // Dotted matchers work via push_node receiver.method text construction
    // (confirmed by existing Net::HTTP.get matcher in ssrf_net_http fixture).
    LabelRule {
        matchers: &["request.headers", "request.body", "request.url", "request.referrer", "request.path"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["CGI.escapeHTML", "ERB::Util.html_escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Rails HTML escaping / sanitization helpers.
    LabelRule {
        matchers: &["CGI.escape", "Rack::Utils.escape_html", "sanitize", "strip_tags"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Shellwords.escape", "Shellwords.shellescape"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // Type coercion sanitizers
    LabelRule {
        matchers: &["to_i", "to_f"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ActiveRecord SQL sanitizers
    LabelRule {
        matchers: &["sanitize_sql", "sanitize_sql_array"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["URI.encode_www_form_component"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
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
        matchers: &["Net::HTTP.get", "Net::HTTP.post", "URI.open", "HTTParty.get", "HTTParty.post"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Marshal.load", "Marshal.restore", "YAML.load"],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // SQL injection: ActiveRecord unsafe raw-query execution APIs.
    LabelRule {
        matchers: &["find_by_sql", "connection.execute", "select_all"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // SQL injection: ActiveRecord query methods that accept raw SQL strings.
    // `where` and `order` are the most common Rails SQLi vectors when called
    // with string interpolation (e.g., User.where("name = '#{params[:name]}'")).
    // Broad matchers — verified against fixture fallout.
    LabelRule {
        matchers: &["where", "order", "group", "having", "joins", "pluck"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // Open redirect: redirect_to with user-controlled destination.
    LabelRule {
        matchers: &["redirect_to"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Path traversal: file serving with user-controlled path.
    LabelRule {
        matchers: &["send_file"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    // XSS escape-bypass footguns: html_safe and raw disable auto-escaping.
    LabelRule {
        matchers: &["html_safe", "raw"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
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

    // begin/rescue/ensure: handled by build_begin_rescue() in cfg.rs
    "begin"                 => Kind::Try,
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

/// Framework-conditional rules for Ruby.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Rails) {
        // Strong parameters — permit/require sanitize user input
        rules.push(RuntimeLabelRule {
            matchers: vec!["permit".into(), "require".into()],
            label: DataLabel::Sanitizer(Cap::all()),
            case_sensitive: false,
        });
    }

    if ctx.has(DetectedFramework::Sinatra) {
        // Sinatra template rendering — user content flows to rendered output
        rules.push(RuntimeLabelRule {
            matchers: vec!["erb".into(), "haml".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    rules
}
