use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["System.getenv"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "getParameter",
            "getInputStream",
            "getHeader",
            "getCookies",
            "getReader",
            "getQueryString",
            "getPathInfo",
            "getRequestURI",
            "getRequestURL",
            "getServletPath",
            "getContextPath",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["readObject", "readLine"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["HtmlUtils.htmlEscape", "StringEscapeUtils.escapeHtml4"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["Runtime.exec", "ProcessBuilder"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["executeQuery", "executeUpdate", "prepareStatement"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Class.forName"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["println", "print", "write"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // openConnection() is the standard java.net.URL API for initiating a connection.
    // It is the correct interception point — the URL is already set on the object.
    LabelRule {
        matchers: &["openConnection", "HttpClient.send", "HttpClient.sendAsync", "getForObject", "RestTemplate.exchange", "postForObject", "postForEntity"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["readObject", "readUnshared", "XMLDecoder.readObject"],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // ─── Spring / JPA / Hibernate SQL sinks ───
    LabelRule {
        matchers: &[
            "jdbcTemplate.query",
            "jdbcTemplate.update",
            "jdbcTemplate.execute",
            "jdbcTemplate.queryForObject",
            "jdbcTemplate.queryForList",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "entityManager.createNativeQuery",
            "entityManager.createQuery",
            "session.createQuery",
            "session.createSQLQuery",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // ─── Logging format injection sinks ───
    LabelRule {
        matchers: &[
            "logger.info", "logger.warn", "logger.error",
            "logger.debug", "logger.trace", "logger.fatal",
            "log.info", "log.warn", "log.error",
            "log.debug", "log.trace", "log.fatal",
        ],
        label: DataLabel::Sink(Cap::FMT_STRING),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["String.format"],
        label: DataLabel::Sink(Cap::FMT_STRING),
        case_sensitive: true,
    },
    // ─── JNDI injection sinks ───
    LabelRule {
        matchers: &[
            "InitialContext.lookup",
            "ctx.lookup",
            "context.lookup",
            "dirContext.lookup",
        ],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"                 => Kind::If,
    "while_statement"              => Kind::While,
    "for_statement"                => Kind::For,
    "enhanced_for_statement"       => Kind::For,
    "do_statement"                 => Kind::While,

    "return_statement"             => Kind::Return,
    "throw_statement"              => Kind::Throw,
    "break_statement"              => Kind::Break,
    "continue_statement"           => Kind::Continue,

    // structure
    "program"                      => Kind::SourceFile,
    "block"                        => Kind::Block,
    "class_declaration"            => Kind::Block,
    "class_body"                   => Kind::Block,
    "interface_body"               => Kind::Block,
    "method_declaration"           => Kind::Function,
    "constructor_declaration"      => Kind::Function,
    "switch_expression"            => Kind::Block,
    "switch_block"                 => Kind::Block,
    "switch_block_statement_group" => Kind::Block,
    "try_statement"                => Kind::Try,
    "try_with_resources_statement" => Kind::Try,
    "catch_clause"                 => Kind::Block,
    "finally_clause"               => Kind::Block,
    "lambda_expression"            => Kind::Block,
    "constructor_body"             => Kind::Block,
    "static_initializer"           => Kind::Block,

    // data-flow
    "method_invocation"            => Kind::CallMethod,
    "object_creation_expression"   => Kind::CallFn,
    "assignment_expression"        => Kind::Assignment,
    "local_variable_declaration"   => Kind::CallWrapper,
    "expression_statement"         => Kind::CallWrapper,

    // trivia
    "line_comment"                 => Kind::Trivia,
    "block_comment"                => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_declaration"           => Kind::Trivia,
    "package_declaration"          => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["formal_parameter", "spread_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};
