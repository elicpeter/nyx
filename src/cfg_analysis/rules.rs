use crate::labels::Cap;
use crate::symbol::Lang;

/// A guard rule: functions that must dominate sinks to ensure safety.
pub struct GuardRule {
    pub matchers: &'static [&'static str],
    pub applies_to_sink_caps: Cap,
}

/// An auth rule: functions that perform authentication/authorization checks.
pub struct AuthRule {
    pub matchers: &'static [&'static str],
}

/// An entry point rule: functions that serve as external-facing entry points.
pub struct EntryPointRule {
    pub matchers: &'static [&'static str],
}

/// A resource acquire/release pair.
pub struct ResourcePair {
    pub acquire: &'static [&'static str],
    pub release: &'static [&'static str],
    pub resource_name: &'static str,
}

// ── Guard rules ─────────────────────────────────────────────────────────

static COMMON_GUARDS: &[GuardRule] = &[
    GuardRule {
        matchers: &["validate", "sanitize"],
        applies_to_sink_caps: Cap::all(),
    },
    GuardRule {
        matchers: &["check_", "verify_", "assert_"],
        applies_to_sink_caps: Cap::all(),
    },
    GuardRule {
        matchers: &["shell_escape", "quote", "escape_shell"],
        applies_to_sink_caps: Cap::SHELL_ESCAPE,
    },
    GuardRule {
        matchers: &["html_escape", "encode_safe", "escape_html", "sanitize_html"],
        applies_to_sink_caps: Cap::HTML_ESCAPE,
    },
    GuardRule {
        matchers: &["url_encode", "encode_uri", "urlencode"],
        applies_to_sink_caps: Cap::URL_ENCODE,
    },
];

pub fn guard_rules(_lang: Lang) -> &'static [GuardRule] {
    // All languages share the common set for now; per-language
    // overrides can be added via match arms when needed.
    COMMON_GUARDS
}

// ── Auth rules ──────────────────────────────────────────────────────────

static COMMON_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
    ],
}];

static GO_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        "middleware.auth",
        "auth.required",
    ],
}];

static JAVA_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        "isAuthenticated",
        "checkPermission",
        "hasAuthority",
        "hasRole",
    ],
}];

pub fn auth_rules(lang: Lang) -> &'static [AuthRule] {
    match lang {
        Lang::Go => GO_AUTH,
        Lang::Java => JAVA_AUTH,
        _ => COMMON_AUTH,
    }
}

// ── Entry point rules ───────────────────────────────────────────────────

static COMMON_ENTRY_POINTS: &[EntryPointRule] = &[EntryPointRule {
    matchers: &[
        "main",
        "handle_*",
        "route_*",
        "api_*",
        "serve_*",
        "process_*",
    ],
}];

static GO_ENTRY_POINTS: &[EntryPointRule] = &[EntryPointRule {
    matchers: &[
        "main",
        "handle_*",
        "handler_*",
        "route_*",
        "api_*",
        "serve_*",
        "process_*",
        "ServeHTTP",
    ],
}];

static PYTHON_ENTRY_POINTS: &[EntryPointRule] = &[EntryPointRule {
    matchers: &[
        "main",
        "handle_*",
        "route_*",
        "api_*",
        "serve_*",
        "process_*",
        "view_*",
    ],
}];

pub fn entry_point_rules(lang: Lang) -> &'static [EntryPointRule] {
    match lang {
        Lang::Go => GO_ENTRY_POINTS,
        Lang::Python => PYTHON_ENTRY_POINTS,
        _ => COMMON_ENTRY_POINTS,
    }
}

// ── Resource pairs ──────────────────────────────────────────────────────

static C_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["malloc", "calloc", "realloc"],
        release: &["free"],
        resource_name: "memory",
    },
    ResourcePair {
        acquire: &["fopen"],
        release: &["fclose"],
        resource_name: "file handle",
    },
    ResourcePair {
        acquire: &["open"],
        release: &["close"],
        resource_name: "file descriptor",
    },
    ResourcePair {
        acquire: &["pthread_mutex_lock"],
        release: &["pthread_mutex_unlock"],
        resource_name: "mutex",
    },
];

static GO_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["os.Open", "os.Create", "os.OpenFile"],
        release: &[".Close"],
        resource_name: "file handle",
    },
    ResourcePair {
        acquire: &[".Lock"],
        release: &[".Unlock"],
        resource_name: "mutex",
    },
];

static RUST_RESOURCES: &[ResourcePair] = &[
    // Rust uses RAII, but unsafe alloc/dealloc is a pattern
    ResourcePair {
        acquire: &["alloc"],
        release: &["dealloc"],
        resource_name: "raw memory",
    },
];

static JAVA_RESOURCES: &[ResourcePair] = &[ResourcePair {
    acquire: &[
        "new FileInputStream",
        "new FileOutputStream",
        "new BufferedReader",
        "openConnection",
    ],
    release: &[".close"],
    resource_name: "stream/connection",
}];

static EMPTY_RESOURCES: &[ResourcePair] = &[];

pub fn resource_pairs(lang: Lang) -> &'static [ResourcePair] {
    match lang {
        Lang::C => C_RESOURCES,
        Lang::Cpp => C_RESOURCES,
        Lang::Go => GO_RESOURCES,
        Lang::Rust => RUST_RESOURCES,
        Lang::Java => JAVA_RESOURCES,
        _ => EMPTY_RESOURCES,
    }
}
