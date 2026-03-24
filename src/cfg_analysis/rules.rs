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
    /// Patterns that look like acquire calls (e.g. `freopen` ends with `fopen`)
    /// but should NOT be treated as acquisitions.
    pub exclude_acquire: &'static [&'static str],
    pub resource_name: &'static str,
    /// Callee patterns that read/write/operate on this specific resource type,
    /// triggering use-after-close if the handle is closed. Checked before the
    /// global `RESOURCE_USE_PATTERNS` fallback.
    pub use_patterns: &'static [&'static str],
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
    GuardRule {
        matchers: &[
            "which",
            "resolve_binary",
            "find_program",
            "lookup_path",
            "shutil.which",
        ],
        applies_to_sink_caps: Cap::SHELL_ESCAPE,
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
        exclude_acquire: &[],
        resource_name: "memory",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["fopen", "fdopen", "curlx_fopen", "curlx_fdopen"],
        release: &["fclose", "curlx_fclose"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["open"],
        release: &["close"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file descriptor",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["pthread_mutex_lock"],
        release: &["pthread_mutex_unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
];

static CPP_RESOURCES: &[ResourcePair] = &[
    // Inherited from C
    ResourcePair {
        acquire: &["malloc", "calloc", "realloc"],
        release: &["free"],
        exclude_acquire: &[],
        resource_name: "memory",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["fopen", "fdopen", "curlx_fopen", "curlx_fdopen"],
        release: &["fclose", "curlx_fclose"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["open"],
        release: &["close"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file descriptor",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["pthread_mutex_lock"],
        release: &["pthread_mutex_unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
    // C++ new/delete (callee normalized to "new"/"delete" in cfg.rs)
    ResourcePair {
        acquire: &["new"],
        release: &["delete"],
        exclude_acquire: &[],
        resource_name: "heap object",
        use_patterns: &[],
    },
];

static GO_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["os.Open", "os.Create", "os.OpenFile"],
        release: &[".Close"],
        exclude_acquire: &[],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &[".Lock"],
        release: &[".Unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
];

static RUST_RESOURCES: &[ResourcePair] = &[
    // Rust uses RAII, but unsafe alloc/dealloc is a pattern
    ResourcePair {
        acquire: &["alloc"],
        release: &["dealloc"],
        exclude_acquire: &[],
        resource_name: "raw memory",
        use_patterns: &[],
    },
];

static JAVA_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["FileInputStream", "FileOutputStream", "BufferedReader", "openConnection"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "stream/connection",
        use_patterns: &[".read", ".write", ".flush", ".available"],
    },
    ResourcePair {
        acquire: &["DriverManager.getConnection", "getConnection"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &[".executeQuery", ".executeUpdate", ".createStatement", ".prepareStatement"],
    },
    ResourcePair {
        acquire: &["Socket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &[".getInputStream", ".getOutputStream", ".connect"],
    },
];

static PYTHON_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["open"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["socket.socket", "socket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["connect", "cursor"],
        release: &[".close"],
        exclude_acquire: &["signal.connect", "event.connect", ".register"],
        resource_name: "db connection",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["threading.Lock", "threading.RLock"],
        release: &[".release"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
];

static RUBY_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["File.open", "File.new", "open"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "file handle",
        use_patterns: &[
            ".read", ".write", ".gets", ".puts", ".each_line",
            ".readline", ".readlines", ".sysread", ".syswrite",
        ],
    },
    ResourcePair {
        acquire: &["TCPSocket.new", "UDPSocket.new", "TCPServer.new", "UNIXSocket.new"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &[".read", ".write", ".send", ".recv", ".gets", ".puts"],
    },
    ResourcePair {
        acquire: &[".lock"],
        release: &[".unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["PG.connect", "PG::Connection.new", "Sequel.connect",
                    "Mysql2::Client.new", "SQLite3::Database.new"],
        release: &[".close", ".disconnect"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &[".exec", ".query", ".exec_params", ".prepare", ".execute"],
    },
];

static PHP_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["fopen"],
        release: &["fclose"],
        exclude_acquire: &["freopen"],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["mysqli_connect", "mysqli"],
        release: &["mysqli_close", ".close"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &["mysqli_query", "mysqli_fetch_array", ".query", ".fetch"],
    },
    ResourcePair {
        acquire: &["curl_init"],
        release: &["curl_close"],
        exclude_acquire: &[],
        resource_name: "curl handle",
        use_patterns: &["curl_exec", "curl_getinfo", "curl_setopt"],
    },
];

static JS_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["fs.open", "fs.openSync"],
        release: &["fs.close", "fs.closeSync"],
        exclude_acquire: &[],
        resource_name: "file descriptor",
        use_patterns: &[
            "fs.readSync",
            "fs.writeSync",
            "fs.fstatSync",
            "fs.ftruncateSync",
            "fs.fsyncSync",
        ],
    },
    ResourcePair {
        acquire: &["createReadStream", "createWriteStream"],
        release: &[".close", ".destroy"],
        exclude_acquire: &[],
        resource_name: "stream",
        use_patterns: &[".pipe", ".resume", ".write", ".read", ".push"],
    },
];

pub fn resource_pairs(lang: Lang) -> &'static [ResourcePair] {
    match lang {
        Lang::C => C_RESOURCES,
        Lang::Cpp => CPP_RESOURCES,
        Lang::Go => GO_RESOURCES,
        Lang::Rust => RUST_RESOURCES,
        Lang::Java => JAVA_RESOURCES,
        Lang::Python => PYTHON_RESOURCES,
        Lang::Ruby => RUBY_RESOURCES,
        Lang::Php => PHP_RESOURCES,
        Lang::JavaScript | Lang::TypeScript => JS_RESOURCES,
    }
}
