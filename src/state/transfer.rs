#![allow(clippy::collapsible_if)]

use super::domain::{AuthLevel, ProductState, ResourceLifecycle};
use super::engine::Transfer;
use super::symbol::{SymbolId, SymbolInterner};
use crate::cfg::{EdgeKind, NodeInfo, StmtKind};
use crate::cfg_analysis::rules::{self, ResourcePair};
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;

/// Events emitted during transfer for illegal state transitions.
/// These are NOT lattice values — they become findings in `facts.rs`.
#[derive(Debug, Clone)]
pub struct TransferEvent {
    pub kind: TransferEventKind,
    pub node: NodeIndex,
    pub var: SymbolId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEventKind {
    UseAfterClose,
    DoubleClose,
}

/// Resource-use patterns: callees that read/write/operate on a resource handle
/// (triggering use-after-close if the handle is closed).
static RESOURCE_USE_PATTERNS: &[&str] = &[
    "read",
    "write",
    "send",
    "recv",
    "fread",
    "fwrite",
    "fgets",
    "fputs",
    "fprintf",
    "fscanf",
    "fflush",
    "fseek",
    "ftell",
    "rewind",
    "feof",
    "ferror",
    "fgetc",
    "fputc",
    "getc",
    "putc",
    "ungetc",
    "query",
    "execute",
    "fetch",
    "sendto",
    "recvfrom",
    "ioctl",
    "fcntl",
    // Memory access functions (for malloc/free use-after-free detection)
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strcmp",
    "strncmp",
    "strlen",
    "sprintf",
    "snprintf",
    // Dot-prefixed method patterns (cross-language method calls)
    ".read",
    ".write",
    ".send",
    ".recv",
    ".query",
    ".execute",
    ".fetch",
    // JS/TS Sync variants (suffix doesn't match plain "read"/"write")
    "readSync",
    "writeSync",
    "readFileSync",
    "writeFileSync",
    "appendFileSync",
    "ftruncateSync",
    "fsyncSync",
    "fstatSync",
    // Stream operations
    "pipe",
    "unpipe",
    "resume",
    "pause",
    "destroy",
];

/// Auth-call matchers for admin-level privilege.
static ADMIN_PATTERNS: &[&str] = &[
    "is_admin",
    "hasrole",
    "has_role",
    "check_admin",
    "require_admin",
];

/// Effect type for resource method summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceEffect {
    Acquire,
    Release,
}

/// Summary for a method body that wraps a known resource operation.
/// Only created for methods whose bodies actually contain a recognized
/// resource acquire/release call from the existing resource_pairs matchers.
#[derive(Debug, Clone)]
pub struct ResourceMethodSummary {
    /// Method name (e.g., "open", "close").
    pub method_name: String,
    /// Whether this method acquires or releases a resource.
    pub effect: ResourceEffect,
    /// `parent_body_id` of the declaring method — groups methods by class.
    pub class_group: crate::cfg::BodyId,
    /// Span of the actual resource operation (e.g., fs.openSync at line 7).
    pub original_span: (usize, usize),
}

pub struct DefaultTransfer<'a> {
    pub lang: Lang,
    pub resource_pairs: &'a [ResourcePair],
    pub interner: &'a SymbolInterner,
    /// Resource method summaries for cross-body proxy resolution.
    pub resource_method_summaries: &'a [ResourceMethodSummary],
}

impl Transfer<ProductState> for DefaultTransfer<'_> {
    type Event = TransferEvent;

    fn apply(
        &self,
        node_idx: NodeIndex,
        info: &NodeInfo,
        edge: Option<EdgeKind>,
        mut state: ProductState,
    ) -> (ProductState, Vec<TransferEvent>) {
        let mut events = Vec::new();

        match info.kind {
            StmtKind::Call => {
                self.apply_call(node_idx, info, &mut state, &mut events);
            }
            StmtKind::If => {
                self.apply_if(info, edge, &mut state);
            }
            StmtKind::Seq => {
                self.apply_assignment(node_idx, info, &mut state);
            }
            _ => {}
        }

        (state, events)
    }
}

impl DefaultTransfer<'_> {
    /// Look up a variable's [`SymbolId`] using the node's enclosing function
    /// as scope context.  This ensures same-name variables in different
    /// functions resolve to distinct IDs.
    fn get_sym(&self, info: &NodeInfo, name: &str) -> Option<SymbolId> {
        self.interner
            .get_scoped(info.enclosing_func.as_deref(), name)
    }

    fn apply_call(
        &self,
        node_idx: NodeIndex,
        info: &NodeInfo,
        state: &mut ProductState,
        events: &mut Vec<TransferEvent>,
    ) {
        let callee = match &info.callee {
            Some(c) => c.to_ascii_lowercase(),
            None => return,
        };

        // ── Resource acquire ─────────────────────────────────────────────
        let mut direct_acquire = false;
        for pair in self.resource_pairs {
            let is_acquire = pair.acquire.iter().any(|a| callee_matches(&callee, a));
            let is_excluded = pair
                .exclude_acquire
                .iter()
                .any(|e| callee_matches(&callee, e));

            if is_acquire
                && !is_excluded
                && let Some(ref def) = info.defines
                && let Some(sym) = self.get_sym(info, def)
            {
                state.resource.set(sym, ResourceLifecycle::OPEN);
                direct_acquire = true;
            }
        }

        // ── Resource release ─────────────────────────────────────────────
        // Track which variables have already been released to avoid double-
        // matching across multiple resource pair definitions.
        let mut direct_release = false;
        let mut released: smallvec::SmallVec<[SymbolId; 4]> = smallvec::SmallVec::new();
        for pair in self.resource_pairs {
            let is_release = pair.release.iter().any(|r| callee_matches(&callee, r));
            if is_release {
                direct_release = true;
                // Go `defer f.Close()`: skip the CLOSED transition so the
                // variable stays OPEN mid-function.  Leak suppression is
                // handled separately in extract_findings().
                if info.in_defer {
                    continue;
                }
                for used in &info.uses {
                    if let Some(sym) = self.get_sym(info, used) {
                        if released.contains(&sym) {
                            continue;
                        }
                        let current = state.resource.get(sym);
                        if current == ResourceLifecycle::CLOSED {
                            // Double close
                            events.push(TransferEvent {
                                kind: TransferEventKind::DoubleClose,
                                node: node_idx,
                                var: sym,
                            });
                        } else if current.contains(ResourceLifecycle::OPEN) {
                            state.resource.set(sym, ResourceLifecycle::CLOSED);
                        }
                        released.push(sym);
                    }
                }
            }
        }

        // ── Resource method proxy ────────────────────────────────────────
        // When no direct resource pair matched, check if the callee is a
        // method wrapper for a known resource operation. Only fires when:
        //   1. The callee is a method call (contains `.`)
        //   2. An explicit receiver is identified
        //   3. The method suffix matches a ResourceMethodSummary
        //   4. For Release: the receiver was previously acquired by the same class group
        if !direct_acquire && !direct_release && callee.contains('.') {
            // Extract receiver: prefer explicit NodeInfo.receiver, fall back
            // to everything before the last `.` in the callee string.
            let recv_from_callee: Option<String>;
            let recv_name: Option<&str> = if let Some(ref r) = info.receiver {
                Some(r.as_str())
            } else {
                recv_from_callee = callee.rsplit_once('.').map(|(prefix, _)| {
                    // For multi-segment paths like "a.b.c", use the root receiver
                    prefix.split('.').next().unwrap_or(prefix).to_string()
                });
                recv_from_callee.as_deref()
            };
            if let Some(recv) = recv_name {
                let method_suffix = callee.rsplit('.').next().unwrap_or("");
                for summary in self.resource_method_summaries {
                    if summary.method_name.eq_ignore_ascii_case(method_suffix) {
                        if let Some(sym) = self.get_sym(info, recv) {
                            match summary.effect {
                                ResourceEffect::Acquire => {
                                    state.resource.set(sym, ResourceLifecycle::OPEN);
                                    // Track class group for release matching
                                    state.receiver_class_group.insert(sym, summary.class_group);
                                    // Store original acquire span for finding attribution
                                    state.proxy_acquire_spans.insert(sym, summary.original_span);
                                }
                                ResourceEffect::Release => {
                                    // Only release if receiver was acquired by same class group
                                    if state.receiver_class_group.get(&sym)
                                        == Some(&summary.class_group)
                                    {
                                        let current = state.resource.get(sym);
                                        if current.contains(ResourceLifecycle::OPEN) {
                                            state.resource.set(sym, ResourceLifecycle::CLOSED);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Resource use (pair-specific patterns first, then global fallback)
        let mut use_checked = false;
        for pair in self.resource_pairs {
            if pair.use_patterns.iter().any(|p| callee_matches(&callee, p)) {
                use_checked = true;
                for used in &info.uses {
                    if let Some(sym) = self.get_sym(info, used) {
                        if state.resource.get(sym) == ResourceLifecycle::CLOSED {
                            events.push(TransferEvent {
                                kind: TransferEventKind::UseAfterClose,
                                node: node_idx,
                                var: sym,
                            });
                        }
                    }
                }
            }
        }
        if !use_checked {
            let is_use = RESOURCE_USE_PATTERNS
                .iter()
                .any(|p| callee_matches(&callee, p));
            if is_use {
                for used in &info.uses {
                    if let Some(sym) = self.get_sym(info, used) {
                        if state.resource.get(sym) == ResourceLifecycle::CLOSED {
                            events.push(TransferEvent {
                                kind: TransferEventKind::UseAfterClose,
                                node: node_idx,
                                var: sym,
                            });
                        }
                    }
                }
            }
        }

        // ── Auth call ────────────────────────────────────────────────────
        let auth_rules = rules::auth_rules(self.lang);
        let is_auth = auth_rules.iter().any(|rule| {
            rule.matchers
                .iter()
                .any(|m| callee_matches(&callee, &m.to_ascii_lowercase()))
        });
        if is_auth {
            let is_admin = ADMIN_PATTERNS.iter().any(|p| callee_matches(&callee, p));
            let new_level = if is_admin {
                AuthLevel::Admin
            } else {
                AuthLevel::Authed
            };
            if new_level > state.auth.auth_level {
                state.auth.auth_level = new_level;
            }
        }

        // ── Validation call (guard) ──────────────────────────────────────
        if is_guard_like(&callee) {
            for used in &info.uses {
                if let Some(sym) = self.get_sym(info, used) {
                    state.auth.validated.insert(sym);
                }
            }
        }
    }

    fn apply_if(&self, info: &NodeInfo, edge: Option<EdgeKind>, state: &mut ProductState) {
        // Determine the "positive edge" — the edge where the underlying
        // (de-negated) condition evaluates to true.
        //
        // For `if (is_authenticated(req))`:  positive = True edge
        // For `if (!allowed[cmd])`:          positive = False edge
        //   (because `!X` being false means `X` is true)
        let is_positive_edge = if info.condition_negated {
            matches!(edge, Some(EdgeKind::False))
        } else {
            matches!(edge, Some(EdgeKind::True))
        };
        if !is_positive_edge {
            return;
        }

        if let Some(ref cond) = info.condition_text {
            let cond_lower = cond.to_ascii_lowercase();
            // Strip leading negation operator for pattern matching —
            // the edge selection above already encodes the semantics.
            let cond_inner = if info.condition_negated {
                cond_lower.trim_start_matches('!').trim_start()
            } else {
                cond_lower.as_str()
            };

            // Auth-related condition
            let auth_rules = rules::auth_rules(self.lang);
            let is_auth_cond = auth_rules.iter().any(|rule| {
                rule.matchers
                    .iter()
                    .any(|m| condition_contains_auth_token(cond_inner, m))
            });
            if is_auth_cond {
                let is_admin = ADMIN_PATTERNS
                    .iter()
                    .any(|p| condition_contains_auth_token(cond_inner, p));
                let new_level = if is_admin {
                    AuthLevel::Admin
                } else {
                    AuthLevel::Authed
                };
                if new_level > state.auth.auth_level {
                    state.auth.auth_level = new_level;
                }
            }

            // Go-specific: map boolean lookup is an allowlist/authorization guard.
            // In Go, `map[string]bool` lookups like `allowed[cmd]` return false
            // for missing keys, making `if allowed[cmd]` a standard allowlist pattern.
            if self.lang == Lang::Go && is_go_map_boolean_guard(cond_inner) {
                if AuthLevel::Authed > state.auth.auth_level {
                    state.auth.auth_level = AuthLevel::Authed;
                }
            }

            // Validation-related condition
            if is_guard_like(cond_inner) {
                for var in &info.condition_vars {
                    if let Some(sym) = self.get_sym(info, var) {
                        state.auth.validated.insert(sym);
                    }
                }
            }
        }
    }

    fn apply_assignment(&self, _node_idx: NodeIndex, info: &NodeInfo, state: &mut ProductState) {
        // Ownership transfer: if `defines` reassigns a tracked resource
        // variable from a `uses` variable, transfer the lifecycle.
        if let Some(ref def) = info.defines
            && let Some(def_sym) = self.get_sym(info, def)
        {
            // If the RHS is a tracked resource, transfer its state
            for used in &info.uses {
                if let Some(use_sym) = self.get_sym(info, used) {
                    let lc = state.resource.get(use_sym);
                    if lc.contains(ResourceLifecycle::OPEN) {
                        state.resource.set(def_sym, lc);
                        state.resource.set(use_sym, ResourceLifecycle::MOVED);
                        return;
                    }
                }
            }
        }
    }
}

/// Public wrapper for `callee_matches` used by `build_resource_method_summaries`.
pub fn callee_matches_pub(callee: &str, pattern: &str) -> bool {
    callee_matches(callee, pattern)
}

/// Check if a callee matches a pattern.
/// Supports suffix matching (e.g., "fclose" matches callee "my_fclose")
/// and dot-prefix matching (e.g., ".close" matches "file.close").
fn callee_matches(callee: &str, pattern: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if pattern_lower.starts_with('.') {
        // Method pattern: ".close" matches "x.close", "file.close", etc.
        callee.ends_with(&pattern_lower)
    } else {
        // Exact or suffix match
        callee == pattern_lower || callee.ends_with(&pattern_lower)
    }
}

/// Check if a callee looks like a guard/validation function.
fn is_guard_like(callee: &str) -> bool {
    static GUARD_PREFIXES: &[&str] = &["validate", "sanitize", "check_", "verify_", "assert_"];
    GUARD_PREFIXES.iter().any(|p| callee.starts_with(p))
}

/// Detect Go `map[string]bool` allowlist lookups used as boolean guards.
///
/// Matches when the entire condition is an index expression of the form
/// `identifier[identifier]` (e.g., `allowed[cmd]`, `whitelist[key]`).
/// In Go, indexing a `map[string]bool` returns `false` for missing keys,
/// making `if allowed[cmd]` a standard allowlist/authorization pattern.
///
/// Narrow by design: does NOT match complex expressions (`arr[i] > 0`),
/// dotted receivers (`obj.map[key]`), or nested indexing.
fn is_go_map_boolean_guard(cond: &str) -> bool {
    let cond = cond.trim();
    let Some(bracket_start) = cond.find('[') else {
        return false;
    };
    if !cond.ends_with(']') {
        return false;
    }
    let before = &cond[..bracket_start];
    let inside = &cond[bracket_start + 1..cond.len() - 1];
    // Before bracket: plain identifier (no dots, no operators)
    // Inside bracket: identifier, possibly dotted (r.URL.Query().Get("cmd"))
    !before.is_empty()
        && before
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !inside.is_empty()
        && inside
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// Check if condition text contains an auth/admin matcher at a word boundary.
///
/// Dispatches based on matcher content:
/// - **Identifier-only** (`is_authenticated`, `require_auth`): tokenise condition
///   text on non-identifier characters and require an exact token match.
/// - **Contains punctuation** (`middleware.auth`): find the matcher as a substring
///   and verify word boundaries (non-ident char or string edge) on both sides.
fn condition_contains_auth_token(cond: &str, matcher: &str) -> bool {
    let matcher_lower = matcher.to_ascii_lowercase();
    let is_ident_only = matcher_lower
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_');

    if is_ident_only {
        // Tokenise on non-identifier chars, check for exact token match.
        cond.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty())
            .any(|token| token == matcher_lower)
    } else {
        // Word-boundary substring match for punctuated patterns.
        let hay = cond.as_bytes();
        let needle = matcher_lower.as_bytes();
        if needle.len() > hay.len() {
            return false;
        }
        let mut start = 0;
        while start + needle.len() <= hay.len() {
            if let Some(pos) = cond[start..].find(&*matcher_lower) {
                let abs = start + pos;
                let end = abs + needle.len();
                let left_ok = abs == 0 || {
                    let c = hay[abs - 1];
                    !c.is_ascii_alphanumeric() && c != b'_'
                };
                let right_ok = end >= hay.len() || {
                    let c = hay[end];
                    !c.is_ascii_alphanumeric() && c != b'_'
                };
                if left_ok && right_ok {
                    return true;
                }
                start = abs + 1;
            } else {
                break;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callee_matches_exact() {
        assert!(callee_matches("fopen", "fopen"));
        assert!(!callee_matches("fopen", "fclose"));
    }

    #[test]
    fn callee_matches_suffix() {
        assert!(callee_matches("curlx_fclose", "fclose"));
    }

    #[test]
    fn callee_matches_dot_prefix() {
        assert!(callee_matches("file.close", ".close"));
        assert!(!callee_matches("file.close", ".open"));
    }

    #[test]
    fn callee_matches_js_fd_use_patterns() {
        assert!(callee_matches("fs.readsync", "fs.readSync"));
        assert!(callee_matches("fs.writesync", "fs.writeSync"));
        assert!(!callee_matches("fs.readsync", "fs.writeSync"));
    }

    #[test]
    fn callee_matches_stream_method_patterns() {
        assert!(callee_matches("reader.pipe", ".pipe"));
        assert!(callee_matches("stream.write", ".write"));
        assert!(!callee_matches("readstream", ".read")); // no dot, no match
    }

    #[test]
    fn callee_matches_dot_prefix_no_c_interference() {
        assert!(!callee_matches("fread", ".read"));
        assert!(!callee_matches("fwrite", ".write"));
        assert!(!callee_matches("send", ".send"));
    }

    #[test]
    fn acquire_sets_open() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (0, 10),
            labels: smallvec::SmallVec::new(),
            defines: Some("f".into()),
            extra_defines: vec![],
            uses: vec![],
            callee: Some("fopen".into()),
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
            arg_uses: vec![],
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            const_text: None,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
            bin_op_const: None,
            managed_resource: false,
            in_defer: false,
        };

        let (state, events) =
            transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert!(events.is_empty());
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::OPEN);
    }

    #[test]
    fn close_after_open_sets_closed() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (10, 20),
            labels: smallvec::SmallVec::new(),
            defines: None,
            extra_defines: vec![],
            uses: vec!["f".into()],
            callee: Some("fclose".into()),
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
            arg_uses: vec![],
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            const_text: None,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
            bin_op_const: None,
            managed_resource: false,
            in_defer: false,
        };

        let (state, events) = transfer.apply(NodeIndex::new(1), &info, None, state);
        assert!(events.is_empty());
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::CLOSED);
    }

    #[test]
    fn double_close_emits_event() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::CLOSED);

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (20, 30),
            labels: smallvec::SmallVec::new(),
            defines: None,
            extra_defines: vec![],
            uses: vec!["f".into()],
            callee: Some("fclose".into()),
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
            arg_uses: vec![],
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            const_text: None,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
            bin_op_const: None,
            managed_resource: false,
            in_defer: false,
        };

        let (_state, events) = transfer.apply(NodeIndex::new(2), &info, None, state);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferEventKind::DoubleClose);
        assert_eq!(events[0].var, sym_f);
    }

    #[test]
    fn use_after_close_emits_event() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::CLOSED);

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (30, 40),
            labels: smallvec::SmallVec::new(),
            defines: None,
            extra_defines: vec![],
            uses: vec!["f".into()],
            callee: Some("fread".into()),
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
            arg_uses: vec![],
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            const_text: None,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
            bin_op_const: None,
            managed_resource: false,
            in_defer: false,
        };

        let (_state, events) = transfer.apply(NodeIndex::new(3), &info, None, state);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferEventKind::UseAfterClose);
    }

    #[test]
    fn is_guard_like_check() {
        assert!(is_guard_like("validate_input"));
        assert!(is_guard_like("sanitize_html"));
        assert!(is_guard_like("check_permission"));
        assert!(!is_guard_like("open_file"));
    }

    // ── Phase 13: callee_matches for new resource patterns ─────────────

    #[test]
    fn callee_matches_js_end_release() {
        assert!(callee_matches("conn.end", ".end"));
        assert!(callee_matches("pool.end", ".end"));
        assert!(!callee_matches("backend", ".end")); // no dot
    }

    #[test]
    fn callee_matches_go_sql_open() {
        assert!(callee_matches("sql.open", "sql.Open")); // case-insensitive
    }

    #[test]
    fn callee_matches_php_pg() {
        assert!(callee_matches("pg_connect", "pg_connect"));
        assert!(callee_matches("pg_close", "pg_close"));
        assert!(!callee_matches("pg_query", "pg_connect"));
    }

    #[test]
    fn callee_matches_java_prepare_statement() {
        assert!(callee_matches("conn.preparestatement", "prepareStatement"));
        assert!(callee_matches("preparestatement", "prepareStatement"));
    }

    #[test]
    fn callee_matches_websocket() {
        assert!(callee_matches("websocket", "WebSocket"));
    }

    #[test]
    fn callee_matches_mysql_create_connection() {
        assert!(callee_matches(
            "mysql.createconnection",
            "mysql.createConnection"
        ));
    }

    #[test]
    fn callee_matches_finish_release() {
        assert!(callee_matches("http.finish", ".finish"));
        assert!(!callee_matches("finish_setup", ".finish")); // no dot
    }

    // ── condition_contains_auth_token ────────────────────────────────────

    #[test]
    fn auth_token_exact_match() {
        assert!(condition_contains_auth_token(
            "is_authenticated",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token("is_admin", "is_admin"));
        assert!(condition_contains_auth_token(
            "require_auth",
            "require_auth"
        ));
    }

    #[test]
    fn auth_token_dotted_access() {
        assert!(condition_contains_auth_token(
            "req.is_authenticated()",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "user.is_authenticated == true",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "req.user.is_authenticated",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token("user.is_admin()", "is_admin"));
    }

    #[test]
    fn auth_token_rejects_substring_regression() {
        // Explicit regression locks for known false positives.
        assert!(!condition_contains_auth_token(
            "not_is_authenticated",
            "is_authenticated"
        ));
        assert!(!condition_contains_auth_token(
            "cached_is_authenticated_flag",
            "is_authenticated"
        ));
        assert!(!condition_contains_auth_token(
            "xis_authenticated",
            "is_authenticated"
        ));
        assert!(!condition_contains_auth_token(
            "this_is_admin_panel",
            "is_admin"
        ));
    }

    #[test]
    fn auth_token_underscore_camel_boundary_cases() {
        // Underscore-joined identifiers are single tokens — must not match interior.
        assert!(!condition_contains_auth_token(
            "req.user_is_authenticated_flag",
            "is_authenticated"
        ));
        // Dot-separated segments ARE separate tokens.
        assert!(condition_contains_auth_token(
            "req.user.is_authenticated",
            "is_authenticated"
        ));
    }

    #[test]
    fn auth_token_dotted_matcher() {
        assert!(condition_contains_auth_token(
            "middleware.auth()",
            "middleware.auth"
        ));
        assert!(condition_contains_auth_token(
            "if middleware.auth(req)",
            "middleware.auth"
        ));
        // Left boundary violation.
        assert!(!condition_contains_auth_token(
            "xmiddleware.auth()",
            "middleware.auth"
        ));
        // Right boundary violation — "middleware.authz" extends past "middleware.auth".
        assert!(!condition_contains_auth_token(
            "middleware.authz()",
            "middleware.auth"
        ));
        // "middleware.auth.check" — matcher ends at '.', which is non-ident → matches.
        assert!(condition_contains_auth_token(
            "middleware.auth.check()",
            "middleware.auth"
        ));
    }

    // ── Phase 13: condition_contains_auth_token for new auth patterns ──

    #[test]
    fn auth_token_jwt_verify() {
        assert!(condition_contains_auth_token(
            "jwt.verify(token)",
            "jwt.verify"
        ));
        assert!(!condition_contains_auth_token(
            "jwt.verifyAsync(token)",
            "jwt.verify"
        ));
    }

    #[test]
    fn auth_token_passport() {
        assert!(condition_contains_auth_token(
            "passport.authenticate('local')",
            "passport.authenticate"
        ));
    }

    #[test]
    fn auth_token_generate_not_auth() {
        assert!(!condition_contains_auth_token(
            "generateToken(secret)",
            "verify_token"
        ));
        assert!(!condition_contains_auth_token(
            "generateToken(secret)",
            "validate_token"
        ));
        assert!(!condition_contains_auth_token(
            "generateToken(secret)",
            "authenticate"
        ));
    }

    #[test]
    fn auth_token_ensure_authenticated() {
        // condition_contains_auth_token expects pre-lowered condition text
        assert!(condition_contains_auth_token(
            "ensureauthenticated(req)",
            "ensureAuthenticated"
        ));
    }

    #[test]
    fn auth_token_require_role_not_substring() {
        assert!(condition_contains_auth_token(
            "requirerole('admin')",
            "requireRole"
        ));
        assert!(!condition_contains_auth_token(
            "prerequirerole()",
            "requireRole"
        ));
    }

    #[test]
    fn auth_token_boolean_composition() {
        // Compound conditions — each token should be individually matchable.
        assert!(condition_contains_auth_token(
            "is_authenticated && is_admin",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "is_authenticated && is_admin",
            "is_admin"
        ));
        assert!(condition_contains_auth_token(
            "!is_authenticated && is_admin",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "user == null || !user.is_authenticated",
            "is_authenticated"
        ));
    }
}
