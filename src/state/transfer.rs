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
    "read", "write", "send", "recv", "fread", "fwrite", "fgets", "fputs", "fprintf", "fscanf",
    "fflush", "fseek", "ftell", "rewind", "feof", "ferror", "fgetc", "fputc", "getc", "putc",
    "ungetc", "query", "execute", "fetch", "sendto", "recvfrom", "ioctl", "fcntl",
    // Memory access functions (for malloc/free use-after-free detection)
    "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "memset", "memcmp", "strcmp",
    "strncmp", "strlen", "sprintf", "snprintf",
];

/// Auth-call matchers for admin-level privilege.
static ADMIN_PATTERNS: &[&str] = &[
    "is_admin",
    "hasrole",
    "has_role",
    "check_admin",
    "require_admin",
];

pub struct DefaultTransfer<'a> {
    pub lang: Lang,
    pub resource_pairs: &'a [ResourcePair],
    pub interner: &'a SymbolInterner,
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
        for pair in self.resource_pairs {
            let is_acquire = pair.acquire.iter().any(|a| callee_matches(&callee, a));
            let is_excluded = pair
                .exclude_acquire
                .iter()
                .any(|e| callee_matches(&callee, e));

            if is_acquire
                && !is_excluded
                && let Some(ref def) = info.defines
                && let Some(sym) = self.interner.get(def)
            {
                state.resource.set(sym, ResourceLifecycle::OPEN);
            }
        }

        // ── Resource release ─────────────────────────────────────────────
        // Track which variables have already been released to avoid double-
        // matching across multiple resource pair definitions.
        let mut released: smallvec::SmallVec<[SymbolId; 4]> = smallvec::SmallVec::new();
        for pair in self.resource_pairs {
            let is_release = pair.release.iter().any(|r| callee_matches(&callee, r));
            if is_release {
                for used in &info.uses {
                    if let Some(sym) = self.interner.get(used) {
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

        // ── Resource use (read/write/etc.) ───────────────────────────────
        let is_use = RESOURCE_USE_PATTERNS
            .iter()
            .any(|p| callee_matches(&callee, p));
        if is_use {
            for used in &info.uses {
                if let Some(sym) = self.interner.get(used) {
                    let current = state.resource.get(sym);
                    if current == ResourceLifecycle::CLOSED {
                        events.push(TransferEvent {
                            kind: TransferEventKind::UseAfterClose,
                            node: node_idx,
                            var: sym,
                        });
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
                if let Some(sym) = self.interner.get(used) {
                    state.auth.validated.insert(sym);
                }
            }
        }
    }

    fn apply_if(&self, info: &NodeInfo, edge: Option<EdgeKind>, state: &mut ProductState) {
        // On the True edge of an If node whose condition is an auth check,
        // refine auth level.
        let is_true_edge = matches!(edge, Some(EdgeKind::True));
        if !is_true_edge {
            return;
        }

        if let Some(ref cond) = info.condition_text {
            let cond_lower = cond.to_ascii_lowercase();

            // Auth-related condition
            let auth_rules = rules::auth_rules(self.lang);
            let is_auth_cond = auth_rules.iter().any(|rule| {
                rule.matchers
                    .iter()
                    .any(|m| cond_lower.contains(&m.to_ascii_lowercase()))
            });
            if is_auth_cond && !info.condition_negated {
                let is_admin = ADMIN_PATTERNS.iter().any(|p| cond_lower.contains(p));
                let new_level = if is_admin {
                    AuthLevel::Admin
                } else {
                    AuthLevel::Authed
                };
                if new_level > state.auth.auth_level {
                    state.auth.auth_level = new_level;
                }
            }

            // Validation-related condition
            if is_guard_like(&cond_lower) && !info.condition_negated {
                for var in &info.condition_vars {
                    if let Some(sym) = self.interner.get(var) {
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
            && let Some(def_sym) = self.interner.get(def)
        {
            // If the RHS is a tracked resource, transfer its state
            for used in &info.uses {
                if let Some(use_sym) = self.interner.get(used) {
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
    fn acquire_sets_open() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (0, 10),
            label: None,
            defines: Some("f".into()),
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
            catch_param: false,
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
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (10, 20),
            label: None,
            defines: None,
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
            catch_param: false,
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
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::CLOSED);

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (20, 30),
            label: None,
            defines: None,
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
            catch_param: false,
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
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::CLOSED);

        let info = NodeInfo {
            kind: StmtKind::Call,
            span: (30, 40),
            label: None,
            defines: None,
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
            catch_param: false,
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
}
