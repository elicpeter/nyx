use super::dominators;
use super::rules;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence};
use crate::cfg::StmtKind;
use crate::patterns::Severity;
use petgraph::graph::NodeIndex;
use std::collections::HashSet;

pub struct ResourceMisuse;

/// Find nodes matching acquire patterns for a given resource pair,
/// excluding any that match `exclude_patterns`.
fn find_acquire_nodes(
    ctx: &AnalysisContext,
    acquire_patterns: &[&str],
    exclude_patterns: &[&str],
) -> Vec<NodeIndex> {
    ctx.cfg
        .node_indices()
        .filter(|&idx| {
            let info = &ctx.cfg[idx];
            if info.kind != StmtKind::Call {
                return false;
            }
            if let Some(callee) = &info.callee {
                let callee_lower = callee.to_ascii_lowercase();
                // Check exclusions first — if the callee matches an exclude
                // pattern, it is NOT an acquire even if it also matches an
                // acquire pattern (e.g. `freopen` ends with `fopen`).
                let excluded = exclude_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                });
                if excluded {
                    return false;
                }
                acquire_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                })
            } else {
                false
            }
        })
        .collect()
}

/// Find nodes matching release patterns for a given resource pair.
fn find_release_nodes(ctx: &AnalysisContext, release_patterns: &[&str]) -> Vec<NodeIndex> {
    ctx.cfg
        .node_indices()
        .filter(|&idx| {
            let info = &ctx.cfg[idx];
            if info.kind != StmtKind::Call {
                return false;
            }
            if let Some(callee) = &info.callee {
                let callee_lower = callee.to_ascii_lowercase();
                release_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                })
            } else {
                false
            }
        })
        .collect()
}

/// Check if a release node is on all paths from acquire to every exit.
fn release_on_all_exit_paths(
    ctx: &AnalysisContext,
    acquire: NodeIndex,
    release_nodes: &[NodeIndex],
    exit: NodeIndex,
) -> bool {
    // Use post-dominators as optimization: if any release post-dominates acquire, it's fine
    if let Some(post_doms) = dominators::compute_post_dominators(ctx.cfg) {
        for &release in release_nodes {
            if dominators::dominates(&post_doms, release, acquire) {
                return true;
            }
        }
    }

    // Fall back to path enumeration via DFS
    // Check if all paths from acquire to exit pass through a release
    let release_set: HashSet<_> = release_nodes.iter().copied().collect();
    all_paths_pass_through(ctx, acquire, exit, &release_set)
}

/// Check if all paths from `from` to `to` pass through at least one node in `through`.
fn all_paths_pass_through(
    ctx: &AnalysisContext,
    from: NodeIndex,
    to: NodeIndex,
    through: &HashSet<NodeIndex>,
) -> bool {
    use std::collections::VecDeque;

    if through.contains(&from) {
        return true;
    }

    // BFS, tracking whether we've passed through a required node
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((from, false));
    visited.insert((from, false));

    while let Some((node, passed)) = queue.pop_front() {
        if node == to {
            if !passed {
                return false; // Found a path to exit without passing through release
            }
            continue;
        }

        for succ in ctx.cfg.neighbors(node) {
            let new_passed = passed || through.contains(&succ);
            let state = (succ, new_passed);
            if visited.insert(state) {
                queue.push_back(state);
            }
        }
    }

    true
}

/// Check whether the acquired variable is stored into a struct field (ownership
/// transfer) downstream of the acquire node.  Patterns recognised:
///   - `ptr->field = var`   (C arrow operator)
///   - `obj.field = var`    (C dot / generic field store)
///   - `list->next = ...`   (linked-list insertion)
///
/// If the variable is transferred, there is no leak — the receiving struct is
/// responsible for the lifetime.
fn is_ownership_transferred(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    let acquired_var = match &ctx.cfg[acquire].defines {
        Some(v) => v.clone(),
        None => return false,
    };

    // BFS through CFG successors looking for a node whose span text
    // mentions the acquired variable in a struct-field store context.
    use std::collections::VecDeque;
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for succ in ctx.cfg.neighbors(acquire) {
        if visited.insert(succ) {
            queue.push_back(succ);
        }
    }

    while let Some(node) = queue.pop_front() {
        let info = &ctx.cfg[node];
        let (start, end) = info.span;

        // Check the source text at this node's span for the acquired variable
        // appearing in a struct-field store context.
        let references_var = info.uses.iter().any(|u| u == &acquired_var)
            || info.defines.as_ref().is_some_and(|d| d == &acquired_var);

        if references_var && start < end && end <= ctx.source_bytes.len() {
            let span_text = &ctx.source_bytes[start..end];
            // `->` anywhere in span means pointer-to-member store
            if span_text.windows(2).any(|w| w == b"->") {
                return true;
            }
            // `.field = var` pattern (but not `==`)
            if has_dot_field_assignment(span_text) {
                return true;
            }
        }

        // If the variable is truly redefined (not a field write), stop
        // following this path. A true redefinition is when `defines` matches
        // but the span doesn't contain `->` or `.field =` patterns.
        if info.defines.as_ref().is_some_and(|d| d == &acquired_var) {
            let is_field_write = if start < end && end <= ctx.source_bytes.len() {
                let span_text = &ctx.source_bytes[start..end];
                span_text.windows(2).any(|w| w == b"->") || has_dot_field_assignment(span_text)
            } else {
                false
            };
            if !is_field_write {
                continue; // genuine redefinition — stop this path
            }
        }

        for succ in ctx.cfg.neighbors(node) {
            if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    false
}

/// Check if `span_text` contains a dot-field assignment pattern like
/// `obj.field = var` (but not `obj.method(...)` or `a == b`).
fn has_dot_field_assignment(span_text: &[u8]) -> bool {
    // Look for `.` followed (possibly with ident chars) by `=` but not `==`
    let mut i = 0;
    while i < span_text.len() {
        if span_text[i] == b'.' {
            // Scan forward past identifier chars to find `=`
            let mut j = i + 1;
            while j < span_text.len()
                && (span_text[j].is_ascii_alphanumeric() || span_text[j] == b'_')
            {
                j += 1;
            }
            // Skip whitespace
            while j < span_text.len() && span_text[j].is_ascii_whitespace() {
                j += 1;
            }
            // Check for `=` but not `==`
            if j < span_text.len()
                && span_text[j] == b'='
                && (j + 1 >= span_text.len() || span_text[j + 1] != b'=')
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Check whether the acquired variable is consumed by an ownership-taking
/// function (e.g. `FileResponse(f)`, `send_file(f)`) downstream of the
/// acquire node.  These functions take ownership of the file handle so there
/// is no leak.
fn is_consumed_by_owner(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    static CONSUMING_SINKS: &[&str] = &[
        "fileresponse",
        "streaminghttpresponse",
        "send_file",
        "make_response",
    ];

    let acquired_var = match &ctx.cfg[acquire].defines {
        Some(v) => v.clone(),
        None => return false,
    };

    use std::collections::VecDeque;
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for succ in ctx.cfg.neighbors(acquire) {
        if visited.insert(succ) {
            queue.push_back(succ);
        }
    }

    while let Some(node) = queue.pop_front() {
        let info = &ctx.cfg[node];

        // Check Call nodes with callee that matches a consuming sink
        if info.kind == StmtKind::Call
            && let Some(callee) = &info.callee
        {
            let callee_lower = callee.to_ascii_lowercase();
            let is_consuming = CONSUMING_SINKS.iter().any(|s| callee_lower.ends_with(s));
            if is_consuming && info.uses.iter().any(|u| u == &acquired_var) {
                return true;
            }
        }

        // Also check the span text for consuming calls — handles cases where
        // the call is embedded in a return statement (e.g. `return FileResponse(f)`)
        if info.uses.iter().any(|u| u == &acquired_var) {
            let (start, end) = info.span;
            if start < end && end <= ctx.source_bytes.len() {
                let span_lower: Vec<u8> = ctx.source_bytes[start..end]
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect();
                if CONSUMING_SINKS
                    .iter()
                    .any(|s| span_lower.windows(s.len()).any(|w| w == s.as_bytes()))
                {
                    return true;
                }
            }
        }

        for succ in ctx.cfg.neighbors(node) {
            if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    false
}

/// For mutex pairs, check that an explicit `.acquire()` or `.lock()` call
/// exists on the acquired variable in the CFG.  If only the constructor
/// (e.g. `threading.Lock()`) is observed without acquire, skip the finding.
fn has_explicit_lock_acquire(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    let acquired_var = match &ctx.cfg[acquire].defines {
        Some(v) => v.clone(),
        None => return false,
    };

    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.kind != StmtKind::Call {
            continue;
        }
        if let Some(callee) = &info.callee {
            let callee_lower = callee.to_ascii_lowercase();
            let is_lock_call = callee_lower.ends_with(".acquire")
                || callee_lower.ends_with(".lock")
                || callee_lower == "pthread_mutex_lock";
            if is_lock_call && info.uses.iter().any(|u| u == &acquired_var) {
                return true;
            }
        }
    }

    false
}

impl CfgAnalysis for ResourceMisuse {
    fn name(&self) -> &'static str {
        "resource-misuse"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let pairs = rules::resource_pairs(ctx.lang);
        let exit = match dominators::find_exit_node(ctx.cfg) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let mut findings = Vec::new();

        for pair in pairs {
            let acquire_nodes = find_acquire_nodes(ctx, pair.acquire, pair.exclude_acquire);
            let release_nodes = find_release_nodes(ctx, pair.release);

            for &acquire in &acquire_nodes {
                // Suppress resources inside managed cleanup scopes
                // (Python `with`, Java try-with-resources).
                if ctx.cfg[acquire].managed_resource {
                    continue;
                }
                // Suppress resources with a deferred release (Go `defer f.Close()`).
                // Defer guarantees cleanup on all exit paths including early returns.
                if let Some(acquired_var) = ctx.cfg[acquire].defines.as_deref() {
                    let has_deferred_release = release_nodes.iter().any(|&r| {
                        ctx.cfg[r].in_defer && ctx.cfg[r].uses.iter().any(|u| u == acquired_var)
                    });
                    if has_deferred_release {
                        continue;
                    }
                }
                if !release_on_all_exit_paths(ctx, acquire, &release_nodes, exit)
                    && !is_ownership_transferred(ctx, acquire)
                    && !is_consumed_by_owner(ctx, acquire)
                {
                    // For mutex pairs, require an explicit .acquire()/.lock() call
                    if pair.resource_name == "mutex" && !has_explicit_lock_acquire(ctx, acquire) {
                        continue;
                    }
                    let info = &ctx.cfg[acquire];
                    let callee_desc = info.callee.as_deref().unwrap_or("(acquire)");

                    findings.push(CfgFinding {
                        rule_id: if pair.resource_name == "mutex" {
                            "cfg-lock-not-released".to_string()
                        } else {
                            "cfg-resource-leak".to_string()
                        },
                        title: format!("{} may leak", pair.resource_name),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        span: info.span,
                        message: format!(
                            "`{callee_desc}` acquires {} but not all exit paths \
                             release it",
                            pair.resource_name
                        ),
                        evidence: vec![acquire],
                        score: None,
                    });
                }
            }
        }

        findings
    }
}
