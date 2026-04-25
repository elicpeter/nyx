use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence, is_sink};
use crate::cfg::{EdgeKind, StmtKind};
use crate::patterns::Severity;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

/// Does the condition text contain a unary `!` (logical-not, NOT `!=`)
/// applied to an identifier or member chain whose name contains "err"?
///
/// Used by the error-fallthrough rule to skip happy-path checks
/// like `if (!data.error && Array.isArray(results))` whose TRUE branch
/// is the success path and is not expected to return.  The original
/// rule fires on `if (err) { warn(); } sink_after()` — a positive
/// error check whose body forgets to early-return.
fn contains_negated_err_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'!' {
            i += 1;
            continue;
        }
        // Skip the `!=` / `!==` operators — those are comparisons, not
        // logical-not.  Only treat a `!` followed by whitespace or an
        // identifier-leading char as logical negation.
        if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        // Allow a leading `(` for `!(expr)` shapes — peek past one open
        // paren and continue capturing the identifier chain.
        if j < bytes.len() && bytes[j] == b'(' {
            j += 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
        }
        let start = j;
        while j < bytes.len() {
            let b = bytes[j];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'$' {
                j += 1;
            } else {
                break;
            }
        }
        if j > start {
            // Lowercase compare without allocating a full lowercase
            // copy: walk byte-by-byte.
            let mut k = start;
            while k + 2 < j {
                if (bytes[k] | 0x20) == b'e'
                    && (bytes[k + 1] | 0x20) == b'r'
                    && (bytes[k + 2] | 0x20) == b'r'
                {
                    return true;
                }
                k += 1;
            }
        }
        i = if j > i { j } else { i + 1 };
    }
    false
}

pub struct IncompleteErrorHandling;

/// Check if the true branch of an If node terminates (has Return/Break/Continue).
fn branch_terminates(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> bool {
    // Follow the True edge from the If node
    let true_successors: Vec<NodeIndex> = cfg
        .edges(if_node)
        .filter(|e| matches!(e.weight(), EdgeKind::True))
        .map(|e| e.target())
        .collect();

    if true_successors.is_empty() {
        return false;
    }

    // Check if any path through the true branch terminates
    for &start in &true_successors {
        if terminates_on_all_paths(cfg, start, if_node) {
            return true;
        }
    }

    false
}

/// Check if all paths from `node` reach a Return/Break/Continue before exiting scope.
fn terminates_on_all_paths(
    cfg: &crate::cfg::Cfg,
    node: NodeIndex,
    _scope_entry: NodeIndex,
) -> bool {
    use std::collections::HashSet;

    let mut visited = HashSet::new();
    let mut stack = vec![node];

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }

        let info = &cfg[current];
        match info.kind {
            StmtKind::Return | StmtKind::Throw | StmtKind::Break | StmtKind::Continue => {
                // This path terminates
                continue;
            }
            _ => {}
        }

        let successors: Vec<_> = cfg.neighbors(current).collect();
        if successors.is_empty() {
            // Reached a dead end without terminating — path does not terminate
            return false;
        }

        for succ in successors {
            // Don't follow back edges (loops)
            let is_back_edge = cfg
                .edges(current)
                .any(|e| e.target() == succ && matches!(e.weight(), EdgeKind::Back));
            if !is_back_edge {
                stack.push(succ);
            }
        }
    }

    true
}

/// Find successor nodes after an If node merges (nodes reachable from both branches).
fn find_post_if_sinks(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> Vec<NodeIndex> {
    let mut sinks_after = Vec::new();

    // Get all successors of the if node's merge point
    // Walk through successors looking for sinks
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<NodeIndex> = cfg.neighbors(if_node).collect();

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }

        let info = &cfg[current];
        if is_sink(info) || (info.kind == StmtKind::Call && info.call.callee.is_some()) {
            sinks_after.push(current);
        }

        for succ in cfg.neighbors(current) {
            let is_back_edge = cfg
                .edges(current)
                .any(|e| e.target() == succ && matches!(e.weight(), EdgeKind::Back));
            if !is_back_edge {
                stack.push(succ);
            }
        }
    }

    sinks_after
}

impl CfgAnalysis for IncompleteErrorHandling {
    fn name(&self) -> &'static str {
        "incomplete-error-handling"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let mut findings = Vec::new();

        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];

            // Look for If nodes whose CONDITION involves "err" or "error".
            // `info.taint.uses` for an If node contains identifiers from the
            // whole if statement (condition + body) — see
            // `cfg::literals::extract_defs_uses_extra_defs` Kind::If branch
            // — so checking it would misfire on `if (!res.ok) { ... const
            // err = await … ; return … }` shapes whose body happens to
            // mention `err` even though the condition doesn't.  Use
            // `info.condition_vars`, which is populated strictly from the
            // condition subtree (`extract_condition_raw`).
            if info.kind != StmtKind::If {
                continue;
            }

            let mentions_err = info.condition_vars.iter().any(|u| {
                let lower = u.to_ascii_lowercase();
                lower == "err" || lower == "error" || lower.contains("err")
            });

            if !mentions_err {
                continue;
            }

            // Polarity gate: only fire when the condition POSITIVELY
            // checks for an error.  `if (!data.error && other)` is a
            // happy-path check — the TRUE branch is the success branch
            // and is not expected to terminate.  Detect by scanning the
            // condition text for any `!` (logical-not, distinct from
            // `!=`) preceding an identifier whose name contains "err".
            //
            // This is the polarity-aware complement to
            // `condition_negated` (which only catches the top-level
            // unary `!`); compound conditions with embedded
            // `!response.error` legitimately fall outside the rule's
            // intended target shape (Go `if err != nil { non-return }`
            // / JS `if (err) { warn(); }`).
            if let Some(text) = info.condition_text.as_deref()
                && contains_negated_err_identifier(text)
            {
                continue;
            }
            if info.condition_negated {
                continue;
            }

            // Check: does the true branch terminate?
            if branch_terminates(ctx.cfg, idx) {
                continue;
            }

            // Check: are there dangerous calls/sinks after this error check?
            let post_sinks = find_post_if_sinks(ctx.cfg, idx);
            let has_dangerous_successor = post_sinks.iter().any(|&s| is_sink(&ctx.cfg[s]));

            if has_dangerous_successor {
                findings.push(CfgFinding {
                    rule_id: "cfg-error-fallthrough".to_string(),
                    title: "Error check without return".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    span: info.ast.span,
                    message: "Error check does not terminate on error; \
                              execution falls through to dangerous operations"
                        .to_string(),
                    evidence: vec![idx],
                    score: None,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod negation_tests {
    use super::contains_negated_err_identifier;

    #[test]
    fn detects_simple_negated_err() {
        assert!(contains_negated_err_identifier("!err"));
        assert!(contains_negated_err_identifier("!error"));
        assert!(contains_negated_err_identifier("! err"));
    }

    #[test]
    fn detects_negated_member_err() {
        assert!(contains_negated_err_identifier("!data.error"));
        assert!(contains_negated_err_identifier(
            "data && !data.error && Array.isArray(results)"
        ));
        assert!(contains_negated_err_identifier(
            "!response.errorMsg && response.ok"
        ));
    }

    #[test]
    fn does_not_match_inequality() {
        assert!(!contains_negated_err_identifier("err != nil"));
        assert!(!contains_negated_err_identifier("error !== null"));
    }

    #[test]
    fn does_not_match_positive_err_checks() {
        assert!(!contains_negated_err_identifier("err"));
        assert!(!contains_negated_err_identifier("err != null"));
        assert!(!contains_negated_err_identifier("response.error"));
        assert!(!contains_negated_err_identifier("hasError(x)"));
    }
}
