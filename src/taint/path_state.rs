use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

/// Maximum predicates tracked per path before truncation.
pub const MAX_PATH_PREDICATES: usize = 8;

// ─── PredicateKind ───────────────────────────────────────────────────────────

/// Classification of what an if-condition tests.
///
/// Determined by heuristic analysis of the raw condition text.
/// Classification is conservative: prefer [`Unknown`](PredicateKind::Unknown)
/// over a wrong guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateKind {
    /// `x.is_none()`, `x == null`, `x == nil`, `x is None`
    NullCheck,
    /// `x.is_empty()`, `x.len() == 0`, `x == ""`
    EmptyCheck,
    /// `x.is_err()`, `x.is_ok()`, `err != nil`
    ErrorCheck,
    /// Call to a validation/guard function: `validate(x)`, `is_safe(x)`
    ValidationCall,
    /// Call to a sanitizer function: `sanitize(x)`, `escape(x)`
    SanitizerCall,
    /// Comparison operators: `x == 5`, `x > threshold`
    Comparison,
    /// Generic boolean test — cannot classify further.
    Unknown,
}

/// Kinds eligible for contradiction pruning.
///
/// Only these single-variable predicates may cause a path to be considered
/// infeasible.  Everything else is left alone (conservative).
const CONTRADICTION_WHITELIST: &[PredicateKind] = &[
    PredicateKind::NullCheck,
    PredicateKind::EmptyCheck,
    PredicateKind::ErrorCheck,
];

/// Classify a raw condition text into a [`PredicateKind`].
///
/// # Rules
///
/// - Empty/None text → [`Unknown`](PredicateKind::Unknown).
/// - `ValidationCall` / `SanitizerCall` require a `(` in the text **and** a
///   matching callee token. This avoids misclassifying comparisons like
///   `x_valid == true`.
/// - Prefers [`Unknown`](PredicateKind::Unknown) over false positives.
pub fn classify_condition(text: &str) -> PredicateKind {
    if text.is_empty() {
        return PredicateKind::Unknown;
    }

    let lower = text.to_ascii_lowercase();

    // ── Error checks (before null checks: `err != nil` is an error check,
    //    not a null check, even though it contains `!= nil`) ──────────────
    if lower.contains("is_err")
        || lower.contains("is_ok")
        || lower.contains("err != nil")
        || lower.contains("err == nil")
        || lower.contains("error != nil")
        || lower.contains("error == nil")
    {
        return PredicateKind::ErrorCheck;
    }

    // ── Null checks ──────────────────────────────────────────────────────
    if lower.contains("is_none")
        || lower.contains("is_some")
        || lower.contains("== none")
        || lower.contains("!= none")
        || lower.contains("is none")
        || lower.contains("is not none")
        || lower.contains("== null")
        || lower.contains("!= null")
        || lower.contains("=== null")
        || lower.contains("!== null")
        || lower.contains("== nil")
        || lower.contains("!= nil")
    {
        return PredicateKind::NullCheck;
    }

    // ── Empty checks ─────────────────────────────────────────────────────
    if lower.contains("is_empty")
        || lower.contains(".len() == 0")
        || lower.contains(".len() != 0")
        || lower.contains(".length == 0")
        || lower.contains(".length === 0")
        || lower.contains(".length != 0")
        || lower.contains(".length !== 0")
        || lower.contains("== \"\"")
        || lower.contains("== ''")
    {
        return PredicateKind::EmptyCheck;
    }

    // ── Call-based kinds (require `(` to be present) ─────────────────────
    if lower.contains('(') {
        // Extract a rough callee token: everything before the first `(`
        // that looks like an identifier (letters, digits, underscores, dots).
        let callee_part = lower.split('(').next().unwrap_or("");
        // Take the last segment (after `.` or `::`) as the bare name.
        let bare = callee_part
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(callee_part)
            .trim();

        // Validation
        if bare.contains("valid")
            || bare.contains("check")
            || bare.contains("verify")
            || bare.starts_with("is_safe")
            || bare.starts_with("is_authorized")
            || bare.starts_with("is_authenticated")
        {
            return PredicateKind::ValidationCall;
        }

        // Sanitizer
        if bare.contains("sanitiz") || bare.contains("escape") || bare.contains("encode") {
            return PredicateKind::SanitizerCall;
        }
    }

    // ── Comparison operators ─────────────────────────────────────────────
    if lower.contains("==")
        || lower.contains("!=")
        || lower.contains(">=")
        || lower.contains("<=")
        || lower.contains(" > ")
        || lower.contains(" < ")
    {
        return PredicateKind::Comparison;
    }

    PredicateKind::Unknown
}

// ─── Predicate ───────────────────────────────────────────────────────────────

/// A single abstract predicate observed on the current BFS path.
#[derive(Debug, Clone)]
pub struct Predicate {
    /// Variables mentioned in the condition (sorted, max [`MAX_PATH_PREDICATES`]).
    pub vars: SmallVec<[String; 2]>,
    /// What the condition tests.
    pub kind: PredicateKind,
    /// `true` = the condition evaluated to true on this path (accounting for
    /// negation).  `false` = it evaluated to false.
    pub polarity: bool,
    /// The CFG If-node this predicate originated from.
    pub origin: NodeIndex,
}

// ─── PathState ───────────────────────────────────────────────────────────────

/// Accumulated path predicates for one BFS state.
///
/// Bounded at [`MAX_PATH_PREDICATES`].  When the limit is exceeded the oldest
/// predicate is dropped and the state is marked *truncated*, which disables
/// contradiction detection (conservative fallback).
#[derive(Debug, Clone)]
pub struct PathState {
    predicates: SmallVec<[Predicate; 4]>,
    truncated: bool,
}

impl Default for PathState {
    fn default() -> Self {
        Self::new()
    }
}

impl PathState {
    pub fn new() -> Self {
        Self {
            predicates: SmallVec::new(),
            truncated: false,
        }
    }

    /// Record a predicate from traversing an If node's True or False edge.
    pub fn push(&mut self, pred: Predicate) {
        if self.predicates.len() >= MAX_PATH_PREDICATES {
            self.predicates.remove(0);
            self.truncated = true;
        }
        self.predicates.push(pred);
    }

    /// Whether this path contains contradictory predicates.
    ///
    /// Contradiction is checked **conservatively**:
    /// - Only for whitelisted kinds (`NullCheck`, `EmptyCheck`, `ErrorCheck`).
    /// - Only when both predicates reference exactly one variable.
    /// - Only when the variable, kind, and polarity match with opposite polarity.
    /// - Never on truncated states.
    pub fn is_contradictory(&self) -> bool {
        if self.truncated {
            return false;
        }
        for (i, a) in self.predicates.iter().enumerate() {
            if a.vars.len() != 1 || !CONTRADICTION_WHITELIST.contains(&a.kind) {
                continue;
            }
            for b in &self.predicates[i + 1..] {
                if b.vars.len() != 1 || b.kind != a.kind {
                    continue;
                }
                if b.polarity != a.polarity && a.vars[0] == b.vars[0] {
                    return true;
                }
            }
        }
        false
    }

    /// Whether a validation predicate guards the given variable on this path.
    ///
    /// Only [`PredicateKind::ValidationCall`] counts (not `SanitizerCall` —
    /// sanitizers transform data rather than returning boolean guards).
    pub fn has_validation_for(&self, var: &str) -> bool {
        self.predicates.iter().any(|p| {
            p.polarity && p.kind == PredicateKind::ValidationCall && p.vars.iter().any(|v| v == var)
        })
    }

    /// The kind of the first validation guard that covers `var`, if any.
    pub fn guard_kind_for(&self, var: &str) -> Option<PredicateKind> {
        self.predicates.iter().find_map(|p| {
            if p.polarity
                && p.kind == PredicateKind::ValidationCall
                && p.vars.iter().any(|v| v == var)
            {
                Some(p.kind)
            } else {
                None
            }
        })
    }

    /// Compute a hash for seen-state deduplication.
    ///
    /// Includes `(origin, kind, polarity, vars)` per predicate — enough to
    /// distinguish materially different path states without being too
    /// fine-grained.
    pub fn state_hash(&self) -> u64 {
        let mut h: u64 = 0;
        for p in &self.predicates {
            let mut entry_h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
            // origin
            entry_h ^= p.origin.index() as u64;
            entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
            // kind
            entry_h ^= p.kind as u64;
            entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
            // polarity
            entry_h ^= p.polarity as u64;
            entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
            // vars: if single-var hash the var directly; else hash all of them.
            if p.vars.len() == 1 {
                for b in p.vars[0].as_bytes() {
                    entry_h ^= *b as u64;
                    entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
                }
            } else {
                for v in &p.vars {
                    for b in v.as_bytes() {
                        entry_h ^= *b as u64;
                        entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
                    }
                    // separator
                    entry_h ^= 0xff;
                    entry_h = entry_h.wrapping_mul(0x0100_0000_01b3);
                }
            }
            h ^= entry_h;
        }
        h
    }

    /// Priority for deterministic eviction from the seen-state map.
    ///
    /// Higher priority = better state to keep.
    /// Prefers non-truncated states, then fewer predicates (more precise).
    pub fn priority(&self) -> (bool, usize) {
        (
            !self.truncated,
            MAX_PATH_PREDICATES.saturating_sub(self.predicates.len()),
        )
    }

    /// Whether this state has been truncated (predicates were dropped).
    #[allow(dead_code)] // public API for future consumers and tests
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Number of predicates currently tracked.
    #[allow(dead_code)] // public API for future consumers and tests
    pub fn len(&self) -> usize {
        self.predicates.len()
    }

    /// Whether no predicates are tracked.
    #[allow(dead_code)] // public API for future consumers and tests
    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pred(var: &str, kind: PredicateKind, polarity: bool, origin_idx: usize) -> Predicate {
        Predicate {
            vars: SmallVec::from_elem(var.to_string(), 1),
            kind,
            polarity,
            origin: NodeIndex::new(origin_idx),
        }
    }

    fn make_multi_var_pred(
        vars: &[&str],
        kind: PredicateKind,
        polarity: bool,
        origin_idx: usize,
    ) -> Predicate {
        Predicate {
            vars: vars.iter().map(|v| v.to_string()).collect(),
            kind,
            polarity,
            origin: NodeIndex::new(origin_idx),
        }
    }

    // ── classify_condition ────────────────────────────────────────────────

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(classify_condition(""), PredicateKind::Unknown);
    }

    #[test]
    fn classify_null_checks() {
        assert_eq!(classify_condition("x.is_none()"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x == null"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x != nil"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x is None"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x === null"), PredicateKind::NullCheck);
    }

    #[test]
    fn classify_error_checks() {
        assert_eq!(classify_condition("x.is_err()"), PredicateKind::ErrorCheck);
        assert_eq!(classify_condition("err != nil"), PredicateKind::ErrorCheck);
        assert_eq!(classify_condition("x.is_ok()"), PredicateKind::ErrorCheck);
    }

    #[test]
    fn classify_empty_checks() {
        assert_eq!(
            classify_condition("x.is_empty()"),
            PredicateKind::EmptyCheck
        );
        assert_eq!(
            classify_condition("x.len() == 0"),
            PredicateKind::EmptyCheck
        );
        assert_eq!(
            classify_condition("x.length === 0"),
            PredicateKind::EmptyCheck
        );
    }

    #[test]
    fn classify_validation_call() {
        assert_eq!(
            classify_condition("validate(x)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("is_safe(input)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("check_auth(req)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("input.verify(sig)"),
            PredicateKind::ValidationCall
        );
    }

    #[test]
    fn classify_validation_requires_paren() {
        // `x_valid == true` should NOT be ValidationCall — no `(` call syntax.
        assert_eq!(
            classify_condition("x_valid == true"),
            PredicateKind::Comparison
        );
        assert_eq!(
            classify_condition("is_valid && ready"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_sanitizer_call() {
        assert_eq!(
            classify_condition("sanitize(x)"),
            PredicateKind::SanitizerCall
        );
        assert_eq!(
            classify_condition("html_escape(s)"),
            PredicateKind::SanitizerCall
        );
        assert_eq!(
            classify_condition("url_encode(path)"),
            PredicateKind::SanitizerCall
        );
    }

    #[test]
    fn classify_comparison() {
        assert_eq!(classify_condition("x == 5"), PredicateKind::Comparison);
        assert_eq!(classify_condition("x != y"), PredicateKind::Comparison);
        assert_eq!(classify_condition("a >= b"), PredicateKind::Comparison);
    }

    #[test]
    fn classify_unknown_fallback() {
        assert_eq!(classify_condition("flag"), PredicateKind::Unknown);
        assert_eq!(classify_condition("a && b"), PredicateKind::Unknown);
    }

    // ── PathState::push + truncation ─────────────────────────────────────

    #[test]
    fn push_within_budget() {
        let mut ps = PathState::new();
        for i in 0..MAX_PATH_PREDICATES {
            ps.push(make_pred("x", PredicateKind::NullCheck, true, i));
        }
        assert_eq!(ps.len(), MAX_PATH_PREDICATES);
        assert!(!ps.is_truncated());
    }

    #[test]
    fn push_over_budget_truncates() {
        let mut ps = PathState::new();
        for i in 0..=MAX_PATH_PREDICATES {
            ps.push(make_pred("x", PredicateKind::NullCheck, true, i));
        }
        assert_eq!(ps.len(), MAX_PATH_PREDICATES);
        assert!(ps.is_truncated());
    }

    // ── PathState::is_contradictory ──────────────────────────────────────

    #[test]
    fn contradictory_null_check() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::NullCheck, true, 0));
        ps.push(make_pred("x", PredicateKind::NullCheck, false, 1));
        assert!(ps.is_contradictory());
    }

    #[test]
    fn contradictory_empty_check() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::EmptyCheck, true, 0));
        ps.push(make_pred("x", PredicateKind::EmptyCheck, false, 1));
        assert!(ps.is_contradictory());
    }

    #[test]
    fn contradictory_error_check() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::ErrorCheck, true, 0));
        ps.push(make_pred("x", PredicateKind::ErrorCheck, false, 1));
        assert!(ps.is_contradictory());
    }

    #[test]
    fn not_contradictory_different_vars() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::NullCheck, true, 0));
        ps.push(make_pred("y", PredicateKind::NullCheck, false, 1));
        assert!(!ps.is_contradictory());
    }

    #[test]
    fn not_contradictory_same_polarity() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::NullCheck, true, 0));
        ps.push(make_pred("x", PredicateKind::NullCheck, true, 1));
        assert!(!ps.is_contradictory());
    }

    #[test]
    fn not_contradictory_non_whitelisted_kind() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::Comparison, true, 0));
        ps.push(make_pred("x", PredicateKind::Comparison, false, 1));
        assert!(!ps.is_contradictory());
    }

    #[test]
    fn not_contradictory_multi_var() {
        let mut ps = PathState::new();
        ps.push(make_multi_var_pred(
            &["x", "y"],
            PredicateKind::NullCheck,
            true,
            0,
        ));
        ps.push(make_multi_var_pred(
            &["x", "y"],
            PredicateKind::NullCheck,
            false,
            1,
        ));
        assert!(!ps.is_contradictory());
    }

    #[test]
    fn not_contradictory_when_truncated() {
        let mut ps = PathState::new();
        // Fill to capacity then overflow to trigger truncation.
        for i in 0..MAX_PATH_PREDICATES + 1 {
            ps.push(make_pred("z", PredicateKind::Unknown, true, i + 10));
        }
        assert!(ps.is_truncated());
        // Now add contradictory predicates — should not fire.
        ps.push(make_pred("x", PredicateKind::NullCheck, true, 100));
        // Need to make room — it's already truncated so one more push is fine.
        ps.push(make_pred("x", PredicateKind::NullCheck, false, 101));
        assert!(!ps.is_contradictory());
    }

    // ── PathState::has_validation_for ────────────────────────────────────

    #[test]
    fn has_validation_for_present() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::ValidationCall, true, 0));
        assert!(ps.has_validation_for("x"));
    }

    #[test]
    fn has_validation_for_wrong_polarity() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::ValidationCall, false, 0));
        assert!(!ps.has_validation_for("x"));
    }

    #[test]
    fn sanitizer_call_does_not_count_as_validation() {
        let mut ps = PathState::new();
        ps.push(make_pred("x", PredicateKind::SanitizerCall, true, 0));
        assert!(!ps.has_validation_for("x"));
    }

    #[test]
    fn has_validation_for_wrong_var() {
        let mut ps = PathState::new();
        ps.push(make_pred("y", PredicateKind::ValidationCall, true, 0));
        assert!(!ps.has_validation_for("x"));
    }

    // ── PathState::state_hash ────────────────────────────────────────────

    #[test]
    fn state_hash_deterministic() {
        let mut ps1 = PathState::new();
        ps1.push(make_pred("x", PredicateKind::NullCheck, true, 0));
        ps1.push(make_pred("y", PredicateKind::ErrorCheck, false, 1));

        let mut ps2 = PathState::new();
        ps2.push(make_pred("x", PredicateKind::NullCheck, true, 0));
        ps2.push(make_pred("y", PredicateKind::ErrorCheck, false, 1));

        assert_eq!(ps1.state_hash(), ps2.state_hash());
    }

    #[test]
    fn state_hash_differs_on_polarity() {
        let mut ps1 = PathState::new();
        ps1.push(make_pred("x", PredicateKind::NullCheck, true, 0));

        let mut ps2 = PathState::new();
        ps2.push(make_pred("x", PredicateKind::NullCheck, false, 0));

        assert_ne!(ps1.state_hash(), ps2.state_hash());
    }

    #[test]
    fn state_hash_differs_on_kind() {
        let mut ps1 = PathState::new();
        ps1.push(make_pred("x", PredicateKind::NullCheck, true, 0));

        let mut ps2 = PathState::new();
        ps2.push(make_pred("x", PredicateKind::EmptyCheck, true, 0));

        assert_ne!(ps1.state_hash(), ps2.state_hash());
    }

    #[test]
    fn state_hash_differs_on_var() {
        let mut ps1 = PathState::new();
        ps1.push(make_pred("x", PredicateKind::NullCheck, true, 0));

        let mut ps2 = PathState::new();
        ps2.push(make_pred("y", PredicateKind::NullCheck, true, 0));

        assert_ne!(ps1.state_hash(), ps2.state_hash());
    }

    // ── PathState::priority ──────────────────────────────────────────────

    #[test]
    fn priority_non_truncated_better() {
        let ps_normal = PathState::new();
        let mut ps_trunc = PathState::new();
        for i in 0..=MAX_PATH_PREDICATES {
            ps_trunc.push(make_pred("x", PredicateKind::Unknown, true, i));
        }
        assert!(ps_normal.priority() > ps_trunc.priority());
    }

    #[test]
    fn priority_fewer_predicates_better() {
        let mut ps1 = PathState::new();
        ps1.push(make_pred("x", PredicateKind::NullCheck, true, 0));

        let mut ps2 = PathState::new();
        ps2.push(make_pred("x", PredicateKind::NullCheck, true, 0));
        ps2.push(make_pred("y", PredicateKind::NullCheck, true, 1));
        ps2.push(make_pred("z", PredicateKind::NullCheck, true, 2));

        assert!(ps1.priority() > ps2.priority());
    }
}
