//! Path abstract domain for abstract interpretation.
//!
//! Tracks the abstract effect of path-sanitizer primitives on filesystem path
//! values along three independent axes:
//!
//! - `dotdot`: whether the path contains a `..` component
//! - `absolute`: whether the path is absolute (rooted at `/`, `\\`, `C:\\`, …)
//! - `normalized`: whether the path has been passed through a canonicalisation
//!   / structural filter step (e.g. `fs::canonicalize`, `Component::Normal`
//!   iterator filter)
//!
//! Plus a `prefix_lock` that records the known canonical root of the path
//! after a `starts_with(root_literal)` guard has been asserted on it.
//!
//! Each axis is a three-value lattice [`Tri::No`] / [`Tri::Yes`] / [`Tri::Maybe`]
//! where `Maybe` is Top (unknown) and `No` / `Yes` are the two definite
//! refinements.  A value is path-safe for a FILE_IO sink iff
//! `dotdot == No && absolute == No` — i.e. we have proof that *no* `..`
//! component and *no* absolute root can leak through.  `normalized == Yes`
//! alone is not sufficient (canonicalising an absolute input still produces
//! an absolute path); prefix_lock is used separately to certify containment
//! under a known root.
//!
//! This domain is Rust-first: the transfer rules wired from
//! `src/taint/ssa_transfer` recognise Rust's standard library path primitives
//! (`fs::canonicalize`, `Path::new`, `.starts_with`, `.components`, …).
//! Per-language extension slots live alongside those transfer rules; this
//! file defines only the lattice and its laws.

use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};

/// Maximum length (bytes) of a tracked prefix-lock root.  Bounds on-disk
/// summary size for callees that stamp a long canonical root onto every
/// return value.
pub const MAX_PREFIX_LOCK_LEN: usize = 128;

/// Three-value lattice: proven-absent, proven-present, or unknown.
///
/// Ordering (join-semilattice where [`Tri::Maybe`] is Top):
///
/// - `No ⊑ Maybe`, `Yes ⊑ Maybe`
/// - `No` and `Yes` are **incomparable** (both are strict refinements of
///   `Maybe`, but neither subsumes the other).
/// - `join(No, No) = No`, `join(Yes, Yes) = Yes`, otherwise `Maybe`.
/// - `meet(Maybe, x) = x`, `meet(No, No) = No`, `meet(Yes, Yes) = Yes`,
///   `meet(No, Yes)` is contradictory (represented by the enclosing
///   [`PathFact`]'s bottom flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tri {
    /// Proven absent (`..` component not present, path not absolute, etc.).
    No,
    /// Proven present.
    Yes,
    /// Unknown — no transfer or guard has proved the axis yet.
    Maybe,
}

impl Tri {
    pub fn top() -> Self {
        Tri::Maybe
    }

    pub fn is_top(&self) -> bool {
        matches!(self, Tri::Maybe)
    }

    /// Join: least upper bound.  Equal values are preserved; disagreements
    /// widen to [`Tri::Maybe`].
    pub fn join(&self, other: &Self) -> Self {
        match (*self, *other) {
            (a, b) if a == b => a,
            _ => Tri::Maybe,
        }
    }

    /// Meet: greatest lower bound.  `Maybe ⊓ x = x`; disagreement between
    /// `No` and `Yes` is contradictory and returns [`None`].  Callers convert
    /// the resulting [`Option`] into a `PathFact` bottom flag at the product
    /// level.
    pub fn meet_checked(&self, other: &Self) -> Option<Self> {
        match (*self, *other) {
            (Tri::Maybe, x) | (x, Tri::Maybe) => Some(x),
            (a, b) if a == b => Some(a),
            _ => None,
        }
    }

    /// Widen: drop to `Maybe` on any change.
    pub fn widen(&self, other: &Self) -> Self {
        if self == other { *self } else { Tri::Maybe }
    }

    /// Partial order: `self ⊑ other`.
    pub fn leq(&self, other: &Self) -> bool {
        match (*self, *other) {
            (_, Tri::Maybe) => true,
            (a, b) => a == b,
        }
    }
}

/// Path abstract fact.
///
/// Product of three [`Tri`] axes plus an optional canonical-prefix root.
/// The empty (`default()`) fact is Top on every axis: the abstract path
/// could be any filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathFact {
    /// Does the path contain a `..` component?
    pub dotdot: Tri,
    /// Is the path absolute (rooted at `/`, `\`, drive letter)?
    pub absolute: Tri,
    /// Has the path been passed through a canonicalisation / component filter?
    pub normalized: Tri,
    /// Canonical root the path was proved to start with.  `None` = unknown.
    pub prefix_lock: Option<String>,
    /// True when the fact is contradictory (e.g. two irreconcilable meets).
    /// Carried as a flag rather than a sentinel so the primary path stays
    /// allocation-free.
    is_bottom: bool,
}

impl Default for PathFact {
    fn default() -> Self {
        Self::top()
    }
}

impl PathFact {
    /// Top: no knowledge on any axis.
    pub fn top() -> Self {
        Self {
            dotdot: Tri::Maybe,
            absolute: Tri::Maybe,
            normalized: Tri::Maybe,
            prefix_lock: None,
            is_bottom: false,
        }
    }

    /// Bottom: unsatisfiable / empty set.
    pub fn bottom() -> Self {
        Self {
            dotdot: Tri::Maybe,
            absolute: Tri::Maybe,
            normalized: Tri::Maybe,
            prefix_lock: None,
            is_bottom: true,
        }
    }

    pub fn is_top(&self) -> bool {
        !self.is_bottom
            && self.dotdot == Tri::Maybe
            && self.absolute == Tri::Maybe
            && self.normalized == Tri::Maybe
            && self.prefix_lock.is_none()
    }

    pub fn is_bottom(&self) -> bool {
        self.is_bottom
    }

    /// Construct a fact after a sanitisation step that clears `..` components.
    pub fn with_dotdot_cleared(mut self) -> Self {
        self.dotdot = Tri::No;
        self
    }

    /// Construct a fact after a sanitisation step that clears absolute roots.
    pub fn with_absolute_cleared(mut self) -> Self {
        self.absolute = Tri::No;
        self
    }

    /// Construct a fact after a normalisation step (canonicalize / components
    /// filter).  Sets `normalized = Yes` and clears `..`.  Absolute axis is
    /// **not** touched by default: `canonicalize("/etc/passwd")` stays
    /// absolute, the plan's `canonicalize` transfer rule sets
    /// `absolute = Yes` separately.
    pub fn with_normalized(mut self) -> Self {
        self.normalized = Tri::Yes;
        self.dotdot = Tri::No;
        self
    }

    /// Attach a prefix-lock root (the argument of a proven `starts_with`
    /// guard).  Truncates to [`MAX_PREFIX_LOCK_LEN`] on a char boundary so
    /// on-disk summary size stays bounded.
    pub fn with_prefix_lock(mut self, root: &str) -> Self {
        if root.is_empty() {
            return self;
        }
        self.prefix_lock = Some(truncate_prefix_lock(root));
        self
    }

    /// True iff the fact proves both `dotdot = No` and `absolute = No`.
    ///
    /// This is the core sink-suppression predicate: a relative, `..`-free
    /// path can still escape into a parent via a symlink, but it cannot
    /// reach an attacker-controlled absolute location and cannot contain
    /// explicit parent-dir components, which together cover the
    /// documented rs-safe-0** FPs.
    pub fn is_path_safe(&self) -> bool {
        !self.is_bottom && self.dotdot == Tri::No && self.absolute == Tri::No
    }

    /// True iff the fact has a prefix lock equal to or contained under
    /// `root`.  Used by sink-suppression to confirm that a path derived
    /// from a locked root is provably still under that root.
    pub fn prefix_locked_under(&self, root: &str) -> bool {
        match &self.prefix_lock {
            Some(p) => p.starts_with(root) || root.starts_with(p.as_str()),
            None => false,
        }
    }

    // ── Lattice operations ──────────────────────────────────────────────

    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix_lock = match (&self.prefix_lock, &other.prefix_lock) {
            (Some(a), Some(b)) => {
                // Longest common prefix; drop to None when LCP is empty.
                let lcp = longest_common_prefix(a, b);
                if lcp.is_empty() {
                    None
                } else {
                    Some(truncate_prefix_lock(&lcp))
                }
            }
            _ => None,
        };
        Self {
            dotdot: self.dotdot.join(&other.dotdot),
            absolute: self.absolute.join(&other.absolute),
            normalized: self.normalized.join(&other.normalized),
            prefix_lock,
            is_bottom: false,
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom || other.is_bottom {
            return Self::bottom();
        }
        let (dotdot, abs, norm) = match (
            self.dotdot.meet_checked(&other.dotdot),
            self.absolute.meet_checked(&other.absolute),
            self.normalized.meet_checked(&other.normalized),
        ) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return Self::bottom(),
        };
        let prefix_lock = match (&self.prefix_lock, &other.prefix_lock) {
            (Some(a), Some(b)) => {
                // Consistent when one is a prefix of the other; pick the
                // more specific (longer) root.  Otherwise contradictory.
                if a.starts_with(b.as_str()) {
                    Some(a.clone())
                } else if b.starts_with(a.as_str()) {
                    Some(b.clone())
                } else {
                    return Self::bottom();
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        Self {
            dotdot,
            absolute: abs,
            normalized: norm,
            prefix_lock,
            is_bottom: false,
        }
    }

    pub fn widen(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix_lock = if self.prefix_lock == other.prefix_lock {
            self.prefix_lock.clone()
        } else {
            None
        };
        Self {
            dotdot: self.dotdot.widen(&other.dotdot),
            absolute: self.absolute.widen(&other.absolute),
            normalized: self.normalized.widen(&other.normalized),
            prefix_lock,
            is_bottom: false,
        }
    }

    pub fn leq(&self, other: &Self) -> bool {
        if self.is_bottom {
            return true;
        }
        if other.is_bottom {
            return false;
        }
        let prefix_ok = match (&self.prefix_lock, &other.prefix_lock) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.starts_with(b.as_str()),
        };
        prefix_ok
            && self.dotdot.leq(&other.dotdot)
            && self.absolute.leq(&other.absolute)
            && self.normalized.leq(&other.normalized)
    }
}

impl Lattice for PathFact {
    fn bot() -> Self {
        Self::bottom()
    }

    fn join(&self, other: &Self) -> Self {
        self.join(other)
    }

    fn leq(&self, other: &Self) -> bool {
        self.leq(other)
    }
}

impl AbstractDomain for PathFact {
    fn top() -> Self {
        Self::top()
    }

    fn meet(&self, other: &Self) -> Self {
        self.meet(other)
    }

    fn widen(&self, other: &Self) -> Self {
        self.widen(other)
    }
}

// ── Rust path-primitive classifiers ─────────────────────────────────────
//
// Per-language extension slot: each new language that wants to participate in
// PathFact should add its own classifier module and dispatch from
// `src/taint/ssa_transfer/mod.rs` on `transfer.lang`.  Rust is wired here
// because the initial rs-safe-0** closure targets Rust idioms; Python's
// `os.path.normpath`, Java's `Path.normalize`, and Go's `filepath.Clean`
// would slot in alongside.

/// Classification of a branch-condition text against Rust path-rejection
/// idioms.  The *rejection* interpretation is: when the condition is TRUE
/// the enclosing branch rejects (returns, panics, throws); when FALSE the
/// narrowed axis can be proved safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    /// `x.contains("..")` — false branch proves `dotdot = No` on the receiver.
    DotDot,
    /// `x.starts_with("/")` / `x.starts_with('\\')` — false branch proves
    /// `absolute = No` on the receiver.
    AbsoluteSlash,
    /// `x.is_absolute()` / `Path::new(x).is_absolute()` — false branch proves
    /// `absolute = No` on the argument/receiver.
    IsAbsolute,
    /// Not a path-rejection idiom.
    None,
}

/// Classification of a branch-condition text against Rust path *positive*
/// assertion idioms.  When the condition is TRUE on the enclosing branch,
/// the listed axis is refined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAssertion {
    /// `x.starts_with("<literal_root>")` — true branch attaches
    /// `prefix_lock = Some("<literal_root>")` to the receiver.
    PrefixLock(String),
    /// Not a path-assertion idiom.
    None,
}

/// Recognise a Rust path-rejection branch idiom from the raw condition text.
///
/// Accepts both atomic conditions (`x.contains("..")`) and multi-clause
/// disjunctions (`x.contains("..") || x.starts_with('/') || ...`).  For
/// disjunctions the false branch implies **every** clause is false, so the
/// classifier returns the **first** recognised axis; callers should also
/// invoke [`classify_path_rejection_axes`] to pick up every axis covered
/// by an OR-chain.  Conservative: returns [`PathRejection::None`] when no
/// path-rejection clause is found.
pub fn classify_path_rejection(text: &str) -> PathRejection {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return PathRejection::None;
    }
    // Multi-clause OR: return the first recognised axis (callers should
    // use `classify_path_rejection_axes` for the full set).
    let axes = classify_path_rejection_axes(trimmed);
    if axes.is_empty() {
        return PathRejection::None;
    }
    axes[0]
}

/// Recognise every path-rejection axis covered by the condition, handling
/// disjunctions (`a || b || c`) by classifying each clause independently
/// and returning the union of recognised rejections.
///
/// The false branch of the whole condition implies all clauses are false,
/// so every recognised axis narrows on the false branch.
pub fn classify_path_rejection_axes(text: &str) -> smallvec::SmallVec<[PathRejection; 3]> {
    let mut out: smallvec::SmallVec<[PathRejection; 3]> = smallvec::SmallVec::new();
    for clause in split_top_level_or(text) {
        let clause = clause.trim();
        let cls = classify_path_rejection_atom(clause);
        if !matches!(cls, PathRejection::None) && !out.contains(&cls) {
            out.push(cls);
        }
    }
    out
}

fn classify_path_rejection_atom(clause: &str) -> PathRejection {
    if let Some(needle) = extract_contains_arg(clause)
        && needle == ".."
    {
        return PathRejection::DotDot;
    }
    if let Some(needle) = extract_starts_with_arg(clause)
        && (needle == "/" || needle == "\\")
    {
        return PathRejection::AbsoluteSlash;
    }
    if clause.contains(".is_absolute()") {
        return PathRejection::IsAbsolute;
    }
    PathRejection::None
}

/// Split a condition text on top-level `||` operators, ignoring those
/// inside string literals or nested parentheses.
fn split_top_level_or(text: &str) -> smallvec::SmallVec<[&str; 4]> {
    let mut out: smallvec::SmallVec<[&str; 4]> = smallvec::SmallVec::new();
    let bytes = text.as_bytes();
    let mut depth: i32 = 0;
    let mut in_quote: Option<u8> = None;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => {
                in_quote = Some(b);
                i += 1;
                continue;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
                continue;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
                continue;
            }
            b'|' if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b'|' => {
                out.push(&text[last..i]);
                last = i + 2;
                i += 2;
                continue;
            }
            _ => {
                i += 1;
            }
        }
    }
    out.push(&text[last..]);
    out
}

/// Recognise a Rust path-positive-assertion branch idiom.
pub fn classify_path_assertion(text: &str) -> PathAssertion {
    let trimmed = text.trim();
    if let Some(needle) = extract_starts_with_arg(trimmed) {
        // Positive assertion: a literal-prefix `starts_with` on a locked
        // root.  Sibling slash ("/") and backslash ("\\") are also
        // classified as rejections above; prefix-lock only fires when the
        // prefix is multi-character (i.e. carries real locking info).
        if needle.len() >= 2 {
            return PathAssertion::PrefixLock(needle);
        }
    }
    PathAssertion::None
}

/// Recognise a *structural* one-argument enum-variant constructor.
///
/// Returns `true` when `callee` matches Rust's grammar for a variant
/// constructor call: the leaf (last path segment after `::` / `.`)
/// starts with an uppercase ASCII letter, and the callee has no method
/// receiver portion past a single terminal identifier.  Callers combine
/// this with a structural "single-argument call, no receiver" gate; the
/// classification is deliberately name-agnostic and does not hard-code
/// `Some` / `Ok` / `Err` / `Box::new` / …, so user-defined enum variants
/// participate on the same footing as stdlib ones.
///
/// The heuristic is intentionally conservative:
///   * Must be non-empty.
///   * The leaf segment must begin with an ASCII uppercase letter
///     (Rust's variant / struct / type grammar).
///   * The leaf segment must be ASCII alphanumeric / underscore — no
///     method call noise (parentheses, argument lists) survives here
///     because callees arrive in their normalised scoped-identifier
///     form.
///
/// Callers that use this as a PathFact passthrough must still verify
/// the call has exactly one argument (or one argument past a receiver-
/// less structural gate); the leaf check alone does not constrain
/// arity.
pub fn is_structural_variant_ctor(callee: &str) -> bool {
    let trimmed = callee.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Accept either form by inspecting both the leaf and (for scoped
    // callees) the penultimate segment.  A bare identifier whose leaf is
    // upper-camel-case names an enum variant or tuple struct (`Some`,
    // `Ok`, `MyResult`).  A scoped identifier whose *penultimate*
    // segment is upper-camel-case names an associated constructor on
    // that type — `Box::new`, `Cell::from`, `PathBuf::with_capacity`,
    // etc.  The latter is the lower-leaf-case shape we want to admit
    // alongside the bare-variant shape.
    let segments: smallvec::SmallVec<[&str; 4]> =
        trimmed.split("::").filter(|s| !s.is_empty()).collect();
    let is_upper_ident = |s: &str| -> bool {
        match s.chars().next() {
            Some(c) if c.is_ascii_uppercase() => {
                s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }
            _ => false,
        }
    };
    if segments.is_empty() {
        return false;
    }
    if segments.len() == 1 {
        return is_upper_ident(segments[0]);
    }
    // Scoped: accept either upper-camel-case leaf (`Module::Variant`)
    // or upper-camel-case penultimate (`Type::associated_fn`).
    let leaf = segments[segments.len() - 1];
    let parent = segments[segments.len() - 2];
    is_upper_ident(leaf) || is_upper_ident(parent)
}

/// Recognise a Rust path-producing primitive call by canonical callee name,
/// and return its PathFact effect on the result.  `input_fact` is the
/// PathFact of the receiver/first argument (the value being sanitised);
/// it is used as the baseline to which the call's effect is applied.
///
/// Returned [`None`] means the callee is not a recognised path primitive —
/// the caller should leave the result at its pre-existing PathFact (Top).
pub fn classify_path_primitive(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    // Accept both path-qualified (`std::fs::canonicalize`, `fs::canonicalize`)
    // and bare-leaf (`canonicalize`, produced from `p.canonicalize()` method
    // calls after normalisation) forms.
    let leaf = rightmost_segment(callee);
    match leaf {
        // `fs::canonicalize(p)` / `p.canonicalize()`:
        //   normalized = Yes, dotdot = No, absolute = Yes.  The result is
        //   an absolute, fully-resolved path; combined with a prefix-lock
        //   via `.starts_with(root)`, this is the standard Rust
        //   path-containment idiom.
        "canonicalize" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        // `Path::new(s)` / `PathBuf::from(s)`:
        //   pass-through of the input's PathFact so downstream `starts_with`
        //   checks against a Path/PathBuf value still see the underlying
        //   string's narrowed axes.  No axis is forced — wrapping does not
        //   sanitize on its own.
        "new" | "from" => {
            if callee_contains_segment(callee, "Path") || callee_contains_segment(callee, "PathBuf")
            {
                Some(input_fact.clone())
            } else {
                None
            }
        }
        // Identity conversions on strings/paths.  Each one re-binds the
        // same logical value — the converted String / PathBuf / OsString
        // still describes the exact same filesystem path — so the PathFact
        // flows through unchanged.  Without this, a sanitised `s: &str`
        // would lose its narrowed axes the moment the helper returns
        // `s.to_string()` / `s.to_owned()` / `String::from(s)`.
        "to_string" | "to_owned" | "clone" | "into" | "as_ref" | "as_str" | "as_path" => {
            Some(input_fact.clone())
        }
        _ => None,
    }
}

// ── Text helpers (kept in sync with path_state.rs's parsing style) ─────

fn rightmost_segment(s: &str) -> &str {
    let after_colons = s.rsplit("::").next().unwrap_or(s);
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

fn callee_contains_segment(callee: &str, seg: &str) -> bool {
    callee.split([':', '.']).any(|s| s == seg)
}

/// Extract the string argument passed to `receiver.contains("...")`.
fn extract_contains_arg(text: &str) -> Option<String> {
    let method = ".contains(";
    let idx = text.find(method)?;
    extract_first_string_literal(&text[idx + method.len()..])
}

/// Extract the string argument passed to `receiver.starts_with("...")`.
fn extract_starts_with_arg(text: &str) -> Option<String> {
    let method = ".starts_with(";
    let idx = text.find(method)?;
    extract_first_string_literal(&text[idx + method.len()..])
}

/// Parse a `"..."` / `'...'` literal at the start of a slice (after an
/// opening `(`).  Returns the inner text, handling the common Rust escapes
/// `\\`, `\"`, `\'`, `\n`, `\t`.  `None` when the slice does not start
/// with a string literal.
fn extract_first_string_literal(after_open: &str) -> Option<String> {
    let bytes = after_open.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    i += 1;
    let mut out = Vec::new();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                c => out.push(c),
            }
            i += 2;
            continue;
        }
        if b == quote {
            return String::from_utf8(out).ok();
        }
        out.push(b);
        i += 1;
    }
    None
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn truncate_prefix_lock(s: &str) -> String {
    if s.len() <= MAX_PREFIX_LOCK_LEN {
        s.to_string()
    } else {
        let mut end = MAX_PREFIX_LOCK_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

fn longest_common_prefix(a: &str, b: &str) -> String {
    a.bytes()
        .zip(b.bytes())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tri lattice laws ────────────────────────────────────────────────

    #[test]
    fn tri_join_idempotent() {
        for v in [Tri::No, Tri::Yes, Tri::Maybe] {
            assert_eq!(v.join(&v), v);
        }
    }

    #[test]
    fn tri_join_commutative() {
        let pairs = [
            (Tri::No, Tri::Yes),
            (Tri::No, Tri::Maybe),
            (Tri::Yes, Tri::Maybe),
        ];
        for (a, b) in pairs {
            assert_eq!(a.join(&b), b.join(&a));
        }
    }

    #[test]
    fn tri_join_disagreement_is_top() {
        assert_eq!(Tri::No.join(&Tri::Yes), Tri::Maybe);
    }

    #[test]
    fn tri_join_with_top_is_top() {
        assert_eq!(Tri::No.join(&Tri::Maybe), Tri::Maybe);
        assert_eq!(Tri::Yes.join(&Tri::Maybe), Tri::Maybe);
    }

    #[test]
    fn tri_meet_top_is_identity() {
        assert_eq!(Tri::No.meet_checked(&Tri::Maybe), Some(Tri::No));
        assert_eq!(Tri::Maybe.meet_checked(&Tri::Yes), Some(Tri::Yes));
    }

    #[test]
    fn tri_meet_contradiction_is_none() {
        assert_eq!(Tri::No.meet_checked(&Tri::Yes), None);
        assert_eq!(Tri::Yes.meet_checked(&Tri::No), None);
    }

    #[test]
    fn tri_meet_agree() {
        assert_eq!(Tri::No.meet_checked(&Tri::No), Some(Tri::No));
        assert_eq!(Tri::Yes.meet_checked(&Tri::Yes), Some(Tri::Yes));
    }

    #[test]
    fn tri_widen_drops_on_change() {
        assert_eq!(Tri::No.widen(&Tri::Yes), Tri::Maybe);
        assert_eq!(Tri::No.widen(&Tri::No), Tri::No);
    }

    #[test]
    fn tri_leq_top_greatest() {
        assert!(Tri::No.leq(&Tri::Maybe));
        assert!(Tri::Yes.leq(&Tri::Maybe));
        assert!(!Tri::Maybe.leq(&Tri::No));
    }

    // ── PathFact basics ─────────────────────────────────────────────────

    #[test]
    fn default_is_top() {
        let f = PathFact::default();
        assert!(f.is_top());
        assert!(!f.is_bottom());
        assert!(!f.is_path_safe());
    }

    #[test]
    fn bottom_detection() {
        let b = PathFact::bottom();
        assert!(b.is_bottom());
        assert!(!b.is_top());
        assert!(!b.is_path_safe());
    }

    #[test]
    fn is_path_safe_requires_both_axes() {
        let mut f = PathFact::default().with_dotdot_cleared();
        assert!(!f.is_path_safe(), "dotdot=No alone is insufficient");
        f = f.with_absolute_cleared();
        assert!(f.is_path_safe());
    }

    #[test]
    fn is_path_safe_truth_table() {
        let cases = [
            (Tri::No, Tri::No, true),
            (Tri::No, Tri::Yes, false),
            (Tri::No, Tri::Maybe, false),
            (Tri::Yes, Tri::No, false),
            (Tri::Maybe, Tri::No, false),
            (Tri::Maybe, Tri::Maybe, false),
        ];
        for (dd, abs, expected) in cases {
            let f = PathFact {
                dotdot: dd,
                absolute: abs,
                normalized: Tri::Maybe,
                prefix_lock: None,
                is_bottom: false,
            };
            assert_eq!(
                f.is_path_safe(),
                expected,
                "is_path_safe({:?}, {:?}) should be {expected}",
                dd,
                abs
            );
        }
    }

    #[test]
    fn with_normalized_clears_dotdot() {
        let f = PathFact::default().with_normalized();
        assert_eq!(f.dotdot, Tri::No);
        assert_eq!(f.normalized, Tri::Yes);
        assert_eq!(f.absolute, Tri::Maybe);
    }

    #[test]
    fn with_prefix_lock_ignores_empty() {
        let f = PathFact::default().with_prefix_lock("");
        assert!(f.prefix_lock.is_none());
    }

    #[test]
    fn with_prefix_lock_truncates() {
        let huge = "/".to_string() + &"a".repeat(MAX_PREFIX_LOCK_LEN * 2);
        let f = PathFact::default().with_prefix_lock(&huge);
        assert!(
            f.prefix_lock.as_deref().unwrap().len() <= MAX_PREFIX_LOCK_LEN,
            "prefix_lock must be bounded"
        );
    }

    #[test]
    fn prefix_locked_under_works() {
        let f = PathFact::default().with_prefix_lock("/var/app/uploads/");
        assert!(f.prefix_locked_under("/var/app/"));
        assert!(f.prefix_locked_under("/var/app/uploads/"));
        assert!(!f.prefix_locked_under("/etc/"));
        assert!(!PathFact::default().prefix_locked_under("/var/app/"));
    }

    // ── Lattice laws ────────────────────────────────────────────────────

    #[test]
    fn join_idempotent() {
        let f = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert_eq!(f.join(&f), f);
    }

    #[test]
    fn join_commutative() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default().with_absolute_cleared();
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_associative() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default().with_absolute_cleared();
        let c = PathFact::default().with_normalized();
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn join_with_bottom_identity() {
        let a = PathFact::default().with_dotdot_cleared();
        assert_eq!(a.join(&PathFact::bottom()), a);
        assert_eq!(PathFact::bottom().join(&a), a);
    }

    #[test]
    fn join_disagreement_yields_maybe() {
        let a = PathFact::default().with_dotdot_cleared(); // dotdot=No
        let b = PathFact {
            dotdot: Tri::Yes,
            ..Default::default()
        };
        let j = a.join(&b);
        assert_eq!(j.dotdot, Tri::Maybe);
    }

    #[test]
    fn join_prefix_locks_lcp() {
        let a = PathFact::default().with_prefix_lock("/var/app/uploads/");
        let b = PathFact::default().with_prefix_lock("/var/app/static/");
        let j = a.join(&b);
        assert_eq!(j.prefix_lock.as_deref(), Some("/var/app/"));
    }

    #[test]
    fn join_prefix_locks_disjoint_drops() {
        let a = PathFact::default().with_prefix_lock("/var/app/");
        let b = PathFact::default().with_prefix_lock("/etc/");
        let j = a.join(&b);
        // LCP of "/var/app/" and "/etc/" is "/"; still a non-empty lock.
        assert_eq!(j.prefix_lock.as_deref(), Some("/"));
        let c = PathFact::default().with_prefix_lock("home/");
        let d = PathFact::default().with_prefix_lock("etc/");
        assert!(c.join(&d).prefix_lock.is_none());
    }

    #[test]
    fn meet_top_is_identity() {
        let a = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert_eq!(a.meet(&PathFact::top()), a);
        assert_eq!(PathFact::top().meet(&a), a);
    }

    #[test]
    fn meet_refines() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default().with_absolute_cleared();
        let m = a.meet(&b);
        assert_eq!(m.dotdot, Tri::No);
        assert_eq!(m.absolute, Tri::No);
        assert!(m.is_path_safe());
    }

    #[test]
    fn meet_contradiction_is_bottom() {
        let a = PathFact::default().with_dotdot_cleared(); // dotdot=No
        let b = PathFact {
            dotdot: Tri::Yes,
            ..Default::default()
        };
        assert!(a.meet(&b).is_bottom());
    }

    #[test]
    fn meet_prefix_locks_picks_longer() {
        let a = PathFact::default().with_prefix_lock("/var/app/");
        let b = PathFact::default().with_prefix_lock("/var/app/uploads/");
        let m = a.meet(&b);
        assert_eq!(m.prefix_lock.as_deref(), Some("/var/app/uploads/"));
    }

    #[test]
    fn meet_prefix_locks_disjoint_is_bottom() {
        let a = PathFact::default().with_prefix_lock("/var/app/");
        let b = PathFact::default().with_prefix_lock("/etc/");
        assert!(a.meet(&b).is_bottom());
    }

    // ── Widening ────────────────────────────────────────────────────────

    #[test]
    fn widen_stable() {
        let a = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert_eq!(a.widen(&a), a);
    }

    #[test]
    fn widen_drops_on_change() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact {
            dotdot: Tri::Yes,
            ..Default::default()
        };
        let w = a.widen(&b);
        assert_eq!(w.dotdot, Tri::Maybe);
    }

    #[test]
    fn widen_chain_terminates() {
        // Finite-ascent guarantee: any sequence of widens must stabilise
        // within a small fixed number of steps (each axis has height 2).
        let mut cur = PathFact::default().with_dotdot_cleared();
        let target = PathFact {
            dotdot: Tri::Yes,
            absolute: Tri::Yes,
            normalized: Tri::Yes,
            prefix_lock: None,
            is_bottom: false,
        };
        for _ in 0..8 {
            cur = cur.widen(&target);
        }
        // After widening with a disagreeing target, we drop to Top on that axis.
        assert_eq!(cur.dotdot, Tri::Maybe);
        assert_eq!(cur, cur.widen(&target), "must have stabilised");
    }

    #[test]
    fn widen_prefix_drops_on_change() {
        let a = PathFact::default().with_prefix_lock("/var/app/v1/");
        let b = PathFact::default().with_prefix_lock("/var/app/v2/");
        assert!(a.widen(&b).prefix_lock.is_none());
    }

    // ── Leq ─────────────────────────────────────────────────────────────

    #[test]
    fn leq_top_greatest() {
        let a = PathFact::default().with_dotdot_cleared();
        assert!(a.leq(&PathFact::top()));
        assert!(!PathFact::top().leq(&a));
    }

    #[test]
    fn leq_bottom_least() {
        assert!(PathFact::bottom().leq(&PathFact::default()));
        assert!(!PathFact::default().leq(&PathFact::bottom()));
    }

    #[test]
    fn leq_refinement() {
        let refined = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        let coarse = PathFact::default().with_dotdot_cleared();
        assert!(refined.leq(&coarse));
        assert!(!coarse.leq(&refined));
    }

    // ── Rust classifier tests ───────────────────────────────────────────

    #[test]
    fn rejection_contains_dotdot() {
        assert_eq!(
            classify_path_rejection("user.contains(\"..\")"),
            PathRejection::DotDot
        );
    }

    #[test]
    fn rejection_axes_disjunction_covers_all_clauses() {
        let axes = classify_path_rejection_axes(
            "s.contains(\"..\") || s.starts_with('/') || s.starts_with('\\\\')",
        );
        assert!(
            axes.contains(&PathRejection::DotDot),
            "expected DotDot in {axes:?}"
        );
        assert!(
            axes.contains(&PathRejection::AbsoluteSlash),
            "expected AbsoluteSlash in {axes:?}"
        );
    }

    #[test]
    fn rejection_axes_deduplicates() {
        let axes = classify_path_rejection_axes("a.starts_with('/') || b.starts_with(\"\\\\\")");
        // Two absolute-slash clauses collapse to a single axis.
        assert_eq!(
            axes.iter()
                .filter(|a| matches!(a, PathRejection::AbsoluteSlash))
                .count(),
            1
        );
    }

    #[test]
    fn rejection_contains_other_needle_is_none() {
        assert_eq!(
            classify_path_rejection("name.contains(\";\")"),
            PathRejection::None
        );
    }

    #[test]
    fn rejection_starts_with_slash() {
        assert_eq!(
            classify_path_rejection("p.starts_with('/')"),
            PathRejection::AbsoluteSlash
        );
        assert_eq!(
            classify_path_rejection("p.starts_with(\"/\")"),
            PathRejection::AbsoluteSlash
        );
    }

    #[test]
    fn rejection_starts_with_backslash() {
        assert_eq!(
            classify_path_rejection("p.starts_with(\"\\\\\")"),
            PathRejection::AbsoluteSlash
        );
    }

    #[test]
    fn rejection_is_absolute() {
        assert_eq!(
            classify_path_rejection("Path::new(s).is_absolute()"),
            PathRejection::IsAbsolute
        );
        assert_eq!(
            classify_path_rejection("p.is_absolute()"),
            PathRejection::IsAbsolute
        );
    }

    #[test]
    fn assertion_prefix_lock() {
        match classify_path_assertion("p.starts_with(\"/var/app/\")") {
            PathAssertion::PrefixLock(r) => assert_eq!(r, "/var/app/"),
            other => panic!("expected PrefixLock, got {other:?}"),
        }
    }

    #[test]
    fn assertion_single_char_not_lock() {
        assert_eq!(
            classify_path_assertion("p.starts_with('/')"),
            PathAssertion::None
        );
    }

    #[test]
    fn primitive_canonicalize_normalises() {
        let f = classify_path_primitive("fs::canonicalize", &PathFact::top()).unwrap();
        assert_eq!(f.dotdot, Tri::No);
        assert_eq!(f.normalized, Tri::Yes);
        assert_eq!(f.absolute, Tri::Yes);
    }

    #[test]
    fn primitive_method_canonicalize_normalises() {
        let f = classify_path_primitive("canonicalize", &PathFact::top()).unwrap();
        assert_eq!(f.normalized, Tri::Yes);
    }

    #[test]
    fn primitive_path_new_passthrough() {
        let input = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        let f = classify_path_primitive("Path::new", &input).unwrap();
        assert_eq!(f, input, "Path::new passes PathFact through unchanged");
    }

    #[test]
    fn primitive_pathbuf_from_passthrough() {
        let input = PathFact::default().with_dotdot_cleared();
        let f = classify_path_primitive("PathBuf::from", &input).unwrap();
        assert_eq!(f, input);
    }

    #[test]
    fn primitive_unknown_returns_none() {
        assert!(classify_path_primitive("unknown_fn", &PathFact::top()).is_none());
        assert!(classify_path_primitive("vec::new", &PathFact::top()).is_none());
    }

    // ── Structural variant-ctor classifier ─────────────────────────────

    #[test]
    fn variant_ctor_recognises_upper_camel_leaf() {
        assert!(is_structural_variant_ctor("Some"));
        assert!(is_structural_variant_ctor("Ok"));
        assert!(is_structural_variant_ctor("Err"));
        assert!(is_structural_variant_ctor("Box::new"));
        assert!(is_structural_variant_ctor("std::option::Option::Some"));
        // User-defined upper-camel-case variant name participates the
        // same way — name list is not part of the contract.
        assert!(is_structural_variant_ctor("MyResult::Ok"));
        assert!(is_structural_variant_ctor("Wrapper"));
    }

    #[test]
    fn variant_ctor_rejects_lowercase_leaf() {
        assert!(!is_structural_variant_ctor("foo"));
        assert!(!is_structural_variant_ctor("bar::baz"));
        assert!(!is_structural_variant_ctor("std::env::var"));
        assert!(!is_structural_variant_ctor("to_string"));
    }

    #[test]
    fn variant_ctor_rejects_empty_or_garbled() {
        assert!(!is_structural_variant_ctor(""));
        assert!(!is_structural_variant_ctor("::"));
        assert!(!is_structural_variant_ctor("123"));
    }

    // ── PathFactReturnEntry merge / dedup ───────────────────────────────

    #[test]
    fn merge_path_fact_dedups_by_predicate_hash() {
        use crate::summary::ssa_summary::{PathFactReturnEntry, merge_path_fact_return_paths};
        use smallvec::SmallVec;
        let mut acc: SmallVec<[PathFactReturnEntry; 2]> = SmallVec::new();
        let f1 = PathFact::top().with_dotdot_cleared();
        let f2 = PathFact::top().with_absolute_cleared();
        merge_path_fact_return_paths(
            &mut acc,
            &[PathFactReturnEntry {
                predicate_hash: 42,
                known_true: 0,
                known_false: 0,
                path_fact: f1.clone(),
                variant_inner_fact: None,
            }],
        );
        merge_path_fact_return_paths(
            &mut acc,
            &[PathFactReturnEntry {
                predicate_hash: 42,
                known_true: 0,
                known_false: 0,
                path_fact: f2.clone(),
                variant_inner_fact: None,
            }],
        );
        assert_eq!(acc.len(), 1, "same predicate hash collapses to one entry");
        let joined = f1.join(&f2);
        assert_eq!(
            acc[0].path_fact, joined,
            "facts join on predicate-hash collision"
        );
    }

    #[test]
    fn merge_path_fact_distinct_hashes_kept_separate() {
        use crate::summary::ssa_summary::{PathFactReturnEntry, merge_path_fact_return_paths};
        use smallvec::SmallVec;
        let mut acc: SmallVec<[PathFactReturnEntry; 2]> = SmallVec::new();
        merge_path_fact_return_paths(
            &mut acc,
            &[
                PathFactReturnEntry {
                    predicate_hash: 1,
                    known_true: 0,
                    known_false: 0,
                    path_fact: PathFact::top().with_dotdot_cleared(),
                    variant_inner_fact: None,
                },
                PathFactReturnEntry {
                    predicate_hash: 2,
                    known_true: 0,
                    known_false: 0,
                    path_fact: PathFact::top(),
                    variant_inner_fact: Some(PathFact::top().with_absolute_cleared()),
                },
            ],
        );
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn merge_path_fact_overflow_caps_at_bound() {
        use crate::summary::ssa_summary::{
            MAX_PATH_FACT_RETURN_ENTRIES, PathFactReturnEntry, merge_path_fact_return_paths,
        };
        use smallvec::SmallVec;
        let mut acc: SmallVec<[PathFactReturnEntry; 2]> = SmallVec::new();
        // Push twice as many distinct predicate hashes as the cap so
        // overflow collapse fires repeatedly.  Each collapse compacts
        // the accumulator back to a single Top-predicate entry; the
        // next insert lands fresh on top.  The invariant we care
        // about is bounded growth: the final length must not exceed
        // `MAX_PATH_FACT_RETURN_ENTRIES`.
        for i in 0..(MAX_PATH_FACT_RETURN_ENTRIES * 2) {
            merge_path_fact_return_paths(
                &mut acc,
                &[PathFactReturnEntry {
                    predicate_hash: i as u64 + 100,
                    known_true: 0,
                    known_false: 0,
                    path_fact: PathFact::top().with_dotdot_cleared(),
                    variant_inner_fact: None,
                }],
            );
        }
        assert!(
            acc.len() <= MAX_PATH_FACT_RETURN_ENTRIES,
            "overflow growth stays bounded: got {}",
            acc.len()
        );
        // Whichever of the post-collapse entries survives, at least
        // one carries the unguarded (predicate_hash == 0) collapse
        // sentinel from a previous overflow.
        assert!(
            acc.iter().any(|e| e.predicate_hash == 0),
            "collapse sentinel must persist"
        );
    }

    #[test]
    fn leq_consistent_with_join() {
        // a ⊑ b iff join(a, b) == b (within the domain's join-semilattice).
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        // b ⊑ a because b is strictly more informative.
        assert!(b.leq(&a));
        assert_eq!(b.join(&a), a);
    }
}
