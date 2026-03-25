//! String abstract domain for abstract interpretation.
//!
//! Tracks known prefix and suffix of string values. Used for SSRF suppression
//! (URL prefix proves host is locked) and general string analysis.

use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};

/// Maximum tracked prefix length (bytes).
pub const MAX_PREFIX_LEN: usize = 256;
/// Maximum tracked suffix length (bytes).
pub const MAX_SUFFIX_LEN: usize = 128;

/// String abstract domain: tracks known prefix and suffix.
///
/// Lattice ordering:
/// - `Bottom` ⊑ everything (unsatisfiable)
/// - Concrete facts ⊑ `Top` (no knowledge)
/// - `Some(prefix)` ⊑ `None` (no prefix known)
///
/// Prefix and suffix are independent: a value can have both, either, or neither.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringFact {
    /// Known prefix of the string. `None` = unknown.
    pub prefix: Option<String>,
    /// Known suffix of the string. `None` = unknown.
    pub suffix: Option<String>,
    /// True when this fact is Bottom (unsatisfiable).
    is_bottom: bool,
}

impl StringFact {
    /// Top: no knowledge about the string.
    pub fn top() -> Self {
        Self {
            prefix: None,
            suffix: None,
            is_bottom: false,
        }
    }

    /// Bottom: unsatisfiable / empty set.
    pub fn bottom() -> Self {
        Self {
            prefix: None,
            suffix: None,
            is_bottom: true,
        }
    }

    /// Exact known string value: both prefix and suffix are the full string.
    pub fn exact(s: &str) -> Self {
        let prefix = truncate_prefix(s);
        let suffix = truncate_suffix(s);
        Self {
            prefix: Some(prefix),
            suffix: Some(suffix),
            is_bottom: false,
        }
    }

    /// Known prefix only.
    pub fn from_prefix(p: &str) -> Self {
        Self {
            prefix: Some(truncate_prefix(p)),
            suffix: None,
            is_bottom: false,
        }
    }

    /// Known suffix only.
    pub fn from_suffix(s: &str) -> Self {
        Self {
            prefix: None,
            suffix: Some(truncate_suffix(s)),
            is_bottom: false,
        }
    }

    pub fn is_top(&self) -> bool {
        !self.is_bottom && self.prefix.is_none() && self.suffix.is_none()
    }

    pub fn is_bottom(&self) -> bool {
        self.is_bottom
    }

    // ── Lattice operations ──────────────────────────────────────────────

    /// Join: longest common prefix (LCP) and longest common suffix (LCS).
    /// Preserves only the part that is common to both paths.
    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix = match (&self.prefix, &other.prefix) {
            (Some(a), Some(b)) => {
                let lcp = longest_common_prefix(a, b);
                if lcp.is_empty() { None } else { Some(lcp) }
            }
            _ => None,
        };
        let suffix = match (&self.suffix, &other.suffix) {
            (Some(a), Some(b)) => {
                let lcs = longest_common_suffix(a, b);
                if lcs.is_empty() { None } else { Some(lcs) }
            }
            _ => None,
        };
        Self {
            prefix,
            suffix,
            is_bottom: false,
        }
    }

    /// Meet: take the longer (more specific) prefix/suffix if consistent.
    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom || other.is_bottom {
            return Self::bottom();
        }
        let prefix = match (&self.prefix, &other.prefix) {
            (Some(a), Some(b)) => {
                if a.starts_with(b.as_str()) {
                    Some(a.clone()) // a is more specific
                } else if b.starts_with(a.as_str()) {
                    Some(b.clone()) // b is more specific
                } else {
                    return Self::bottom(); // contradictory prefixes
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        let suffix = match (&self.suffix, &other.suffix) {
            (Some(a), Some(b)) => {
                if a.ends_with(b.as_str()) {
                    Some(a.clone())
                } else if b.ends_with(a.as_str()) {
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
            prefix,
            suffix,
            is_bottom: false,
        }
    }

    /// Widen: drop prefix/suffix that changed between iterations.
    pub fn widen(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix = if self.prefix == other.prefix {
            self.prefix.clone()
        } else {
            None
        };
        let suffix = if self.suffix == other.suffix {
            self.suffix.clone()
        } else {
            None
        };
        Self {
            prefix,
            suffix,
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
        // self ⊑ other iff other has weaker (shorter or None) constraints
        let prefix_ok = match (&self.prefix, &other.prefix) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.starts_with(b.as_str()),
        };
        let suffix_ok = match (&self.suffix, &other.suffix) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.ends_with(b.as_str()),
        };
        prefix_ok && suffix_ok
    }

    // ── Transfer functions ──────────────────────────────────────────────

    /// String concatenation: `self ++ other`.
    ///
    /// - Prefix of result = prefix of `self` (left operand)
    /// - Suffix of result = suffix of `other` (right operand)
    pub fn concat(&self, other: &Self) -> Self {
        if self.is_bottom || other.is_bottom {
            return Self::bottom();
        }
        Self {
            prefix: self.prefix.clone(),
            suffix: other.suffix.clone(),
            is_bottom: false,
        }
    }
}

impl Lattice for StringFact {
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

impl AbstractDomain for StringFact {
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

// ── Helpers ─────────────────────────────────────────────────────────────

fn truncate_prefix(s: &str) -> String {
    if s.len() <= MAX_PREFIX_LEN {
        s.to_string()
    } else {
        // Find a char boundary at or before MAX_PREFIX_LEN
        let mut end = MAX_PREFIX_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

fn truncate_suffix(s: &str) -> String {
    if s.len() <= MAX_SUFFIX_LEN {
        s.to_string()
    } else {
        let start = s.len() - MAX_SUFFIX_LEN;
        let mut start = start;
        while start < s.len() && !s.is_char_boundary(start) {
            start += 1;
        }
        s[start..].to_string()
    }
}

/// Longest common prefix of two strings.
pub fn longest_common_prefix(a: &str, b: &str) -> String {
    a.bytes()
        .zip(b.bytes())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x as char)
        .collect()
}

/// Longest common suffix of two strings.
pub fn longest_common_suffix(a: &str, b: &str) -> String {
    let lcs: String = a
        .bytes()
        .rev()
        .zip(b.bytes().rev())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x as char)
        .collect();
    lcs.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_and_bottom() {
        assert!(StringFact::top().is_top());
        assert!(!StringFact::top().is_bottom());
        assert!(StringFact::bottom().is_bottom());
        assert!(!StringFact::bottom().is_top());
    }

    #[test]
    fn exact_sets_both() {
        let f = StringFact::exact("hello");
        assert_eq!(f.prefix.as_deref(), Some("hello"));
        assert_eq!(f.suffix.as_deref(), Some("hello"));
    }

    // ── LCP / LCS helpers ───────────────────────────────────────────

    #[test]
    fn lcp_basic() {
        assert_eq!(longest_common_prefix("abcdef", "abcxyz"), "abc");
        assert_eq!(longest_common_prefix("abc", "abc"), "abc");
        assert_eq!(longest_common_prefix("abc", "xyz"), "");
        assert_eq!(longest_common_prefix("", "abc"), "");
    }

    #[test]
    fn lcs_basic() {
        assert_eq!(longest_common_suffix("hello.json", "world.json"), ".json");
        assert_eq!(longest_common_suffix("abc", "xyz"), "");
        assert_eq!(longest_common_suffix("abc", "abc"), "abc");
    }

    // ── Join ────────────────────────────────────────────────────────

    #[test]
    fn join_same_prefix() {
        let a = StringFact::from_prefix("https://api.com/users/");
        let b = StringFact::from_prefix("https://api.com/items/");
        let j = a.join(&b);
        assert_eq!(j.prefix.as_deref(), Some("https://api.com/"));
    }

    #[test]
    fn join_no_common_prefix() {
        let a = StringFact::from_prefix("https://a.com/");
        let b = StringFact::from_prefix("http://b.com/");
        let j = a.join(&b);
        assert_eq!(j.prefix.as_deref(), Some("http")); // common: "http"
    }

    #[test]
    fn join_suffix() {
        let a = StringFact::from_suffix(".json");
        let b = StringFact::from_suffix(".json");
        assert_eq!(a.join(&b).suffix.as_deref(), Some(".json"));
    }

    #[test]
    fn join_different_suffix() {
        let a = StringFact::from_suffix(".json");
        let b = StringFact::from_suffix(".xml");
        assert_eq!(a.join(&b).suffix, None);
    }

    #[test]
    fn join_with_bottom() {
        let a = StringFact::from_prefix("hello");
        assert_eq!(a.join(&StringFact::bottom()), a);
        assert_eq!(StringFact::bottom().join(&a), a);
    }

    // ── Meet ────────────────────────────────────────────────────────

    #[test]
    fn meet_consistent_prefix() {
        let a = StringFact::from_prefix("https://");
        let b = StringFact::from_prefix("https://api.com/");
        let m = a.meet(&b);
        assert_eq!(m.prefix.as_deref(), Some("https://api.com/"));
    }

    #[test]
    fn meet_contradictory_prefix() {
        let a = StringFact::from_prefix("https://a.com/");
        let b = StringFact::from_prefix("https://b.com/");
        assert!(a.meet(&b).is_bottom());
    }

    // ── Widen ───────────────────────────────────────────────────────

    #[test]
    fn widen_stable() {
        let a = StringFact::from_prefix("https://api.com/");
        assert_eq!(a.widen(&a), a);
    }

    #[test]
    fn widen_changed_prefix() {
        let old = StringFact::from_prefix("https://api.com/v1/");
        let new = StringFact::from_prefix("https://api.com/v2/");
        let w = old.widen(&new);
        assert_eq!(w.prefix, None); // changed → dropped
    }

    // ── Concat ──────────────────────────────────────────────────────

    #[test]
    fn concat_exact() {
        let a = StringFact::exact("hello");
        let b = StringFact::exact(" world");
        let c = a.concat(&b);
        assert_eq!(c.prefix.as_deref(), Some("hello"));
        assert_eq!(c.suffix.as_deref(), Some(" world"));
    }

    #[test]
    fn concat_prefix_with_top() {
        let a = StringFact::from_prefix("https://api.com/");
        let b = StringFact::top();
        let c = a.concat(&b);
        assert_eq!(c.prefix.as_deref(), Some("https://api.com/"));
        assert_eq!(c.suffix, None);
    }

    #[test]
    fn concat_top_with_suffix() {
        let a = StringFact::top();
        let b = StringFact::from_suffix(".json");
        let c = a.concat(&b);
        assert_eq!(c.prefix, None);
        assert_eq!(c.suffix.as_deref(), Some(".json"));
    }

    // ── Leq ─────────────────────────────────────────────────────────

    #[test]
    fn leq_more_specific_prefix() {
        let specific = StringFact::from_prefix("https://api.com/users/");
        let general = StringFact::from_prefix("https://api.com/");
        assert!(specific.leq(&general));
        assert!(!general.leq(&specific));
    }

    #[test]
    fn leq_top_greatest() {
        let a = StringFact::from_prefix("hello");
        assert!(a.leq(&StringFact::top()));
        assert!(!StringFact::top().leq(&a));
    }

    #[test]
    fn leq_bottom_least() {
        assert!(StringFact::bottom().leq(&StringFact::top()));
        assert!(StringFact::bottom().leq(&StringFact::from_prefix("x")));
    }
}
