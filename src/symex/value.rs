//! Symbolic value expression trees for Phase 18a.

use std::fmt;

use crate::cfg;
use crate::ssa::ir::{BlockId, SsaValue};

/// Maximum expression tree depth before collapsing to `Unknown`.
pub const MAX_EXPR_DEPTH: u32 = 32;

/// Arithmetic operator for symbolic expressions.
///
/// Local to the symex module; converted from `cfg::BinOp` via `From`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl From<cfg::BinOp> for Op {
    fn from(b: cfg::BinOp) -> Self {
        match b {
            cfg::BinOp::Add => Op::Add,
            cfg::BinOp::Sub => Op::Sub,
            cfg::BinOp::Mul => Op::Mul,
            cfg::BinOp::Div => Op::Div,
            cfg::BinOp::Mod => Op::Mod,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Add => write!(f, "+"),
            Op::Sub => write!(f, "-"),
            Op::Mul => write!(f, "*"),
            Op::Div => write!(f, "/"),
            Op::Mod => write!(f, "%"),
        }
    }
}

/// A symbolic expression tree representing how a value is computed.
///
/// Expression trees are depth-bounded by [`MAX_EXPR_DEPTH`]; all construction
/// goes through smart constructors ([`mk_binop`], [`mk_concat`], [`mk_call`],
/// [`mk_phi`]) that enforce this limit.
#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicValue {
    /// Known integer constant.
    Concrete(i64),
    /// Known string constant (quotes already stripped).
    ConcreteStr(String),
    /// Unconstrained symbolic input tied to an SSA value.
    Symbol(SsaValue),
    /// Arithmetic binary operation.
    BinOp(Op, Box<SymbolicValue>, Box<SymbolicValue>),
    /// String concatenation.
    Concat(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Uninterpreted function application.
    Call(String, Vec<SymbolicValue>),
    /// Phi merge (stored structurally; not resolved in Phase 18a single-path).
    Phi(Vec<(BlockId, SymbolicValue)>),
    /// No information (top).
    Unknown,
}

impl SymbolicValue {
    /// Compute the depth of this expression tree.
    ///
    /// Leaf nodes (`Concrete`, `ConcreteStr`, `Symbol`, `Unknown`) have depth 0.
    /// Compound nodes have depth 1 + max(children).
    pub fn depth(&self) -> u32 {
        match self {
            SymbolicValue::Concrete(_)
            | SymbolicValue::ConcreteStr(_)
            | SymbolicValue::Symbol(_)
            | SymbolicValue::Unknown => 0,
            SymbolicValue::BinOp(_, l, r) | SymbolicValue::Concat(l, r) => {
                1 + l.depth().max(r.depth())
            }
            SymbolicValue::Call(_, args) => {
                1 + args.iter().map(|a| a.depth()).max().unwrap_or(0)
            }
            SymbolicValue::Phi(operands) => {
                1 + operands.iter().map(|(_, v)| v.depth()).max().unwrap_or(0)
            }
        }
    }

    /// Returns `true` if this is a known concrete value (int or string).
    pub fn is_concrete(&self) -> bool {
        matches!(self, SymbolicValue::Concrete(_) | SymbolicValue::ConcreteStr(_))
    }

    /// Extract a concrete integer if this is `Concrete(n)`.
    pub fn as_concrete_int(&self) -> Option<i64> {
        match self {
            SymbolicValue::Concrete(n) => Some(*n),
            _ => None,
        }
    }

    /// Extract a concrete string reference if this is `ConcreteStr(s)`.
    pub fn as_concrete_str(&self) -> Option<&str> {
        match self {
            SymbolicValue::ConcreteStr(s) => Some(s),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Smart constructors — all tree-building goes through these
// ─────────────────────────────────────────────────────────────────────────────

/// Build a binary arithmetic expression with concrete folding and depth bounding.
///
/// - If both operands are `Concrete`, folds via `checked_*` arithmetic.
///   Overflow or division by zero produces `Unknown`.
/// - If the resulting tree exceeds `MAX_EXPR_DEPTH`, returns `Unknown`.
pub fn mk_binop(op: Op, lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    // Concrete folding
    if let (SymbolicValue::Concrete(a), SymbolicValue::Concrete(b)) = (&lhs, &rhs) {
        let result = match op {
            Op::Add => a.checked_add(*b),
            Op::Sub => a.checked_sub(*b),
            Op::Mul => a.checked_mul(*b),
            Op::Div => {
                if *b == 0 {
                    None
                } else {
                    a.checked_div(*b)
                }
            }
            Op::Mod => {
                if *b == 0 {
                    None
                } else {
                    a.checked_rem(*b)
                }
            }
        };
        return match result {
            Some(n) => SymbolicValue::Concrete(n),
            None => SymbolicValue::Unknown,
        };
    }

    // Depth check
    let depth = 1 + lhs.depth().max(rhs.depth());
    if depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::BinOp(op, Box::new(lhs), Box::new(rhs))
}

/// Build a string concatenation expression with concrete folding and depth bounding.
///
/// - If both operands are `ConcreteStr`, folds to a single `ConcreteStr`.
/// - If the resulting tree exceeds `MAX_EXPR_DEPTH`, returns `Unknown`.
pub fn mk_concat(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    // Concrete folding: ConcreteStr + ConcreteStr
    if let (SymbolicValue::ConcreteStr(a), SymbolicValue::ConcreteStr(b)) = (&lhs, &rhs) {
        return SymbolicValue::ConcreteStr(format!("{}{}", a, b));
    }

    // Depth check
    let depth = 1 + lhs.depth().max(rhs.depth());
    if depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::Concat(Box::new(lhs), Box::new(rhs))
}

/// Build an uninterpreted function call expression with depth bounding.
pub fn mk_call(name: String, args: Vec<SymbolicValue>) -> SymbolicValue {
    let max_arg_depth = args.iter().map(|a| a.depth()).max().unwrap_or(0);
    if 1 + max_arg_depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::Call(name, args)
}

/// Build a phi merge expression with simplification and depth bounding.
///
/// - Single operand: unwrap to the operand value.
/// - All operands identical: fold to one value.
/// - Otherwise: build `Phi(...)` with depth check.
pub fn mk_phi(operands: Vec<(BlockId, SymbolicValue)>) -> SymbolicValue {
    if operands.is_empty() {
        return SymbolicValue::Unknown;
    }
    if operands.len() == 1 {
        return operands.into_iter().next().unwrap().1;
    }
    // All-same fold
    if operands.windows(2).all(|w| w[0].1 == w[1].1) {
        return operands.into_iter().next().unwrap().1;
    }

    // Depth check
    let max_depth = operands.iter().map(|(_, v)| v.depth()).max().unwrap_or(0);
    if 1 + max_depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::Phi(operands)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Display — human-readable witness strings
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum length for the Display output before truncation.
const MAX_DISPLAY_LEN: usize = 256;
/// Maximum length for inline string constants in Display.
const MAX_STR_DISPLAY_LEN: usize = 64;

impl fmt::Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use an internal formatter, then truncate if needed.
        let s = display_inner(self);
        if s.len() > MAX_DISPLAY_LEN {
            write!(f, "{}...", &s[..MAX_DISPLAY_LEN])
        } else {
            write!(f, "{}", s)
        }
    }
}

fn display_inner(val: &SymbolicValue) -> String {
    match val {
        SymbolicValue::Concrete(n) => format!("{}", n),
        SymbolicValue::ConcreteStr(s) => {
            if s.len() > MAX_STR_DISPLAY_LEN {
                format!("\"{}...\"", &s[..MAX_STR_DISPLAY_LEN])
            } else {
                format!("\"{}\"", s)
            }
        }
        SymbolicValue::Symbol(v) => format!("sym(v{})", v.0),
        SymbolicValue::BinOp(op, l, r) => {
            format!("({} {} {})", display_inner(l), op, display_inner(r))
        }
        SymbolicValue::Concat(l, r) => {
            format!("({} ++ {})", display_inner(l), display_inner(r))
        }
        SymbolicValue::Call(name, args) => {
            let arg_strs: Vec<String> = args.iter().map(display_inner).collect();
            format!("{}({})", name, arg_strs.join(", "))
        }
        SymbolicValue::Phi(operands) => {
            let parts: Vec<String> = operands
                .iter()
                .map(|(bid, v)| format!("B{}:{}", bid.0, display_inner(v)))
                .collect();
            format!("phi({})", parts.join(", "))
        }
        SymbolicValue::Unknown => "?".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_fold_add() {
        assert_eq!(
            mk_binop(Op::Add, SymbolicValue::Concrete(3), SymbolicValue::Concrete(5)),
            SymbolicValue::Concrete(8)
        );
    }

    #[test]
    fn concrete_fold_sub() {
        assert_eq!(
            mk_binop(Op::Sub, SymbolicValue::Concrete(10), SymbolicValue::Concrete(3)),
            SymbolicValue::Concrete(7)
        );
    }

    #[test]
    fn concrete_fold_mul() {
        assert_eq!(
            mk_binop(Op::Mul, SymbolicValue::Concrete(4), SymbolicValue::Concrete(7)),
            SymbolicValue::Concrete(28)
        );
    }

    #[test]
    fn concrete_fold_div() {
        assert_eq!(
            mk_binop(Op::Div, SymbolicValue::Concrete(15), SymbolicValue::Concrete(3)),
            SymbolicValue::Concrete(5)
        );
    }

    #[test]
    fn concrete_fold_mod() {
        assert_eq!(
            mk_binop(Op::Mod, SymbolicValue::Concrete(17), SymbolicValue::Concrete(5)),
            SymbolicValue::Concrete(2)
        );
    }

    #[test]
    fn overflow_add() {
        assert_eq!(
            mk_binop(Op::Add, SymbolicValue::Concrete(i64::MAX), SymbolicValue::Concrete(1)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn overflow_sub() {
        assert_eq!(
            mk_binop(Op::Sub, SymbolicValue::Concrete(i64::MIN), SymbolicValue::Concrete(1)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn overflow_mul() {
        assert_eq!(
            mk_binop(Op::Mul, SymbolicValue::Concrete(i64::MAX), SymbolicValue::Concrete(2)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn div_by_zero() {
        assert_eq!(
            mk_binop(Op::Div, SymbolicValue::Concrete(10), SymbolicValue::Concrete(0)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn mod_by_zero() {
        assert_eq!(
            mk_binop(Op::Mod, SymbolicValue::Concrete(10), SymbolicValue::Concrete(0)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn min_mod_neg_one() {
        // i64::MIN % -1 overflows
        assert_eq!(
            mk_binop(Op::Mod, SymbolicValue::Concrete(i64::MIN), SymbolicValue::Concrete(-1)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn depth_bounding() {
        // Build a chain of depth 33 — should collapse to Unknown
        let mut val = SymbolicValue::Symbol(SsaValue(0));
        for _ in 0..MAX_EXPR_DEPTH {
            val = mk_binop(Op::Add, val, SymbolicValue::Concrete(1));
        }
        // At depth == MAX_EXPR_DEPTH, should still be fine (depth check is >)
        assert_ne!(val, SymbolicValue::Unknown);
        assert_eq!(val.depth(), MAX_EXPR_DEPTH);

        // One more pushes past the limit
        val = mk_binop(Op::Add, val, SymbolicValue::Concrete(1));
        assert_eq!(val, SymbolicValue::Unknown);
    }

    #[test]
    fn concat_fold() {
        assert_eq!(
            mk_concat(
                SymbolicValue::ConcreteStr("hello ".into()),
                SymbolicValue::ConcreteStr("world".into()),
            ),
            SymbolicValue::ConcreteStr("hello world".into())
        );
    }

    #[test]
    fn concat_no_int_coercion() {
        // ConcreteStr + Concrete(int) should NOT fold — no type coercion
        let result = mk_concat(
            SymbolicValue::ConcreteStr("val=".into()),
            SymbolicValue::Concrete(42),
        );
        assert!(matches!(result, SymbolicValue::Concat(_, _)));
    }

    #[test]
    fn concat_depth_bounding() {
        let mut val = SymbolicValue::ConcreteStr("a".into());
        for _ in 0..MAX_EXPR_DEPTH {
            val = mk_concat(val, SymbolicValue::Symbol(SsaValue(0)));
        }
        assert_eq!(val.depth(), MAX_EXPR_DEPTH);
        val = mk_concat(val, SymbolicValue::Symbol(SsaValue(0)));
        assert_eq!(val, SymbolicValue::Unknown);
    }

    #[test]
    fn phi_single_operand_unwrap() {
        let v = SymbolicValue::Concrete(42);
        assert_eq!(mk_phi(vec![(BlockId(0), v.clone())]), v);
    }

    #[test]
    fn phi_all_same_fold() {
        let v = SymbolicValue::Concrete(7);
        assert_eq!(
            mk_phi(vec![(BlockId(0), v.clone()), (BlockId(1), v.clone())]),
            v
        );
    }

    #[test]
    fn phi_different_values() {
        let result = mk_phi(vec![
            (BlockId(0), SymbolicValue::Concrete(1)),
            (BlockId(1), SymbolicValue::Concrete(2)),
        ]);
        assert!(matches!(result, SymbolicValue::Phi(_)));
    }

    #[test]
    fn phi_empty() {
        assert_eq!(mk_phi(vec![]), SymbolicValue::Unknown);
    }

    #[test]
    fn call_depth_bounding() {
        let deep = {
            let mut v = SymbolicValue::Symbol(SsaValue(0));
            for _ in 0..MAX_EXPR_DEPTH {
                v = mk_binop(Op::Add, v, SymbolicValue::Concrete(1));
            }
            v
        };
        // deep has depth == MAX_EXPR_DEPTH; wrapping in Call would exceed
        let result = mk_call("f".into(), vec![deep]);
        assert_eq!(result, SymbolicValue::Unknown);
    }

    #[test]
    fn depth_leaf_nodes() {
        assert_eq!(SymbolicValue::Concrete(0).depth(), 0);
        assert_eq!(SymbolicValue::ConcreteStr("x".into()).depth(), 0);
        assert_eq!(SymbolicValue::Symbol(SsaValue(0)).depth(), 0);
        assert_eq!(SymbolicValue::Unknown.depth(), 0);
    }

    #[test]
    fn depth_nested() {
        let v = mk_binop(
            Op::Add,
            mk_binop(Op::Mul, SymbolicValue::Concrete(2), SymbolicValue::Symbol(SsaValue(0))),
            SymbolicValue::Concrete(1),
        );
        assert_eq!(v.depth(), 2);
    }

    #[test]
    fn is_concrete_checks() {
        assert!(SymbolicValue::Concrete(1).is_concrete());
        assert!(SymbolicValue::ConcreteStr("x".into()).is_concrete());
        assert!(!SymbolicValue::Symbol(SsaValue(0)).is_concrete());
        assert!(!SymbolicValue::Unknown.is_concrete());
    }

    #[test]
    fn as_concrete_int_checks() {
        assert_eq!(SymbolicValue::Concrete(42).as_concrete_int(), Some(42));
        assert_eq!(SymbolicValue::ConcreteStr("x".into()).as_concrete_int(), None);
        assert_eq!(SymbolicValue::Unknown.as_concrete_int(), None);
    }

    #[test]
    fn as_concrete_str_checks() {
        assert_eq!(SymbolicValue::ConcreteStr("hi".into()).as_concrete_str(), Some("hi"));
        assert_eq!(SymbolicValue::Concrete(1).as_concrete_str(), None);
    }

    #[test]
    fn display_concrete() {
        assert_eq!(format!("{}", SymbolicValue::Concrete(42)), "42");
    }

    #[test]
    fn display_concrete_str() {
        assert_eq!(
            format!("{}", SymbolicValue::ConcreteStr("hello".into())),
            "\"hello\""
        );
    }

    #[test]
    fn display_symbol() {
        assert_eq!(format!("{}", SymbolicValue::Symbol(SsaValue(3))), "sym(v3)");
    }

    #[test]
    fn display_binop() {
        let v = mk_binop(Op::Add, SymbolicValue::Symbol(SsaValue(1)), SymbolicValue::Concrete(2));
        assert_eq!(format!("{}", v), "(sym(v1) + 2)");
    }

    #[test]
    fn display_concat() {
        let v = mk_concat(
            SymbolicValue::ConcreteStr("SELECT ".into()),
            SymbolicValue::Symbol(SsaValue(5)),
        );
        assert_eq!(format!("{}", v), "(\"SELECT \" ++ sym(v5))");
    }

    #[test]
    fn display_call() {
        let v = mk_call(
            "parseInt".into(),
            vec![SymbolicValue::Symbol(SsaValue(2))],
        );
        assert_eq!(format!("{}", v), "parseInt(sym(v2))");
    }

    #[test]
    fn display_phi() {
        let v = mk_phi(vec![
            (BlockId(0), SymbolicValue::Concrete(1)),
            (BlockId(1), SymbolicValue::Symbol(SsaValue(3))),
        ]);
        assert_eq!(format!("{}", v), "phi(B0:1, B1:sym(v3))");
    }

    #[test]
    fn display_unknown() {
        assert_eq!(format!("{}", SymbolicValue::Unknown), "?");
    }

    #[test]
    fn display_truncation() {
        // Build a very long expression
        let mut v = SymbolicValue::Symbol(SsaValue(0));
        for i in 1..30 {
            v = mk_binop(Op::Add, v, SymbolicValue::Symbol(SsaValue(i)));
        }
        let s = format!("{}", v);
        assert!(s.len() <= MAX_DISPLAY_LEN + 3); // +3 for "..."
        if s.len() > MAX_DISPLAY_LEN {
            assert!(s.ends_with("..."));
        }
    }

    #[test]
    fn display_long_string_truncation() {
        let long = "a".repeat(100);
        let v = SymbolicValue::ConcreteStr(long);
        let s = format!("{}", v);
        assert!(s.contains("..."));
        assert!(s.len() <= MAX_STR_DISPLAY_LEN + 6); // quotes + "..."
    }

    #[test]
    fn op_from_cfg_binop() {
        assert_eq!(Op::from(cfg::BinOp::Add), Op::Add);
        assert_eq!(Op::from(cfg::BinOp::Sub), Op::Sub);
        assert_eq!(Op::from(cfg::BinOp::Mul), Op::Mul);
        assert_eq!(Op::from(cfg::BinOp::Div), Op::Div);
        assert_eq!(Op::from(cfg::BinOp::Mod), Op::Mod);
    }
}
