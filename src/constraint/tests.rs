//! Comprehensive tests for the constraint solving module.

use super::domain::*;
use super::lower::*;
use super::solver::*;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::SsaValue;
use std::collections::HashMap;

// ── ValueFact meet tests ────────────────────────────────────────────────

#[test]
fn valuefact_meet_eq_eq_same() {
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    let mut b = ValueFact::top();
    b.exact = Some(ConstValue::Int(5));
    let m = a.meet(&b);
    assert_eq!(m.exact, Some(ConstValue::Int(5)));
    assert!(!m.is_bottom());
}

#[test]
fn valuefact_meet_eq_eq_diff() {
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    let mut b = ValueFact::top();
    b.exact = Some(ConstValue::Int(7));
    let m = a.meet(&b);
    assert!(m.is_bottom());
}

#[test]
fn valuefact_meet_eq_neq() {
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    let mut b = ValueFact::top();
    b.excluded.push(ConstValue::Int(5));
    let m = a.meet(&b);
    assert!(m.is_bottom());
}

#[test]
fn valuefact_meet_gt_lt_contradiction() {
    // x > 10 meet x < 5 → empty interval → bottom
    let mut a = ValueFact::top();
    a.lo = Some(10);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.hi = Some(5);
    b.hi_strict = true;
    let m = a.meet(&b);
    assert!(m.is_bottom(), "expected bottom for (10,+inf) ∩ (-inf,5)");
}

#[test]
fn valuefact_meet_gt_lt_compatible() {
    // x > 0 meet x < 100 → (0, 100) open interval
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.hi = Some(100);
    b.hi_strict = true;
    let m = a.meet(&b);
    assert!(!m.is_bottom());
    assert_eq!(m.lo, Some(0));
    assert!(m.lo_strict);
    assert_eq!(m.hi, Some(100));
    assert!(m.hi_strict);
}

#[test]
fn valuefact_meet_null_nonnull_is_bottom() {
    let mut a = ValueFact::top();
    a.null = Nullability::Null;
    let mut b = ValueFact::top();
    b.null = Nullability::NonNull;
    let m = a.meet(&b);
    assert!(m.is_bottom());
}

// ── ValueFact join tests ────────────────────────────────────────────────

#[test]
fn valuefact_join_intervals_preserves_weaker() {
    // [x > 0] join [x > 5] = [x > 0]
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.lo = Some(5);
    b.lo_strict = true;
    let j = a.join(&b);
    assert_eq!(j.lo, Some(0));
    assert!(j.lo_strict);
    assert_eq!(j.hi, None); // no upper bound
}

#[test]
fn valuefact_join_exact_to_interval() {
    // Eq(5) join Eq(7) = no exact, interval [5,7]
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    a.lo = Some(5);
    a.hi = Some(5);
    let mut b = ValueFact::top();
    b.exact = Some(ConstValue::Int(7));
    b.lo = Some(7);
    b.hi = Some(7);
    let j = a.join(&b);
    assert_eq!(j.exact, None); // different constants
    assert_eq!(j.lo, Some(5));
    assert_eq!(j.hi, Some(7));
}

#[test]
fn valuefact_join_nonnull_and_unknown() {
    let mut a = ValueFact::top();
    a.null = Nullability::NonNull;
    let b = ValueFact::top(); // null = Unknown
    let j = a.join(&b);
    assert_eq!(j.null, Nullability::Unknown);
}

#[test]
fn valuefact_join_nonnull_and_nonnull() {
    let mut a = ValueFact::top();
    a.null = Nullability::NonNull;
    let mut b = ValueFact::top();
    b.null = Nullability::NonNull;
    let j = a.join(&b);
    assert_eq!(j.null, Nullability::NonNull);
}

// ── ValueFact widen tests ───────────────────────────────────────────────

#[test]
fn valuefact_widen_unstable_bound() {
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.lo = Some(5); // changed from 0 to 5
    b.lo_strict = true;
    let w = a.widen(&b);
    assert_eq!(w.lo, None); // dropped because unstable
}

#[test]
fn valuefact_widen_stable_bound() {
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.lo = Some(0);
    b.lo_strict = true;
    let w = a.widen(&b);
    assert_eq!(w.lo, Some(0)); // stable — preserved
    assert!(w.lo_strict);
}

// ── Nullability tests ───────────────────────────────────────────────────

#[test]
fn nullability_meet_join_exhaustive() {
    use Nullability::*;
    // meet: refine
    assert_eq!(Unknown.meet(Null), Null);
    assert_eq!(Unknown.meet(NonNull), NonNull);
    assert_eq!(Null.meet(NonNull), Bottom);
    assert_eq!(Null.meet(Null), Null);
    assert_eq!(Bottom.meet(Unknown), Bottom);
    // join: merge
    assert_eq!(Null.join(NonNull), Unknown);
    assert_eq!(Null.join(Null), Null);
    assert_eq!(Unknown.join(Null), Unknown);
    assert_eq!(Bottom.join(Null), Null);
    assert_eq!(Bottom.join(Bottom), Bottom);
}

// ── BoolState tests ─────────────────────────────────────────────────────

#[test]
fn boolstate_meet_join_exhaustive() {
    use BoolState::*;
    assert_eq!(Unknown.meet(True), True);
    assert_eq!(True.meet(False), Bottom);
    assert_eq!(True.meet(True), True);
    assert_eq!(Bottom.meet(True), Bottom);
    assert_eq!(True.join(False), Unknown);
    assert_eq!(True.join(True), True);
    assert_eq!(Bottom.join(True), True);
}

// ── TypeSet tests ───────────────────────────────────────────────────────

#[test]
fn typeset_meet_is_intersection() {
    use crate::ssa::type_facts::TypeKind;
    let a = TypeSet::singleton(&TypeKind::String).join(TypeSet::singleton(&TypeKind::Int));
    let b = TypeSet::singleton(&TypeKind::Int).join(TypeSet::singleton(&TypeKind::Bool));
    let m = a.meet(b);
    assert!(m.contains(&TypeKind::Int));
    assert!(!m.contains(&TypeKind::String));
    assert!(!m.contains(&TypeKind::Bool));
}

#[test]
fn typeset_join_is_union() {
    use crate::ssa::type_facts::TypeKind;
    let a = TypeSet::singleton(&TypeKind::String);
    let b = TypeSet::singleton(&TypeKind::Int);
    let j = a.join(b);
    assert!(j.contains(&TypeKind::String));
    assert!(j.contains(&TypeKind::Int));
}

#[test]
fn typeset_complement() {
    use crate::ssa::type_facts::TypeKind;
    let s = TypeSet::singleton(&TypeKind::String);
    let c = s.complement();
    assert!(!c.contains(&TypeKind::String));
    assert!(c.contains(&TypeKind::Int));
    assert!(c.contains(&TypeKind::Bool));
    // complement of complement is original
    assert_eq!(c.complement(), s);
}

#[test]
fn typeset_top_bottom() {
    assert!(TypeSet::TOP.is_top());
    assert!(!TypeSet::TOP.is_bottom());
    assert!(TypeSet::BOTTOM.is_bottom());
    assert!(!TypeSet::BOTTOM.is_top());
}

// ── PathEnv tests ───────────────────────────────────────────────────────

#[test]
fn pathenv_refine_and_get() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let mut fact = ValueFact::top();
    fact.null = Nullability::NonNull;
    env.refine(v, &fact);
    let got = env.get(v);
    assert_eq!(got.null, Nullability::NonNull);
}

#[test]
fn pathenv_refine_contradiction_sets_unsat() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let mut f1 = ValueFact::top();
    f1.null = Nullability::Null;
    env.refine(v, &f1);
    assert!(!env.is_unsat());
    let mut f2 = ValueFact::top();
    f2.null = Nullability::NonNull;
    env.refine(v, &f2);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_join_common_facts_preserved() {
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    let mut f1 = ValueFact::top();
    f1.null = Nullability::NonNull;
    env1.refine(v, &f1);
    let mut env2 = PathEnv::empty();
    let mut f2 = ValueFact::top();
    f2.null = Nullability::NonNull;
    env2.refine(v, &f2);
    let joined = env1.join(&env2);
    let got = joined.get(v);
    assert_eq!(got.null, Nullability::NonNull);
}

#[test]
fn pathenv_join_one_side_absent_drops() {
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    let mut f1 = ValueFact::top();
    f1.null = Nullability::NonNull;
    env1.refine(v, &f1);
    let env2 = PathEnv::empty(); // no fact for v
    let joined = env1.join(&env2);
    let got = joined.get(v);
    // Intentional: absent = Top, Top.join(NonNull) = Top → dropped
    assert_eq!(got.null, Nullability::Unknown);
}

#[test]
fn pathenv_join_one_side_nonnull_other_untouched() {
    // Verify explicitly: one branch refines x to NonNull, other leaves x untouched
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    env1.refine(v, &{
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        f
    });
    let env2 = PathEnv::empty();
    let joined = env1.join(&env2);
    assert_eq!(joined.get(v).null, Nullability::Unknown); // drops to Unknown
}

#[test]
fn pathenv_join_one_side_range_other_untouched() {
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    env1.refine(v, &{
        let mut f = ValueFact::top();
        f.lo = Some(0);
        f.lo_strict = true;
        f
    });
    let env2 = PathEnv::empty();
    let joined = env1.join(&env2);
    assert_eq!(joined.get(v).lo, None); // dropped
}

#[test]
fn pathenv_join_one_side_type_other_untouched() {
    use crate::ssa::type_facts::TypeKind;
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    env1.refine(v, &{
        let mut f = ValueFact::top();
        f.types = TypeSet::singleton(&TypeKind::String);
        f
    });
    let env2 = PathEnv::empty();
    let joined = env1.join(&env2);
    assert!(joined.get(v).types.is_top()); // dropped to Top
}

#[test]
fn pathenv_bounded_size() {
    let mut env = PathEnv::empty();
    for i in 0..(MAX_PATH_ENV_ENTRIES + 10) {
        let v = SsaValue(i as u32);
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        env.refine(v, &f);
    }
    assert!(env.fact_count() <= MAX_PATH_ENV_ENTRIES);
    assert!(!env.is_unsat());
}

#[test]
fn pathenv_max_refine_per_block() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // Reset counter
    env.reset_refine_count();
    // Refine many times — should stop after MAX_REFINE_PER_BLOCK
    for _ in 0..(MAX_REFINE_PER_BLOCK + 50) {
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        env.refine(v, &f);
    }
    // Should not panic or set unsat from excessive refinement
    assert!(!env.is_unsat());
}

// ── UnionFind tests ─────────────────────────────────────────────────────

#[test]
fn uf_basic_union_find() {
    let mut uf = UnionFind::new();
    let a = SsaValue(0);
    let b = SsaValue(1);
    assert!(!uf.same_class(a, b));
    uf.union(a, b);
    assert!(uf.same_class(a, b));
    assert_eq!(uf.find(a), uf.find(b));
}

#[test]
fn uf_transitive() {
    let mut uf = UnionFind::new();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);
    uf.union(a, b);
    uf.union(b, c);
    assert!(uf.same_class(a, c));
}

#[test]
fn uf_equality_propagates_facts() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_equal(a, b);
    // Refine a with Eq(5) → should propagate to b
    let mut fact = ValueFact::top();
    fact.exact = Some(ConstValue::Int(5));
    fact.lo = Some(5);
    fact.hi = Some(5);
    env.refine(a, &fact);
    let got_b = env.get(b);
    assert_eq!(got_b.exact, Some(ConstValue::Int(5)));
}

#[test]
fn uf_disequality_contradiction() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_equal(a, b);
    env.assert_not_equal(a, b);
    assert!(env.is_unsat());
}

#[test]
fn uf_transitive_disequality() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);
    env.assert_equal(a, b);
    env.assert_equal(b, c);
    // Now a==b==c, then assert a!=c → contradiction
    env.assert_not_equal(a, c);
    assert!(env.is_unsat());
}

#[test]
fn uf_max_edges_bounded() {
    let mut uf = UnionFind::new();
    for i in 0..(MAX_EQUALITY_EDGES + 10) {
        uf.union(SsaValue(0), SsaValue(i as u32 + 1));
    }
    assert!(uf.edge_count() <= MAX_EQUALITY_EDGES);
}

// ── Lowering tests ──────────────────────────────────────────────────────

#[test]
fn compop_flip() {
    assert_eq!(CompOp::Lt.flip(), CompOp::Gt);
    assert_eq!(CompOp::Gt.flip(), CompOp::Lt);
    assert_eq!(CompOp::Le.flip(), CompOp::Ge);
    assert_eq!(CompOp::Ge.flip(), CompOp::Le);
    assert_eq!(CompOp::Eq.flip(), CompOp::Eq);
    assert_eq!(CompOp::Neq.flip(), CompOp::Neq);
}

#[test]
fn compop_negate() {
    assert_eq!(CompOp::Eq.negate(), CompOp::Neq);
    assert_eq!(CompOp::Neq.negate(), CompOp::Eq);
    assert_eq!(CompOp::Lt.negate(), CompOp::Ge);
    assert_eq!(CompOp::Ge.negate(), CompOp::Lt);
    assert_eq!(CompOp::Gt.negate(), CompOp::Le);
    assert_eq!(CompOp::Le.negate(), CompOp::Gt);
}

#[test]
fn compop_negate_round_trip() {
    for op in [
        CompOp::Eq,
        CompOp::Neq,
        CompOp::Lt,
        CompOp::Gt,
        CompOp::Le,
        CompOp::Ge,
    ] {
        assert_eq!(op.negate().negate(), op);
    }
}

#[test]
fn condition_expr_negate_comparison() {
    let expr = ConditionExpr::Comparison {
        lhs: Operand::Value(SsaValue(0)),
        op: CompOp::Gt,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    let neg = expr.negate();
    match neg {
        ConditionExpr::Comparison { op, .. } => assert_eq!(op, CompOp::Le),
        _ => panic!("expected Comparison"),
    }
}

#[test]
fn condition_expr_negate_null_check() {
    let expr = ConditionExpr::NullCheck {
        var: SsaValue(0),
        is_null: true,
    };
    let neg = expr.negate();
    match neg {
        ConditionExpr::NullCheck { is_null, .. } => assert!(!is_null),
        _ => panic!("expected NullCheck"),
    }
}

#[test]
fn condition_expr_negate_type_check() {
    let expr = ConditionExpr::TypeCheck {
        var: SsaValue(0),
        type_name: "number".into(),
        positive: true,
    };
    let neg = expr.negate();
    match neg {
        ConditionExpr::TypeCheck { positive, .. } => assert!(!positive),
        _ => panic!("expected TypeCheck"),
    }
}

#[test]
fn const_value_parse_literal() {
    assert_eq!(ConstValue::parse_literal("5"), Some(ConstValue::Int(5)));
    assert_eq!(ConstValue::parse_literal("-3"), Some(ConstValue::Int(-3)));
    assert_eq!(ConstValue::parse_literal("null"), Some(ConstValue::Null));
    assert_eq!(ConstValue::parse_literal("None"), Some(ConstValue::Null));
    assert_eq!(
        ConstValue::parse_literal("true"),
        Some(ConstValue::Bool(true))
    );
    assert_eq!(
        ConstValue::parse_literal("\"hello\""),
        Some(ConstValue::Str("hello".into()))
    );
    assert_eq!(
        ConstValue::parse_literal("'world'"),
        Some(ConstValue::Str("world".into()))
    );
    assert_eq!(ConstValue::parse_literal(""), None);
    assert_eq!(ConstValue::parse_literal("xyz"), None);
}

// ── Solver tests ────────────────────────────────────────────────────────

#[test]
fn refine_null_check_true_branch() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::NullCheck {
        var: v,
        is_null: true,
    };
    env = refine_env(&env, &cond, true);
    assert_eq!(env.get(v).null, Nullability::Null);
}

#[test]
fn refine_null_check_false_branch() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::NullCheck {
        var: v,
        is_null: true,
    };
    env = refine_env(&env, &cond, false); // negated: not null
    assert_eq!(env.get(v).null, Nullability::NonNull);
}

#[test]
fn refine_comparison_gt_then_lt_contradiction() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // x > 10
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Gt,
        rhs: Operand::Const(ConstValue::Int(10)),
    };
    env = refine_env(&env, &c1, true);
    assert!(!env.is_unsat());
    // x < 5 (contradicts x > 10)
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Lt,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat());
}

#[test]
fn refine_comparison_eq_then_neq_contradiction() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    env = refine_env(&env, &c1, true);
    assert!(!env.is_unsat());
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Neq,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat());
}

#[test]
fn refine_comparison_eq_string_then_different_string() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Str("safe".into())),
    };
    env = refine_env(&env, &c1, true);
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Str("dangerous".into())),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat(), "Eq('safe') ∧ Eq('dangerous') should be unsat");
}

#[test]
fn refine_type_check_positive() {
    use crate::ssa::type_facts::TypeKind;
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::TypeCheck {
        var: v,
        type_name: "number".into(),
        positive: true,
    };
    env = refine_env(&env, &cond, true);
    let got = env.get(v);
    assert!(got.types.contains(&TypeKind::Int));
    assert!(!got.types.contains(&TypeKind::String));
    assert_eq!(got.null, Nullability::NonNull);
}

#[test]
fn refine_type_check_negative() {
    use crate::ssa::type_facts::TypeKind;
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::TypeCheck {
        var: v,
        type_name: "number".into(),
        positive: true,
    };
    env = refine_env(&env, &cond, false); // NOT number
    let got = env.get(v);
    assert!(!got.types.contains(&TypeKind::Int));
    assert!(got.types.contains(&TypeKind::String));
}

#[test]
fn refine_value_eq_value() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    // First: a is NonNull
    env.refine(a, &{
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        f
    });
    // Then: a == b → b should also become NonNull
    let cond = ConditionExpr::Comparison {
        lhs: Operand::Value(a),
        op: CompOp::Eq,
        rhs: Operand::Value(b),
    };
    env = refine_env(&env, &cond, true);
    assert_eq!(env.get(b).null, Nullability::NonNull);
}

#[test]
fn refine_unknown_is_noop() {
    let env = PathEnv::empty();
    let refined = refine_env(&env, &ConditionExpr::Unknown, true);
    assert!(!refined.is_unsat());
    assert_eq!(refined.fact_count(), 0);
}

#[test]
fn refine_booltest_conservative() {
    // BoolTest should NOT add NonNull for non-boolean-typed values
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::BoolTest { var: v };
    env = refine_env(&env, &cond, true);
    // Since v has no known type, BoolTest should be conservative
    assert_eq!(env.get(v).null, Nullability::Unknown);
}

#[test]
fn refine_booltest_boolean_typed() {
    use crate::ssa::type_facts::TypeKind;
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // First: mark v as boolean-typed
    env.refine(v, &{
        let mut f = ValueFact::top();
        f.types = TypeSet::singleton(&TypeKind::Bool);
        f
    });
    // Now BoolTest should refine to True + NonNull
    let cond = ConditionExpr::BoolTest { var: v };
    env = refine_env(&env, &cond, true);
    assert_eq!(env.get(v).bool_state, BoolState::True);
    assert_eq!(env.get(v).null, Nullability::NonNull);
}

#[test]
fn refine_comparison_feasible_range_not_pruned() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // x > 0
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Gt,
        rhs: Operand::Const(ConstValue::Int(0)),
    };
    env = refine_env(&env, &c1, true);
    // x < 100 (compatible with x > 0)
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Lt,
        rhs: Operand::Const(ConstValue::Int(100)),
    };
    env = refine_env(&env, &c2, true);
    assert!(
        !env.is_unsat(),
        "feasible range (0, 100) should not be pruned"
    );
}

#[test]
fn refine_null_then_eq_string_contradiction() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // x is null
    let c1 = ConditionExpr::NullCheck {
        var: v,
        is_null: true,
    };
    env = refine_env(&env, &c1, true);
    // x == "rm" (contradicts: null value can't be a string)
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Str("rm".into())),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat(), "null ∧ Eq('rm') should be unsat");
}

// ── parse_type_name tests ───────────────────────────────────────────────

#[test]
fn parse_type_name_coverage() {
    use crate::ssa::type_facts::TypeKind;
    assert_eq!(parse_type_name("string"), Some(TypeKind::String));
    assert_eq!(parse_type_name("str"), Some(TypeKind::String));
    assert_eq!(parse_type_name("number"), Some(TypeKind::Int));
    assert_eq!(parse_type_name("int"), Some(TypeKind::Int));
    assert_eq!(parse_type_name("boolean"), Some(TypeKind::Bool));
    assert_eq!(parse_type_name("bool"), Some(TypeKind::Bool));
    assert_eq!(parse_type_name("object"), Some(TypeKind::Object));
    assert_eq!(parse_type_name("array"), Some(TypeKind::Array));
    assert_eq!(parse_type_name("null"), Some(TypeKind::Null));
    assert_eq!(parse_type_name("undefined"), Some(TypeKind::Null));
    assert_eq!(parse_type_name("blah"), None);
}

// ── PathEnv seed tests ──────────────────────────────────────────────────

#[test]
fn pathenv_seed_from_optimization() {
    use crate::ssa::type_facts::{TypeFact, TypeFactResult, TypeKind};
    let mut env = PathEnv::empty();
    let v0 = SsaValue(0);
    let v1 = SsaValue(1);
    let mut const_values = HashMap::new();
    const_values.insert(v0, ConstLattice::Int(42));
    let mut type_facts = TypeFactResult {
        facts: HashMap::new(),
    };
    type_facts.facts.insert(
        v1,
        TypeFact {
            kind: TypeKind::String,
            nullable: false,
        },
    );
    env.seed_from_optimization(&const_values, &type_facts);
    let f0 = env.get(v0);
    assert_eq!(f0.exact, Some(ConstValue::Int(42)));
    assert_eq!(f0.null, Nullability::NonNull);
    let f1 = env.get(v1);
    assert!(f1.types.contains(&TypeKind::String));
    assert_eq!(f1.null, Nullability::NonNull);
}
