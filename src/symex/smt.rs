//! Phase 23: SMT Solver Integration via Z3.
//!
//! Provides a hybrid constraint solving architecture: [`PathEnv`] handles the
//! fast path (~95% of branches), and Z3 is invoked as a secondary solver for
//! cases that involve cross-variable relationships PathEnv cannot decide.
//!
//! ## Architecture
//!
//! - **Shape-based escalation**: SMT is only invoked when accumulated path
//!   constraints contain cross-variable comparisons (`Value` vs `Value`).
//!   Simple single-variable constraints never trigger Z3.
//! - **Integer/bool only (Phase 1)**: No string theory. String-related
//!   constraints are skipped conservatively.
//! - **Strict sort safety**: Z3 variables are only created when the sort is
//!   known with confidence. Unknown-sort variables are skipped entirely.
//! - **Sound infeasibility**: Z3 `Unsat` → path is infeasible. Anything else
//!   (Sat, Unknown, timeout, translation failure) → continue as before.
//!   This can never suppress a real finding.

use std::collections::HashMap;

use z3::ast::Int as Z3Int;
use z3::{Config, Params, SatResult, Solver};

use crate::constraint::{CompOp, ConditionExpr, ConstValue, Operand, PathEnv, RelOp};
use crate::ssa::ir::SsaValue;

use super::state::{PathConstraint, SymbolicState};

// ─────────────────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum SMT queries per finding (across all paths).
const MAX_SMT_QUERIES_PER_FINDING: u32 = 10;

/// Per-query timeout in milliseconds.
const SMT_QUERY_TIMEOUT_MS: u32 = 100;

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of an SMT satisfiability check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtResult {
    /// Path constraints are satisfiable (path is feasible).
    Sat,
    /// Path constraints are unsatisfiable (path is provably infeasible).
    Unsat,
    /// Solver returned unknown (timeout, resource limit, etc.).
    /// Treated conservatively as Sat.
    Unknown,
    /// Per-finding query budget exhausted.
    BudgetExhausted,
}

/// Z3 context and budget tracking for one finding's exploration.
///
/// Created once per `explore_finding()` call, shared across all paths explored
/// for that finding. A fresh `Solver` is created per `check_path_feasibility()`
/// call (reset-and-replay strategy).
///
/// The z3 0.19 crate uses a thread-local context model via `with_z3_config`.
/// We store the `Config` and create a scoped context per query.
pub struct SmtContext {
    cfg: Config,
    queries_used: u32,
    timeout_ms: u32,
}

/// Tracks the Z3 sort assigned to each SSA variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarSort {
    Int,
}

// ─────────────────────────────────────────────────────────────────────────────
//  SmtContext
// ─────────────────────────────────────────────────────────────────────────────

impl SmtContext {
    /// Create a new SMT context for one finding's exploration.
    pub fn new() -> Self {
        SmtContext {
            cfg: Config::new(),
            queries_used: 0,
            timeout_ms: SMT_QUERY_TIMEOUT_MS,
        }
    }

    /// Check whether the query budget has remaining capacity.
    pub fn has_budget(&self) -> bool {
        self.queries_used < MAX_SMT_QUERIES_PER_FINDING
    }

    /// Check path feasibility using Z3.
    ///
    /// Translates accumulated path constraints and PathEnv facts into Z3
    /// assertions, then checks satisfiability. Returns `Unsat` only when Z3
    /// proves the constraints are contradictory.
    ///
    /// Constraints that cannot be fully translated (unknown sorts, string
    /// operands, etc.) are silently skipped — this is sound because omitting
    /// a constraint can only make Z3 return `Sat` when the actual result
    /// might be `Unsat`, never the reverse.
    pub fn check_path_feasibility(
        &mut self,
        constraints: &[PathConstraint],
        _sym_state: &SymbolicState,
        env: &PathEnv,
    ) -> SmtResult {
        if !self.has_budget() {
            return SmtResult::BudgetExhausted;
        }
        self.queries_used += 1;

        // Use with_z3_config to create a scoped Z3 context for this query.
        let timeout_ms = self.timeout_ms;
        z3::with_z3_config(&self.cfg, || {
            let solver = Solver::new();

            // Set per-query timeout.
            let mut params = Params::new();
            params.set_u32("timeout", timeout_ms);
            solver.set_params(&params);

            // Build variable map from constraints + PathEnv.
            let mut var_map: HashMap<SsaValue, (Z3Int, VarSort)> = HashMap::new();

            // Seed from PathEnv facts (interval bounds, exact values).
            seed_from_path_env(&solver, &mut var_map, env);

            // Translate path constraints.
            for pc in constraints {
                assert_path_constraint(&solver, &mut var_map, pc, env);
            }

            // Check satisfiability.
            match solver.check() {
                SatResult::Unsat => SmtResult::Unsat,
                SatResult::Sat => SmtResult::Sat,
                SatResult::Unknown => SmtResult::Unknown,
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sort inference
// ─────────────────────────────────────────────────────────────────────────────

/// Try to determine that an SSA value is an integer from PathEnv facts.
fn is_known_int(v: SsaValue, env: &PathEnv) -> bool {
    let fact = env.get(v);
    // Has interval bounds → definitely numeric.
    if fact.lo.is_some() || fact.hi.is_some() {
        return true;
    }
    // Has an exact integer value.
    if matches!(fact.exact, Some(ConstValue::Int(_))) {
        return true;
    }
    false
}

/// Get or create a Z3 integer variable for an SSA value, but only if the
/// sort is known to be Int. Returns `None` if the sort is unknown.
fn ensure_int_var(
    var_map: &mut HashMap<SsaValue, (Z3Int, VarSort)>,
    v: SsaValue,
    env: &PathEnv,
) -> Option<Z3Int> {
    if let Some((z3_var, VarSort::Int)) = var_map.get(&v) {
        return Some(z3_var.clone());
    }
    // Only create if we have evidence this is an integer.
    if is_known_int(v, env) {
        let z3_var = Z3Int::new_const(format!("v{}", v.0));
        var_map.insert(v, (z3_var.clone(), VarSort::Int));
        return Some(z3_var);
    }
    None
}

/// Create a Z3 integer variable unconditionally (used when context proves
/// the sort, e.g., both sides of an integer comparison).
fn force_int_var(
    var_map: &mut HashMap<SsaValue, (Z3Int, VarSort)>,
    v: SsaValue,
) -> Z3Int {
    if let Some((z3_var, _)) = var_map.get(&v) {
        return z3_var.clone();
    }
    let z3_var = Z3Int::new_const(format!("v{}", v.0));
    var_map.insert(v, (z3_var.clone(), VarSort::Int));
    z3_var
}

// ─────────────────────────────────────────────────────────────────────────────
//  PathEnv seeding
// ─────────────────────────────────────────────────────────────────────────────

/// Seed Z3 solver with known facts from PathEnv.
///
/// Only seeds integer-typed facts. String or unknown-sort values are skipped.
fn seed_from_path_env(
    solver: &Solver,
    var_map: &mut HashMap<SsaValue, (Z3Int, VarSort)>,
    env: &PathEnv,
) {
    // Interval bounds and exact values.
    for &(v, ref fact) in env.facts() {
        // Only seed if this value has integer evidence.
        let has_int_evidence = fact.lo.is_some()
            || fact.hi.is_some()
            || matches!(fact.exact, Some(ConstValue::Int(_)));

        if !has_int_evidence {
            continue;
        }

        let z3_var = force_int_var(var_map, v);

        if let Some(lo) = fact.lo {
            if fact.lo_strict {
                solver.assert(&z3_var.gt(&Z3Int::from_i64(lo)));
            } else {
                solver.assert(&z3_var.ge(&Z3Int::from_i64(lo)));
            }
        }
        if let Some(hi) = fact.hi {
            if fact.hi_strict {
                solver.assert(&z3_var.lt(&Z3Int::from_i64(hi)));
            } else {
                solver.assert(&z3_var.le(&Z3Int::from_i64(hi)));
            }
        }
        if let Some(ConstValue::Int(n)) = &fact.exact {
            solver.assert(&z3_var.eq(&Z3Int::from_i64(*n)));
        }

        // Excluded integer values.
        for excl in &fact.excluded {
            if let ConstValue::Int(n) = excl {
                solver.assert(&z3_var.ne(&Z3Int::from_i64(*n)));
            }
        }
    }

    // Equality classes from UnionFind.
    // Iterate facts and check if any two share a class.
    let known_ints: Vec<SsaValue> = var_map.keys().copied().collect();
    for &v in &known_ints {
        let root = env.uf.find_immutable(v);
        if root != v {
            if let Some(root_var) = var_map.get(&root).map(|(z, _)| z.clone()) {
                let v_var = force_int_var(var_map, v);
                solver.assert(&v_var.eq(&root_var));
            }
        }
    }

    // Disequalities.
    for &(a, b) in env.disequalities() {
        if let (Some(za), Some(zb)) = (
            var_map.get(&a).map(|(z, _)| z.clone()),
            var_map.get(&b).map(|(z, _)| z.clone()),
        ) {
            solver.assert(&za.ne(&zb));
        }
    }

    // Relational constraints.
    for &(a, op, b) in env.relational() {
        if let (Some(za), Some(zb)) = (
            var_map.get(&a).map(|(z, _)| z.clone()),
            var_map.get(&b).map(|(z, _)| z.clone()),
        ) {
            match op {
                RelOp::Lt => solver.assert(&za.lt(&zb)),
                RelOp::Le => solver.assert(&za.le(&zb)),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constraint translation
// ─────────────────────────────────────────────────────────────────────────────

/// Translate a single path constraint into a Z3 assertion.
///
/// Skips constraints that cannot be fully translated (unknown sort, string
/// operands, etc.). This is sound — see module-level docs.
fn assert_path_constraint(
    solver: &Solver,
    var_map: &mut HashMap<SsaValue, (Z3Int, VarSort)>,
    pc: &PathConstraint,
    env: &PathEnv,
) {
    match &pc.condition {
        ConditionExpr::Comparison { lhs, op, rhs } => {
            if let (Some(z_lhs), Some(z_rhs)) =
                (translate_operand(var_map, lhs, env), translate_operand(var_map, rhs, env))
            {
                let cmp = build_comparison(&z_lhs, *op, &z_rhs);
                if pc.polarity {
                    solver.assert(&cmp);
                } else {
                    solver.assert(&cmp.not());
                }
            }
            // If either operand can't be translated, skip (conservative).
        }
        ConditionExpr::BoolTest { var } => {
            // Model as var != 0 if var is known int.
            if let Some(z_var) = ensure_int_var(var_map, *var, env) {
                let test = z_var.ne(&Z3Int::from_i64(0));
                if pc.polarity {
                    solver.assert(&test);
                } else {
                    solver.assert(&test.not());
                }
            }
        }
        // NullCheck, TypeCheck, Unknown — skip (not modeled in int/bool domain).
        ConditionExpr::NullCheck { .. }
        | ConditionExpr::TypeCheck { .. }
        | ConditionExpr::Unknown => {}
    }
}

/// Translate a constraint operand to a Z3 integer expression.
///
/// Returns `None` if the operand cannot be translated (unknown sort, string
/// constant, etc.).
fn translate_operand(
    var_map: &mut HashMap<SsaValue, (Z3Int, VarSort)>,
    op: &Operand,
    _env: &PathEnv,
) -> Option<Z3Int> {
    match op {
        Operand::Const(ConstValue::Int(n)) => Some(Z3Int::from_i64(*n)),
        Operand::Const(ConstValue::Bool(b)) => Some(Z3Int::from_i64(if *b { 1 } else { 0 })),
        Operand::Value(v) => {
            // When translating a comparison operand, the comparison context
            // proves this is a numeric value (it's being compared). So we
            // use force_int_var — the comparison itself is the sort evidence.
            Some(force_int_var(var_map, *v))
        }
        // String constants, Null, Unknown — cannot translate in int/bool domain.
        Operand::Const(ConstValue::Str(_))
        | Operand::Const(ConstValue::Null)
        | Operand::Unknown => None,
    }
}

/// Build a Z3 boolean expression for a comparison.
fn build_comparison(lhs: &Z3Int, op: CompOp, rhs: &Z3Int) -> z3::ast::Bool {
    match op {
        CompOp::Eq => lhs.eq(rhs),
        CompOp::Neq => lhs.ne(rhs),
        CompOp::Lt => lhs.lt(rhs),
        CompOp::Gt => lhs.gt(rhs),
        CompOp::Le => lhs.le(rhs),
        CompOp::Ge => lhs.ge(rhs),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Escalation predicate
// ─────────────────────────────────────────────────────────────────────────────

/// Determine whether accumulated path constraints warrant SMT escalation.
///
/// Returns `true` when the constraints contain patterns that PathEnv's
/// per-value abstract domain structurally cannot decide:
/// - Cross-variable comparisons (`Value` vs `Value`)
///
/// Simple single-variable constraints (x > 5, x == null, typeof x) never
/// trigger SMT — PathEnv handles those precisely.
pub fn should_escalate(constraints: &[PathConstraint]) -> bool {
    constraints.iter().any(|c| {
        matches!(
            &c.condition,
            ConditionExpr::Comparison {
                lhs: Operand::Value(_),
                rhs: Operand::Value(_),
                ..
            }
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::{CompOp, ConditionExpr, Operand, PathEnv};
    use crate::ssa::ir::{BlockId, SsaValue};

    /// Helper: build a Comparison PathConstraint.
    fn comparison_constraint(
        lhs: Operand,
        op: CompOp,
        rhs: Operand,
        polarity: bool,
    ) -> PathConstraint {
        PathConstraint {
            block: BlockId(0),
            condition: ConditionExpr::Comparison { lhs, op, rhs },
            polarity,
        }
    }

    fn val(n: u32) -> Operand {
        Operand::Value(SsaValue(n))
    }

    fn int_const(n: i64) -> Operand {
        Operand::Const(ConstValue::Int(n))
    }

    // ── Escalation predicate ─────────────────────────────────────────────

    #[test]
    fn escalation_fires_on_value_vs_value() {
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Gt,
            val(1),
            true,
        )];
        assert!(should_escalate(&constraints));
    }

    #[test]
    fn escalation_skips_value_vs_const() {
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Gt,
            int_const(5),
            true,
        )];
        assert!(!should_escalate(&constraints));
    }

    #[test]
    fn escalation_skips_empty() {
        assert!(!should_escalate(&[]));
    }

    #[test]
    fn escalation_skips_non_comparison() {
        let constraints = vec![PathConstraint {
            block: BlockId(0),
            condition: ConditionExpr::BoolTest {
                var: SsaValue(0),
            },
            polarity: true,
        }];
        assert!(!should_escalate(&constraints));
    }

    // ── Simple contradiction ─────────────────────────────────────────────

    #[test]
    fn simple_contradiction() {
        // x > 10 AND x < 5 → Unsat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(10), true),
            comparison_constraint(val(0), CompOp::Lt, int_const(5), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Cross-variable contradiction (key SMT value prop) ────────────────

    #[test]
    fn cross_variable_contradiction() {
        // x > y AND y > x → Unsat
        // PathEnv cannot detect this — it tracks per-variable intervals.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, val(1), true),
            comparison_constraint(val(1), CompOp::Gt, val(0), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Arithmetic cross-variable ────────────────────────────────────────

    #[test]
    fn arithmetic_cross_variable() {
        // x < 3 AND y < 5 AND (x + y) > 10 → Unsat
        // We model this as: x < 3, y < 5, and a third variable z = x + y > 10.
        // Since we don't yet translate SymbolicValue BinOps into Z3, we test
        // the simpler case: x < 3 AND y < 5 AND x > y AND y > 3 → Unsat
        // because y < 5 AND y > 3 means y=4, x > y means x > 4, but x < 3.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Lt, int_const(3), true),
            comparison_constraint(val(1), CompOp::Lt, int_const(5), true),
            comparison_constraint(val(1), CompOp::Gt, int_const(3), true),
            comparison_constraint(val(0), CompOp::Gt, val(1), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Satisfiable path ─────────────────────────────────────────────────

    #[test]
    fn satisfiable_path() {
        // x > 0 AND x < 100 → Sat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(0), true),
            comparison_constraint(val(0), CompOp::Lt, int_const(100), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Sat);
    }

    // ── Budget exhaustion ────────────────────────────────────────────────

    #[test]
    fn budget_exhaustion() {
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Gt,
            int_const(0),
            true,
        )];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();

        // Exhaust budget.
        for _ in 0..MAX_SMT_QUERIES_PER_FINDING {
            let r = ctx.check_path_feasibility(&constraints, &sym, &env);
            assert_ne!(r, SmtResult::BudgetExhausted);
        }

        // Next call should return BudgetExhausted.
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::BudgetExhausted);
    }

    // ── PathEnv seeding ──────────────────────────────────────────────────

    #[test]
    fn path_env_seeding_interval() {
        // Seed PathEnv with x in [10, 20], then assert x < 5 → Unsat.
        let mut env = PathEnv::empty();
        use crate::constraint::ValueFact;
        let mut fact = ValueFact::top();
        fact.lo = Some(10);
        fact.hi = Some(20);
        env.refine(SsaValue(0), &fact);

        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Lt,
            int_const(5),
            true,
        )];
        let mut ctx = SmtContext::new();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Sort safety: unknown sort variables are skipped ──────────────────

    #[test]
    fn skip_unknown_sort() {
        // BoolTest on a variable with no int evidence → skip.
        // The constraint is effectively ignored, so result should be Sat
        // (no assertions emitted).
        let constraints = vec![PathConstraint {
            block: BlockId(0),
            condition: ConditionExpr::BoolTest {
                var: SsaValue(99),
            },
            polarity: true,
        }];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        // No assertions emitted → trivially Sat.
        assert_eq!(result, SmtResult::Sat);
    }

    // ── String constraints are skipped ───────────────────────────────────

    #[test]
    fn string_constraint_skipped() {
        // Comparison with string constant → skip (no string theory in phase 1).
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Eq,
            Operand::Const(ConstValue::Str("hello".into())),
            true,
        )];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        // String operand → skip → no assertions → Sat.
        assert_eq!(result, SmtResult::Sat);
    }

    // ── Negated polarity ─────────────────────────────────────────────────

    #[test]
    fn negated_polarity() {
        // !(x > 10) means x <= 10, combined with x > 20 → Unsat.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(10), false), // x <= 10
            comparison_constraint(val(0), CompOp::Gt, int_const(20), true),  // x > 20
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Cross-variable with equality ─────────────────────────────────────

    #[test]
    fn cross_variable_equality_contradiction() {
        // x == y AND x > 5 AND y < 3 → Unsat (x == y but 5 < x and y < 3)
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Eq, val(1), true),
            comparison_constraint(val(0), CompOp::Gt, int_const(5), true),
            comparison_constraint(val(1), CompOp::Lt, int_const(3), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }
}
