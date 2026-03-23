//! Constraint solver: apply conditions to [`PathEnv`] and check satisfiability.
//!
//! The solver operates on structured [`ConditionExpr`] values — never on raw
//! text. Negation is always structural (via [`ConditionExpr::negate`] /
//! [`CompOp::negate`]), not via a generic "negate ValueFact" operation.

use crate::ssa::type_facts::TypeKind;

use super::domain::{BoolState, ConstValue, Nullability, PathEnv, TypeSet, ValueFact};
use super::lower::{CompOp, ConditionExpr, Operand};

/// Apply a condition to a [`PathEnv`], producing the refined environment
/// for the branch where the condition has the given polarity.
///
/// `polarity = true`: condition holds (true branch).
/// `polarity = false`: condition does NOT hold (false branch) — negate
/// the condition structurally, then apply.
pub fn refine_env(env: &PathEnv, cond: &ConditionExpr, polarity: bool) -> PathEnv {
    if env.is_unsat() {
        return env.clone();
    }

    let effective = if polarity {
        cond.clone()
    } else {
        cond.negate()
    };

    let mut result = env.clone();
    apply_condition(&mut result, &effective);
    result
}

/// Check if a [`PathEnv`] is satisfiable.
///
/// Unsatisfiability is detected incrementally during [`PathEnv::refine`],
/// so this is just a flag check.
pub fn is_satisfiable(env: &PathEnv) -> bool {
    !env.is_unsat()
}

// ── Internal dispatch ───────────────────────────────────────────────────

fn apply_condition(env: &mut PathEnv, cond: &ConditionExpr) {
    match cond {
        ConditionExpr::NullCheck { var, is_null } => {
            let mut fact = ValueFact::top();
            if *is_null {
                fact.null = Nullability::Null;
                fact.types = TypeSet::singleton(&TypeKind::Null);
            } else {
                fact.null = Nullability::NonNull;
            }
            env.refine(*var, &fact);
        }

        ConditionExpr::TypeCheck {
            var,
            type_name,
            positive,
        } => {
            if let Some(kind) = parse_type_name(type_name) {
                let ts = TypeSet::singleton(&kind);
                let mut fact = ValueFact::top();
                if *positive {
                    fact.types = ts;
                    if kind != TypeKind::Null {
                        fact.null = Nullability::NonNull;
                    }
                } else {
                    fact.types = ts.complement();
                }
                env.refine(*var, &fact);
            }
            // Unknown type name → no refinement (conservative)
        }

        ConditionExpr::BoolTest { var } => {
            // Conservative: only refine NonNull for known boolean-typed values.
            // Truthiness is language-specific (0, "", empty containers are
            // falsy in some languages). Over-constraining would be unsound.
            //
            // We check the existing fact: if the value is already known
            // boolean-typed, we can safely refine to True.
            let existing = env.get(*var);
            if existing.types == TypeSet::singleton(&TypeKind::Bool) {
                let mut fact = ValueFact::top();
                fact.bool_state = BoolState::True;
                fact.null = Nullability::NonNull;
                env.refine(*var, &fact);
            }
            // Otherwise: no refinement (conservative)
        }

        ConditionExpr::Comparison { lhs, op, rhs } => {
            apply_comparison(env, lhs, *op, rhs);
        }

        ConditionExpr::Unknown => {
            // No information — no refinement
        }
    }
}

fn apply_comparison(env: &mut PathEnv, lhs: &Operand, op: CompOp, rhs: &Operand) {
    match (lhs, rhs) {
        (Operand::Value(v), Operand::Const(c)) => {
            apply_value_const(env, *v, op, c);
        }
        (Operand::Const(c), Operand::Value(v)) => {
            // Flip: const op var → var (flipped_op) const
            apply_value_const(env, *v, op.flip(), c);
        }
        (Operand::Value(a), Operand::Value(b)) => match op {
            CompOp::Eq => env.assert_equal(*a, *b),
            CompOp::Neq => env.assert_not_equal(*a, *b),
            CompOp::Lt | CompOp::Gt | CompOp::Le | CompOp::Ge => {
                // V1 limitation: no relational constraints beyond eq/neq.
                // Could transfer known bounds if one side has an interval,
                // but deferred to V2.
            }
        },
        // At least one Unknown operand: no refinement
        _ => {}
    }
}

/// Apply a value-vs-constant comparison to the environment.
fn apply_value_const(env: &mut PathEnv, v: crate::ssa::ir::SsaValue, op: CompOp, c: &ConstValue) {
    let mut fact = ValueFact::top();

    match op {
        CompOp::Eq => {
            fact.exact = Some(c.clone());
            match c {
                ConstValue::Int(i) => {
                    fact.lo = Some(*i);
                    fact.hi = Some(*i);
                    fact.types = TypeSet::singleton(&TypeKind::Int);
                    fact.null = Nullability::NonNull;
                }
                ConstValue::Null => {
                    fact.null = Nullability::Null;
                    fact.types = TypeSet::singleton(&TypeKind::Null);
                }
                ConstValue::Bool(b) => {
                    fact.bool_state = if *b {
                        BoolState::True
                    } else {
                        BoolState::False
                    };
                    fact.types = TypeSet::singleton(&TypeKind::Bool);
                    fact.null = Nullability::NonNull;
                }
                ConstValue::Str(_) => {
                    fact.types = TypeSet::singleton(&TypeKind::String);
                    fact.null = Nullability::NonNull;
                }
            }
        }
        CompOp::Neq => {
            if c == &ConstValue::Null {
                fact.null = Nullability::NonNull;
            }
            fact.excluded.push(c.clone());
        }
        CompOp::Lt => {
            if let ConstValue::Int(i) = c {
                fact.hi = Some(*i);
                fact.hi_strict = true;
                fact.null = Nullability::NonNull;
            }
            // Non-Int Lt: no refinement (V1)
        }
        CompOp::Le => {
            if let ConstValue::Int(i) = c {
                fact.hi = Some(*i);
                fact.null = Nullability::NonNull;
            }
        }
        CompOp::Gt => {
            if let ConstValue::Int(i) = c {
                fact.lo = Some(*i);
                fact.lo_strict = true;
                fact.null = Nullability::NonNull;
            }
        }
        CompOp::Ge => {
            if let ConstValue::Int(i) = c {
                fact.lo = Some(*i);
                fact.null = Nullability::NonNull;
            }
        }
    }

    env.refine(v, &fact);
}

/// Map typeof / type-name strings to [`TypeKind`].
pub fn parse_type_name(name: &str) -> Option<TypeKind> {
    match name.to_ascii_lowercase().as_str() {
        "string" | "str" => Some(TypeKind::String),
        "number" | "int" | "integer" | "i32" | "i64" | "u32" | "u64" | "float" | "double" => {
            Some(TypeKind::Int)
        }
        "boolean" | "bool" => Some(TypeKind::Bool),
        "object" => Some(TypeKind::Object),
        "array" | "list" => Some(TypeKind::Array),
        "null" | "nil" | "none" | "undefined" => Some(TypeKind::Null),
        _ => None,
    }
}
