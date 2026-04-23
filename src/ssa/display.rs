use std::fmt;

use super::ir::*;

impl fmt::Display for SsaBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for block in &self.blocks {
            let entry_marker = if block.id == self.entry {
                " (entry)"
            } else {
                ""
            };
            writeln!(f, "Block B{}{entry_marker}:", block.id.0)?;

            // Predecessors
            if !block.preds.is_empty() {
                let preds: Vec<String> = block.preds.iter().map(|p| format!("B{}", p.0)).collect();
                writeln!(f, "  ; preds: {}", preds.join(", "))?;
            }

            // Phi instructions
            for inst in &block.phis {
                write!(f, "  v{} = ", inst.value.0)?;
                if let SsaOp::Phi(ref operands) = inst.op {
                    let ops: Vec<String> = operands
                        .iter()
                        .map(|(bid, val)| format!("B{}:v{}", bid.0, val.0))
                        .collect();
                    write!(f, "phi({})", ops.join(", "))?;
                }
                if let Some(ref name) = inst.var_name {
                    write!(f, "  # {name}")?;
                }
                writeln!(f)?;
            }

            // Body instructions
            for inst in &block.body {
                write!(f, "  v{} = ", inst.value.0)?;
                match &inst.op {
                    SsaOp::Phi(_) => write!(f, "phi(???)")?, // shouldn't appear in body
                    SsaOp::Assign(uses) => {
                        let uses_str: Vec<String> =
                            uses.iter().map(|v| format!("v{}", v.0)).collect();
                        write!(f, "assign({})", uses_str.join(", "))?;
                    }
                    SsaOp::Call {
                        callee,
                        args,
                        receiver,
                    } => {
                        if let Some(rv) = receiver {
                            write!(f, "v{}.{callee}(", rv.0)?;
                        } else {
                            write!(f, "{callee}(")?;
                        }
                        let arg_strs: Vec<String> = args
                            .iter()
                            .map(|arg| {
                                let vs: Vec<String> =
                                    arg.iter().map(|v| format!("v{}", v.0)).collect();
                                vs.join("+")
                            })
                            .collect();
                        write!(f, "{})", arg_strs.join(", "))?;
                    }
                    SsaOp::Source => write!(f, "source()")?,
                    SsaOp::Const(val) => {
                        if let Some(v) = val {
                            write!(f, "const({v})")?;
                        } else {
                            write!(f, "const")?;
                        }
                    }
                    SsaOp::Param { index } => write!(f, "param({index})")?,
                    SsaOp::SelfParam => write!(f, "self_param()")?,
                    SsaOp::CatchParam => write!(f, "catch_param()")?,
                    SsaOp::Nop => write!(f, "nop")?,
                }
                if let Some(ref name) = inst.var_name {
                    write!(f, "  # {name}")?;
                }
                // Span info
                if inst.span != (0, 0) {
                    write!(f, "  @ {}..{}", inst.span.0, inst.span.1)?;
                }
                writeln!(f)?;
            }

            // Terminator
            match &block.terminator {
                Terminator::Goto(target) => writeln!(f, "  goto → B{}", target.0)?,
                Terminator::Branch {
                    true_blk,
                    false_blk,
                    ..
                } => writeln!(
                    f,
                    "  branch → B{} (true), B{} (false)",
                    true_blk.0, false_blk.0
                )?,
                Terminator::Switch {
                    scrutinee,
                    targets,
                    default,
                } => {
                    write!(f, "  switch v{} → [", scrutinee.0)?;
                    for (i, t) in targets.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "B{}", t.0)?;
                    }
                    writeln!(f, "] default B{}", default.0)?;
                }
                Terminator::Return(ret_val) => {
                    if let Some(v) = ret_val {
                        writeln!(f, "  return v{}", v.0)?
                    } else {
                        writeln!(f, "  return")?
                    }
                }
                Terminator::Unreachable => writeln!(f, "  unreachable")?,
            }

            writeln!(f)?;
        }
        Ok(())
    }
}

impl fmt::Display for SsaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B{}", self.0)
    }
}
