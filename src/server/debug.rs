//! Debug view-model types and on-demand analysis pipeline.
//!
//! Provides serializable "view" structs that mirror internal engine types
//! (CFG, SSA, taint state, etc.) without requiring the engine types themselves
//! to derive `Serialize`.  Also provides helper functions that re-run the
//! analysis pipeline on a single file/function for debug inspection.

use crate::ast::build_cfg_for_file;
use crate::callgraph::{CallGraph, CallGraphAnalysis};
use crate::cfg::{Cfg, EdgeKind, FileCfg, FuncSummaries, StmtKind};
use crate::constraint::{CompOp, ConditionExpr, ConstValue, Operand};
use crate::labels::{Cap, DataLabel};
use crate::ssa::ir::*;
use crate::ssa::{self, OptimizeResult};
use crate::state::symbol::SymbolInterner;
use crate::summary::GlobalSummaries;
use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};
use crate::symbol::{FuncKey, Lang};
use crate::symex::state::SymbolicState;
use crate::taint::domain::VarTaint;
use crate::taint::ssa_transfer::{SsaTaintEvent, SsaTaintState, SsaTaintTransfer};
use crate::utils::config::Config;
use axum::http::StatusCode;
use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoNodeReferences};
use serde::Serialize;
use std::collections::VecDeque;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
//  Line-number helper
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a byte offset to a 1-based line number.
fn byte_offset_to_line(bytes: &[u8], offset: usize) -> usize {
    let offset = offset.min(bytes.len());
    bytes[..offset].iter().filter(|&&b| b == b'\n').count() + 1
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cap → human-readable names
// ─────────────────────────────────────────────────────────────────────────────

fn cap_names(c: Cap) -> Vec<String> {
    let mut names = Vec::new();
    if c.contains(Cap::ENV_VAR) {
        names.push("ENV_VAR".into());
    }
    if c.contains(Cap::HTML_ESCAPE) {
        names.push("HTML_ESCAPE".into());
    }
    if c.contains(Cap::SHELL_ESCAPE) {
        names.push("SHELL_ESCAPE".into());
    }
    if c.contains(Cap::URL_ENCODE) {
        names.push("URL_ENCODE".into());
    }
    if c.contains(Cap::JSON_PARSE) {
        names.push("JSON_PARSE".into());
    }
    if c.contains(Cap::FILE_IO) {
        names.push("FILE_IO".into());
    }
    if c.contains(Cap::FMT_STRING) {
        names.push("FMT_STRING".into());
    }
    if c.contains(Cap::SQL_QUERY) {
        names.push("SQL_QUERY".into());
    }
    if c.contains(Cap::DESERIALIZE) {
        names.push("DESERIALIZE".into());
    }
    if c.contains(Cap::SSRF) {
        names.push("SSRF".into());
    }
    if c.contains(Cap::CODE_EXEC) {
        names.push("CODE_EXEC".into());
    }
    if c.contains(Cap::CRYPTO) {
        names.push("CRYPTO".into());
    }
    names
}

fn label_str(l: &DataLabel) -> String {
    match l {
        DataLabel::Source(c) => format!("Source({})", cap_names(*c).join("|")),
        DataLabel::Sanitizer(c) => format!("Sanitizer({})", cap_names(*c).join("|")),
        DataLabel::Sink(c) => format!("Sink({})", cap_names(*c).join("|")),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  View-model types
// ═════════════════════════════════════════════════════════════════════════════

// ── Function list ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FunctionInfo {
    pub name: String,
    pub namespace: String,
    pub param_count: usize,
    pub line: usize,
    pub source_caps: Vec<String>,
    pub sanitizer_caps: Vec<String>,
    pub sink_caps: Vec<String>,
}

// ── CFG ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CfgNodeView {
    pub id: usize,
    pub kind: String,
    pub span: (usize, usize),
    pub line: usize,
    pub defines: Option<String>,
    pub uses: Vec<String>,
    pub callee: Option<String>,
    pub labels: Vec<String>,
    pub condition_text: Option<String>,
    pub enclosing_func: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CfgEdgeView {
    pub source: usize,
    pub target: usize,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct CfgGraphView {
    pub nodes: Vec<CfgNodeView>,
    pub edges: Vec<CfgEdgeView>,
    pub entry: usize,
}

impl CfgGraphView {
    pub fn from_cfg(cfg: &Cfg, entry: NodeIndex, bytes: &[u8]) -> Self {
        let nodes = cfg
            .node_references()
            .map(|(idx, info)| CfgNodeView {
                id: idx.index(),
                kind: stmt_kind_str(info.kind),
                span: info.ast.span,
                line: byte_offset_to_line(bytes, info.ast.span.0),
                defines: info.taint.defines.clone(),
                uses: info.taint.uses.clone(),
                callee: info.call.callee.clone(),
                labels: info.taint.labels.iter().map(label_str).collect(),
                condition_text: info.condition_text.clone(),
                enclosing_func: info.ast.enclosing_func.clone(),
            })
            .collect();

        let edges = cfg
            .edge_references()
            .map(|e| CfgEdgeView {
                source: e.source().index(),
                target: e.target().index(),
                kind: edge_kind_str(*e.weight()),
            })
            .collect();

        CfgGraphView {
            nodes,
            edges,
            entry: entry.index(),
        }
    }

    /// Build a CFG view for a single function by looking up its dedicated
    /// `BodyCfg` in the `FileCfg`.  This replaces the old BFS-filter approach
    /// that walked the supergraph filtered by `enclosing_func`.
    pub fn from_cfg_function(file_cfg: &FileCfg, func_name: &str, bytes: &[u8]) -> Option<Self> {
        // Find the BodyCfg whose meta.name matches the requested function.
        let body = file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some(func_name))?;

        Some(Self::from_cfg(&body.graph, body.entry, bytes))
    }
}

fn stmt_kind_str(k: StmtKind) -> String {
    match k {
        StmtKind::Entry => "Entry",
        StmtKind::Exit => "Exit",
        StmtKind::Seq => "Seq",
        StmtKind::If => "If",
        StmtKind::Loop => "Loop",
        StmtKind::Break => "Break",
        StmtKind::Continue => "Continue",
        StmtKind::Return => "Return",
        StmtKind::Throw => "Throw",
        StmtKind::Call => "Call",
    }
    .into()
}

fn edge_kind_str(k: EdgeKind) -> String {
    match k {
        EdgeKind::Seq => "Seq",
        EdgeKind::True => "True",
        EdgeKind::False => "False",
        EdgeKind::Back => "Back",
        EdgeKind::Exception => "Exception",
    }
    .into()
}

// ── SSA ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SsaInstView {
    pub value: u32,
    pub op: String,
    pub operands: Vec<String>,
    pub var_name: Option<String>,
    pub span: (usize, usize),
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct SsaBlockView {
    pub id: u32,
    pub phis: Vec<SsaInstView>,
    pub body: Vec<SsaInstView>,
    pub terminator: String,
    pub preds: Vec<u32>,
    pub succs: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct SsaBodyView {
    pub blocks: Vec<SsaBlockView>,
    pub entry: u32,
    pub num_values: usize,
}

impl SsaBodyView {
    pub fn from_ssa(ssa: &SsaBody, bytes: &[u8]) -> Self {
        let blocks = ssa
            .blocks
            .iter()
            .map(|block| {
                let phis = block.phis.iter().map(|i| inst_view(i, bytes)).collect();
                let body = block.body.iter().map(|i| inst_view(i, bytes)).collect();
                let terminator = terminator_str(&block.terminator);
                SsaBlockView {
                    id: block.id.0,
                    phis,
                    body,
                    terminator,
                    preds: block.preds.iter().map(|b| b.0).collect(),
                    succs: block.succs.iter().map(|b| b.0).collect(),
                }
            })
            .collect();

        SsaBodyView {
            blocks,
            entry: ssa.entry.0,
            num_values: ssa.num_values(),
        }
    }
}

fn inst_view(inst: &SsaInst, bytes: &[u8]) -> SsaInstView {
    let (op, operands) = op_view(&inst.op);
    SsaInstView {
        value: inst.value.0,
        op,
        operands,
        var_name: inst.var_name.clone(),
        span: inst.span,
        line: byte_offset_to_line(bytes, inst.span.0),
    }
}

fn op_view(op: &SsaOp) -> (String, Vec<String>) {
    match op {
        SsaOp::Phi(operands) => {
            let ops: Vec<String> = operands
                .iter()
                .map(|(bid, val)| format!("B{}:v{}", bid.0, val.0))
                .collect();
            ("Phi".into(), ops)
        }
        SsaOp::Assign(uses) => {
            let ops: Vec<String> = uses.iter().map(|v| format!("v{}", v.0)).collect();
            ("Assign".into(), ops)
        }
        SsaOp::Call {
            callee,
            args,
            receiver,
        } => {
            let mut ops = Vec::new();
            if let Some(rv) = receiver {
                ops.push(format!("recv=v{}", rv.0));
            }
            ops.push(format!("callee={}", callee));
            for (i, arg) in args.iter().enumerate() {
                let vs: Vec<String> = arg.iter().map(|v| format!("v{}", v.0)).collect();
                ops.push(format!("arg{}=[{}]", i, vs.join(",")));
            }
            ("Call".into(), ops)
        }
        SsaOp::Source => ("Source".into(), vec![]),
        SsaOp::Const(text) => {
            let ops = text.iter().cloned().collect();
            ("Const".into(), ops)
        }
        SsaOp::Param { index } => ("Param".into(), vec![format!("{}", index)]),
        SsaOp::SelfParam => ("SelfParam".into(), vec![]),
        SsaOp::CatchParam => ("CatchParam".into(), vec![]),
        SsaOp::Nop => ("Nop".into(), vec![]),
    }
}

fn terminator_str(t: &Terminator) -> String {
    match t {
        Terminator::Goto(bid) => format!("goto B{}", bid.0),
        Terminator::Branch {
            true_blk,
            false_blk,
            condition,
            ..
        } => {
            let cond_str = condition
                .as_ref()
                .map(|c| format!("{:?}", c))
                .unwrap_or_else(|| "?".into());
            format!("branch {} -> B{}, B{}", cond_str, true_blk.0, false_blk.0)
        }
        Terminator::Return(v) => match v {
            Some(val) => format!("return v{}", val.0),
            None => "return".into(),
        },
        Terminator::Unreachable => "unreachable".into(),
    }
}

// ── Taint ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TaintValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub caps: Vec<String>,
    pub uses_summary: bool,
}

#[derive(Debug, Serialize)]
pub struct TaintBlockStateView {
    pub block_id: u32,
    pub values: Vec<TaintValueView>,
    pub validated_must: u64,
    pub validated_may: u64,
}

#[derive(Debug, Serialize)]
pub struct TaintEventView {
    pub sink_node: usize,
    pub sink_caps: Vec<String>,
    pub tainted_values: Vec<TaintValueView>,
    pub all_validated: bool,
    pub uses_summary: bool,
}

#[derive(Debug, Serialize)]
pub struct TaintAnalysisView {
    pub block_states: Vec<TaintBlockStateView>,
    pub events: Vec<TaintEventView>,
    /// Whether cross-file global summaries were available from DB.
    pub cross_file_context: bool,
    /// Whether SSA-level summaries were loaded (subset of cross-file context).
    pub ssa_summaries_available: bool,
}

impl TaintAnalysisView {
    pub fn from_results(
        events: &[SsaTaintEvent],
        block_states: &[Option<SsaTaintState>],
        ssa: &SsaBody,
        cross_file_context: bool,
        ssa_summaries_available: bool,
    ) -> Self {
        let block_states_view: Vec<TaintBlockStateView> = block_states
            .iter()
            .enumerate()
            .filter_map(|(i, state_opt)| {
                let state = state_opt.as_ref()?;
                let values: Vec<TaintValueView> = state
                    .values
                    .iter()
                    .map(|(sv, taint)| taint_value_view(*sv, taint, ssa))
                    .collect();
                Some(TaintBlockStateView {
                    block_id: i as u32,
                    values,
                    validated_must: state.validated_must.bits(),
                    validated_may: state.validated_may.bits(),
                })
            })
            .collect();

        let events_view: Vec<TaintEventView> = events
            .iter()
            .map(|e| {
                let tainted_values: Vec<TaintValueView> = e
                    .tainted_values
                    .iter()
                    .map(|(sv, caps, _origins)| TaintValueView {
                        ssa_value: sv.0,
                        var_name: ssa
                            .value_defs
                            .get(sv.0 as usize)
                            .and_then(|d| d.var_name.clone()),
                        caps: cap_names(*caps),
                        uses_summary: false,
                    })
                    .collect();

                TaintEventView {
                    sink_node: e.sink_node.index(),
                    sink_caps: cap_names(e.sink_caps),
                    tainted_values,
                    all_validated: e.all_validated,
                    uses_summary: e.uses_summary,
                }
            })
            .collect();

        TaintAnalysisView {
            block_states: block_states_view,
            events: events_view,
            cross_file_context,
            ssa_summaries_available,
        }
    }
}

fn taint_value_view(sv: SsaValue, taint: &VarTaint, ssa: &SsaBody) -> TaintValueView {
    TaintValueView {
        ssa_value: sv.0,
        var_name: ssa
            .value_defs
            .get(sv.0 as usize)
            .and_then(|d| d.var_name.clone()),
        caps: cap_names(taint.caps),
        uses_summary: taint.uses_summary,
    }
}

// ── Abstract Interpretation ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AbstractValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub interval_lo: Option<i64>,
    pub interval_hi: Option<i64>,
    pub string_prefix: Option<String>,
    pub string_suffix: Option<String>,
    pub known_zero: u64,
    pub known_one: u64,
}

#[derive(Debug, Serialize)]
pub struct AbstractBlockView {
    pub block_id: u32,
    pub values: Vec<AbstractValueView>,
}

#[derive(Debug, Serialize)]
pub struct TypeFactView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub type_kind: String,
    pub nullable: bool,
}

#[derive(Debug, Serialize)]
pub struct ConstValueViewEntry {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct AbstractInterpView {
    pub blocks: Vec<AbstractBlockView>,
    pub type_facts: Vec<TypeFactView>,
    pub const_values: Vec<ConstValueViewEntry>,
}

impl AbstractInterpView {
    pub fn from_taint_states(
        block_states: &[Option<SsaTaintState>],
        ssa: &SsaBody,
        opt: &OptimizeResult,
    ) -> Self {
        let blocks: Vec<AbstractBlockView> = block_states
            .iter()
            .enumerate()
            .filter_map(|(i, state_opt)| {
                let state = state_opt.as_ref()?;
                let abs_state = state.abstract_state.as_ref()?;
                let values: Vec<AbstractValueView> = (0..ssa.num_values() as u32)
                    .filter_map(|v| {
                        let av = abs_state.get(SsaValue(v));
                        if av.is_top() {
                            return None;
                        }
                        Some(AbstractValueView {
                            ssa_value: v,
                            var_name: ssa
                                .value_defs
                                .get(v as usize)
                                .and_then(|d| d.var_name.clone()),
                            interval_lo: av.interval.lo,
                            interval_hi: av.interval.hi,
                            string_prefix: av.string.prefix.clone(),
                            string_suffix: av.string.suffix.clone(),
                            known_zero: av.bits.known_zero,
                            known_one: av.bits.known_one,
                        })
                    })
                    .collect();

                if values.is_empty() {
                    return None;
                }

                Some(AbstractBlockView {
                    block_id: i as u32,
                    values,
                })
            })
            .collect();

        // Type facts from optimization pass
        let mut type_facts: Vec<TypeFactView> = opt
            .type_facts
            .facts
            .iter()
            .filter(|(_, tf)| !matches!(tf.kind, crate::ssa::type_facts::TypeKind::Unknown))
            .map(|(sv, tf)| TypeFactView {
                ssa_value: sv.0,
                var_name: ssa
                    .value_defs
                    .get(sv.0 as usize)
                    .and_then(|d| d.var_name.clone()),
                type_kind: format!("{:?}", tf.kind),
                nullable: tf.nullable,
            })
            .collect();
        type_facts.sort_by_key(|v| v.ssa_value);

        // Const values from constant propagation
        let mut const_values: Vec<ConstValueViewEntry> = opt
            .const_values
            .iter()
            .filter(|(_, cl)| {
                !matches!(
                    cl,
                    crate::ssa::const_prop::ConstLattice::Top
                        | crate::ssa::const_prop::ConstLattice::Varying
                )
            })
            .map(|(sv, cl)| {
                let value = match cl {
                    crate::ssa::const_prop::ConstLattice::Str(s) => format!("\"{}\"", s),
                    crate::ssa::const_prop::ConstLattice::Int(n) => format!("{}", n),
                    crate::ssa::const_prop::ConstLattice::Bool(b) => format!("{}", b),
                    crate::ssa::const_prop::ConstLattice::Null => "null".into(),
                    _ => unreachable!(),
                };
                ConstValueViewEntry {
                    ssa_value: sv.0,
                    var_name: ssa
                        .value_defs
                        .get(sv.0 as usize)
                        .and_then(|d| d.var_name.clone()),
                    value,
                }
            })
            .collect();
        const_values.sort_by_key(|v| v.ssa_value);

        AbstractInterpView {
            blocks,
            type_facts,
            const_values,
        }
    }
}

// ── Symbolic Execution ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SymexValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub expression: String,
}

#[derive(Debug, Serialize)]
pub struct PathConstraintView {
    pub block: u32,
    pub condition: String,
    pub polarity: bool,
}

#[derive(Debug, Serialize)]
pub struct SymexView {
    pub values: Vec<SymexValueView>,
    pub path_constraints: Vec<PathConstraintView>,
    pub tainted_roots: Vec<u32>,
}

impl SymexView {
    pub fn from_symbolic_state(state: &SymbolicState, ssa: &SsaBody) -> Self {
        let mut values: Vec<SymexValueView> = state
            .iter_values()
            .map(|(&v, sym)| SymexValueView {
                ssa_value: v.0,
                var_name: ssa
                    .value_defs
                    .get(v.0 as usize)
                    .and_then(|d| d.var_name.clone()),
                expression: format!("{}", sym),
            })
            .collect();
        values.sort_by_key(|v| v.ssa_value);

        let path_constraints = state
            .path_constraints()
            .iter()
            .map(|pc| PathConstraintView {
                block: pc.block.0,
                condition: format_condition_expr(&pc.condition),
                polarity: pc.polarity,
            })
            .collect();

        let mut tainted_roots: Vec<u32> = state.tainted_values().iter().map(|v| v.0).collect();
        tainted_roots.sort();

        SymexView {
            values,
            path_constraints,
            tainted_roots,
        }
    }
}

// ── Call Graph ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CallGraphNodeView {
    pub id: usize,
    pub name: String,
    pub file: String,
    pub lang: String,
    pub namespace: String,
    pub arity: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CallGraphEdgeView {
    pub source: usize,
    pub target: usize,
    pub call_site: String,
}

#[derive(Debug, Serialize)]
pub struct CallGraphView {
    pub nodes: Vec<CallGraphNodeView>,
    pub edges: Vec<CallGraphEdgeView>,
    pub sccs: Vec<Vec<usize>>,
    pub unresolved_count: usize,
    pub ambiguous_count: usize,
}

impl CallGraphView {
    pub fn from_call_graph(cg: &CallGraph, analysis: &CallGraphAnalysis) -> Self {
        let nodes: Vec<CallGraphNodeView> = cg
            .graph
            .node_references()
            .map(|(idx, fk)| CallGraphNodeView {
                id: idx.index(),
                name: fk.name.clone(),
                file: fk.namespace.clone(),
                lang: format!("{:?}", fk.lang),
                namespace: fk.namespace.clone(),
                arity: fk.arity,
            })
            .collect();

        let edges: Vec<CallGraphEdgeView> = cg
            .graph
            .edge_references()
            .map(|e| CallGraphEdgeView {
                source: e.source().index(),
                target: e.target().index(),
                call_site: e.weight().call_site.clone(),
            })
            .collect();

        let sccs: Vec<Vec<usize>> = analysis
            .sccs
            .iter()
            .filter(|scc| scc.len() > 1) // Only show non-trivial SCCs
            .map(|scc| scc.iter().map(|n| n.index()).collect())
            .collect();

        CallGraphView {
            nodes,
            edges,
            sccs,
            unresolved_count: cg.unresolved_not_found.len(),
            ambiguous_count: cg.unresolved_ambiguous.len(),
        }
    }
}

// ── Summaries ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FuncSummaryView {
    pub name: String,
    pub file_path: String,
    pub lang: String,
    pub namespace: String,
    pub arity: Option<usize>,
    pub param_count: usize,
    pub source_caps: Vec<String>,
    pub sanitizer_caps: Vec<String>,
    pub sink_caps: Vec<String>,
    pub propagates_taint: bool,
    pub propagating_params: Vec<usize>,
    pub tainted_sink_params: Vec<usize>,
    pub callees: Vec<CalleeSiteView>,
    pub ssa_summary: Option<SsaSummaryView>,
}

#[derive(Debug, Serialize)]
pub struct CalleeSiteView {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arity: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub ordinal: u32,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Serialize)]
pub struct SsaSummaryView {
    pub param_to_return: Vec<ParamReturnView>,
    pub param_to_sink: Vec<ParamSinkView>,
    pub source_caps: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ParamReturnView {
    pub param_index: usize,
    pub transform: String,
}

#[derive(Debug, Serialize)]
pub struct ParamSinkView {
    pub param_index: usize,
    pub sink_caps: Vec<String>,
}

impl FuncSummaryView {
    pub fn from_global(
        key: &FuncKey,
        summary: &crate::summary::FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
    ) -> Self {
        let ssa_view = ssa_summary.map(|ss| SsaSummaryView {
            param_to_return: ss
                .param_to_return
                .iter()
                .map(|(idx, transform)| ParamReturnView {
                    param_index: *idx,
                    transform: transform_str(transform),
                })
                .collect(),
            param_to_sink: ss
                .param_to_sink_caps()
                .into_iter()
                .map(|(idx, caps)| ParamSinkView {
                    param_index: idx,
                    sink_caps: cap_names(caps),
                })
                .collect(),
            source_caps: cap_names(ss.source_caps),
        });

        FuncSummaryView {
            name: key.name.clone(),
            file_path: summary.file_path.clone(),
            lang: format!("{:?}", key.lang),
            namespace: key.namespace.clone(),
            arity: key.arity,
            param_count: summary.param_count,
            source_caps: cap_names(Cap::from_bits_truncate(summary.source_caps)),
            sanitizer_caps: cap_names(Cap::from_bits_truncate(summary.sanitizer_caps)),
            sink_caps: cap_names(Cap::from_bits_truncate(summary.sink_caps)),
            propagates_taint: summary.propagates_taint,
            propagating_params: summary.propagating_params.clone(),
            tainted_sink_params: summary.tainted_sink_params.clone(),
            callees: summary
                .callees
                .iter()
                .map(|c| CalleeSiteView {
                    name: c.name.clone(),
                    arity: c.arity,
                    receiver: c.receiver.clone(),
                    qualifier: c.qualifier.clone(),
                    ordinal: c.ordinal,
                })
                .collect(),
            ssa_summary: ssa_view,
        }
    }
}

fn transform_str(t: &TaintTransform) -> String {
    match t {
        TaintTransform::Identity => "Identity".into(),
        TaintTransform::StripBits(caps) => format!("StripBits({})", cap_names(*caps).join("|")),
        TaintTransform::AddBits(caps) => format!("AddBits({})", cap_names(*caps).join("|")),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  On-demand analysis pipeline
// ═════════════════════════════════════════════════════════════════════════════

/// Result of parsing + CFG construction for a single file.
pub struct FileAnalysis {
    pub file_cfg: crate::cfg::FileCfg,
    pub lang: Lang,
    pub bytes: Vec<u8>,
}

impl FileAnalysis {
    /// Top-level body's graph (backward-compatible accessor).
    pub fn cfg(&self) -> &Cfg {
        &self.file_cfg.toplevel().graph
    }
    pub fn entry(&self) -> NodeIndex {
        self.file_cfg.toplevel().entry
    }
    pub fn summaries(&self) -> &FuncSummaries {
        &self.file_cfg.summaries
    }
}

/// Parse a file and build its CFG. Returns an error status code on failure.
pub fn analyse_file(file_path: &Path, config: &Config) -> Result<FileAnalysis, StatusCode> {
    let result =
        build_cfg_for_file(file_path, config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some((file_cfg, lang)) => {
            let bytes = std::fs::read(file_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(FileAnalysis {
                file_cfg,
                lang,
                bytes,
            })
        }
        None => Err(StatusCode::BAD_REQUEST),
    }
}

/// Extract function info list from local summaries.
pub fn function_list(analysis: &FileAnalysis) -> Vec<FunctionInfo> {
    analysis
        .summaries()
        .iter()
        .map(|(key, summary)| FunctionInfo {
            name: key.name.clone(),
            namespace: key.namespace.clone(),
            param_count: summary.param_count,
            line: byte_offset_to_line(&analysis.bytes, analysis.cfg()[summary.entry].ast.span.0),
            source_caps: cap_names(summary.source_caps),
            sanitizer_caps: cap_names(summary.sanitizer_caps),
            sink_caps: cap_names(summary.sink_caps),
        })
        .collect()
}

/// Lower a single function to SSA and optimize it.
pub fn analyse_function_ssa(
    analysis: &FileAnalysis,
    func_name: &str,
) -> Result<(SsaBody, OptimizeResult), StatusCode> {
    // Find the function body by name from the per-body CFGs.
    let body = analysis
        .file_cfg
        .bodies
        .iter()
        .find(|b| b.meta.name.as_deref() == Some(func_name))
        .ok_or(StatusCode::NOT_FOUND)?;

    let ssa_result = crate::ssa::lower::lower_to_ssa_with_params(
        &body.graph,
        body.entry,
        Some(func_name),
        false,
        &body.meta.params,
    );

    let mut ssa = ssa_result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let opt = ssa::optimize_ssa(&mut ssa, &body.graph, Some(analysis.lang));

    Ok((ssa, opt))
}

/// Run taint analysis on a function's SSA body.
pub fn analyse_function_taint(
    ssa: &SsaBody,
    cfg: &Cfg,
    lang: Lang,
    summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    opt: &OptimizeResult,
) -> (
    Vec<SsaTaintEvent>,
    Vec<Option<SsaTaintState>>,
    Vec<Option<SsaTaintState>>,
) {
    let interner = SymbolInterner::default();
    let empty_interop = vec![];

    let transfer = SsaTaintTransfer {
        lang,
        namespace: "",
        interner: &interner,
        local_summaries: summaries,
        global_summaries,
        interop_edges: &empty_interop,
        global_seed: None,
        const_values: Some(&opt.const_values),
        type_facts: Some(&opt.type_facts),
        ssa_summaries: None,
        extra_labels: None,
        callee_bodies: None,
        inline_cache: None,
        base_aliases: Some(&opt.alias_result),
        context_depth: 0,
        callback_bindings: None,
        points_to: Some(&opt.points_to),
        dynamic_pts: None,
        import_bindings: None,
        promisify_aliases: None,
        module_aliases: if opt.module_aliases.is_empty() {
            None
        } else {
            Some(&opt.module_aliases)
        },
        static_map: None,
        auto_seed_handler_params: matches!(lang, Lang::JavaScript | Lang::TypeScript),
        cross_file_bodies: global_summaries.and_then(|gs| gs.bodies_by_key()),
    };

    crate::taint::ssa_transfer::run_ssa_taint_full_with_exits(ssa, cfg, &transfer)
}

/// Run symbolic execution on a function's SSA body and return the final state.
pub fn analyse_function_symex(
    ssa: &SsaBody,
    cfg: &Cfg,
    lang: Lang,
    opt: &OptimizeResult,
    global_summaries: Option<&GlobalSummaries>,
) -> SymbolicState {
    let mut state = SymbolicState::new();
    state.seed_from_const_values(&opt.const_values);

    let summary_ctx = global_summaries.map(|gs| crate::symex::transfer::SymexSummaryCtx {
        global_summaries: gs,
        lang,
        namespace: "",
        type_facts: Some(&opt.type_facts),
    });
    let heap_ctx = crate::symex::transfer::SymexHeapCtx {
        points_to: &opt.points_to,
        ssa,
        lang,
        const_values: &opt.const_values,
    };

    // BFS over blocks from entry to cover all reachable blocks.
    let mut visited = std::collections::HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(ssa.entry);
    visited.insert(ssa.entry);

    while let Some(bid) = queue.pop_front() {
        let block = ssa.block(bid);
        crate::symex::transfer::transfer_block(
            &mut state,
            block,
            cfg,
            ssa,
            summary_ctx.as_ref(),
            Some(&heap_ctx),
            None, // no interproc context
            Some(lang),
        );
        for &succ in &block.succs {
            if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    state
}

/// Extract `GlobalSummaries` from a single file on-demand (no DB required).
pub fn analyse_file_summaries(
    file_path: &Path,
    config: &Config,
) -> Result<GlobalSummaries, StatusCode> {
    let bytes = std::fs::read(file_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (func_summaries, ssa_rows, _ssa_bodies) =
        crate::ast::extract_all_summaries_from_bytes(&bytes, file_path, config, None)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut global = crate::summary::merge_summaries(func_summaries, None);

    for (key, ssa_summary) in ssa_rows {
        global.insert_ssa(key, ssa_summary);
    }

    Ok(global)
}

/// Format a `ConditionExpr` as a human-readable string.
fn format_condition_expr(cond: &ConditionExpr) -> String {
    match cond {
        ConditionExpr::Comparison { lhs, op, rhs } => {
            let op_str = match op {
                CompOp::Eq => "==",
                CompOp::Neq => "!=",
                CompOp::Lt => "<",
                CompOp::Gt => ">",
                CompOp::Le => "<=",
                CompOp::Ge => ">=",
            };
            format!("{} {} {}", format_operand(lhs), op_str, format_operand(rhs))
        }
        ConditionExpr::NullCheck { var, is_null } => {
            if *is_null {
                format!("v{} == null", var.0)
            } else {
                format!("v{} != null", var.0)
            }
        }
        ConditionExpr::TypeCheck {
            var,
            type_name,
            positive,
        } => {
            if *positive {
                format!("typeof v{} === \"{}\"", var.0, type_name)
            } else {
                format!("typeof v{} !== \"{}\"", var.0, type_name)
            }
        }
        ConditionExpr::BoolTest { var } => format!("v{}", var.0),
        ConditionExpr::Unknown => "?".to_string(),
    }
}

fn format_operand(op: &Operand) -> String {
    match op {
        Operand::Value(v) => format!("v{}", v.0),
        Operand::Const(c) => match c {
            ConstValue::Int(n) => format!("{}", n),
            ConstValue::Str(s) => format!("\"{}\"", s),
            ConstValue::Bool(b) => format!("{}", b),
            ConstValue::Null => "null".to_string(),
        },
        Operand::Unknown => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::Config;

    #[test]
    fn taint_debug_uses_exit_states_for_single_block_flows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.js");
        std::fs::write(
            &path,
            r#"
function demo() {
  const cmd = process.env.CRON_JOB_CMD;
  eval(cmd);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt) =
            analyse_function_ssa(&analysis, "demo").expect("function should lower to SSA");
        let body = analysis
            .file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some("demo"))
            .expect("should find demo function body");
        let (events, _entry_states, exit_states) = analyse_function_taint(
            &ssa,
            &body.graph,
            analysis.lang,
            analysis.summaries(),
            None,
            &opt,
        );

        assert!(
            !events.is_empty(),
            "expected the test fixture to produce at least one taint event"
        );
        assert!(
            exit_states
                .iter()
                .flatten()
                .any(|state| !state.values.is_empty()),
            "exit-state debug view should show tainted SSA values even for single-block functions"
        );

        let view = TaintAnalysisView::from_results(&events, &exit_states, &ssa, false, false);
        assert!(
            view.block_states
                .iter()
                .any(|state| !state.values.is_empty()),
            "serialized debug taint view should expose the populated exit states"
        );
    }

    #[test]
    fn taint_view_without_global_summaries_marks_no_cross_file_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.js");
        std::fs::write(
            &path,
            r#"
function sink() {
  const x = process.env.SECRET;
  eval(x);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt) =
            analyse_function_ssa(&analysis, "sink").expect("function should lower to SSA");
        let body = analysis
            .file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some("sink"))
            .expect("should find sink function body");
        let (events, _entry_states, exit_states) = analyse_function_taint(
            &ssa,
            &body.graph,
            analysis.lang,
            analysis.summaries(),
            None, // no global summaries
            &opt,
        );

        let view = TaintAnalysisView::from_results(&events, &exit_states, &ssa, false, false);
        assert!(!view.cross_file_context);
        assert!(!view.ssa_summaries_available);
        // The local analysis should still find the taint event
        assert!(
            !view.events.is_empty(),
            "local taint should still find events"
        );
    }

    #[test]
    fn taint_view_with_global_summaries_marks_cross_file_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("consumer.js");
        std::fs::write(
            &path,
            r#"
function consume() {
  const x = process.env.SECRET;
  eval(x);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt) =
            analyse_function_ssa(&analysis, "consume").expect("function should lower to SSA");
        let body = analysis
            .file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some("consume"))
            .expect("should find consume function body");

        // Create non-empty global summaries to simulate having run a scan
        let mut global = crate::summary::GlobalSummaries::default();
        let key = crate::symbol::FuncKey {
            lang: crate::symbol::Lang::JavaScript,
            namespace: "src/helper.js".into(),
            name: "getInput".into(),
            arity: Some(0),
            ..Default::default()
        };
        global.insert_ssa(
            key,
            crate::summary::ssa_summary::SsaFuncSummary {
                param_to_return: vec![],
                param_to_sink: vec![],
                source_caps: crate::labels::Cap::all(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
            },
        );

        let cross_file = !global.is_empty();
        let ssa_avail = !global.snapshot_ssa().is_empty();

        let (events, _entry_states, exit_states) = analyse_function_taint(
            &ssa,
            &body.graph,
            analysis.lang,
            analysis.summaries(),
            Some(&global),
            &opt,
        );

        let view =
            TaintAnalysisView::from_results(&events, &exit_states, &ssa, cross_file, ssa_avail);
        assert!(view.cross_file_context);
        assert!(view.ssa_summaries_available);
    }

    #[test]
    fn cfg_function_view_does_not_bleed_into_sibling_functions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.js");
        std::fs::write(
            &path,
            r#"
const db = require("../db");

async function writeAuditLog({ actorId, action, targetType, targetId, metadata }) {
  await db.query(
    `
      INSERT INTO audit_logs (actor_id, action, target_type, target_id, metadata)
      VALUES ($1, $2, $3, $4, $5)
    `,
    [actorId, action, targetType, targetId, metadata]
  );
}

async function recentAuditLogs() {
  const result = await db.query(
    `
      SELECT a.*, u.full_name AS actor_name
      FROM audit_logs a
      LEFT JOIN users u ON u.id = a.actor_id
      ORDER BY a.created_at DESC
      LIMIT 20
    `
  );
  return result.rows;
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let view =
            CfgGraphView::from_cfg_function(&analysis.file_cfg, "writeAuditLog", &analysis.bytes)
                .expect("function view should exist");

        assert!(
            !view.nodes.is_empty(),
            "expected writeAuditLog to produce CFG nodes"
        );
        assert!(
            view.nodes
                .iter()
                .all(|node| node.enclosing_func.as_deref() == Some("writeAuditLog")),
            "function-scoped CFG view should only contain writeAuditLog nodes"
        );
        assert!(
            view.nodes.iter().any(|node| node.line == 4),
            "expected function entry/header for writeAuditLog"
        );
        assert!(
            view.nodes.iter().any(|node| node.line == 5),
            "expected db.query call inside writeAuditLog"
        );
        assert!(
            view.nodes.iter().all(|node| node.line < 13),
            "sibling function nodes should not appear in writeAuditLog view"
        );
    }
}
