//! Debug API route handlers.
//!
//! Provides endpoints for inspecting engine internals: CFG, SSA IR, taint
//! propagation, summaries, call graphs, abstract interpretation, and symbolic
//! execution.

use crate::server::app::AppState;
use crate::server::debug::{self, *};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/debug/functions", get(list_functions))
        .route("/debug/cfg", get(get_cfg))
        .route("/debug/ssa", get(get_ssa))
        .route("/debug/taint", get(get_taint))
        .route("/debug/summaries", get(get_summaries))
        .route("/debug/call-graph", get(get_call_graph))
        .route("/debug/abstract-interp", get(get_abstract_interp))
        .route("/debug/symex", get(get_symex))
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FileQuery {
    file: String,
}

#[derive(Debug, Deserialize)]
struct FileFunctionQuery {
    file: String,
    function: String,
}

#[derive(Debug, Deserialize)]
struct CallGraphQuery {
    scope: Option<String>,
    file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SummaryQuery {
    function: Option<String>,
    file: Option<String>,
}

// ── Path validation ──────────────────────────────────────────────────────────

fn validate_and_resolve(scan_root: &Path, file: &str) -> Result<std::path::PathBuf, StatusCode> {
    if file.contains("..") {
        return Err(StatusCode::FORBIDDEN);
    }
    let canonical_root =
        fs::canonicalize(scan_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let target = canonical_root.join(file);
    let canonical = fs::canonicalize(&target).map_err(|_| StatusCode::NOT_FOUND)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(canonical)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// GET /api/debug/functions?file=<path>
/// List functions available for debug inspection in a file.
async fn list_functions(
    State(state): State<AppState>,
    Query(q): Query<FileQuery>,
) -> Result<Json<Vec<FunctionInfo>>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let analysis = debug::analyse_file(&path, &config)?;
    Ok(Json(debug::function_list(&analysis)))
}

/// GET /api/debug/cfg?file=<path>&function=<name>
/// Return the CFG for a specific function as a graph JSON.
async fn get_cfg(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<CfgGraphView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let analysis = debug::analyse_file(&path, &config)?;

    let view =
        CfgGraphView::from_cfg_function(&analysis.cfg, &analysis.summaries, &q.function, &analysis.bytes)
            .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(view))
}

/// GET /api/debug/ssa?file=<path>&function=<name>
/// Return the SSA IR for a specific function.
async fn get_ssa(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<SsaBodyView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, _opt) = debug::analyse_function_ssa(&analysis, &q.function)?;
    Ok(Json(SsaBodyView::from_ssa(&ssa, &analysis.bytes)))
}

/// GET /api/debug/taint?file=<path>&function=<name>
/// Return taint analysis results for a specific function.
async fn get_taint(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<TaintAnalysisView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt) = debug::analyse_function_ssa(&analysis, &q.function)?;

    // Try to load global summaries from DB for cross-file context
    let global = load_global_summaries(&state);

    let (events, block_states) = debug::analyse_function_taint(
        &ssa,
        &analysis.cfg,
        analysis.lang,
        &analysis.summaries,
        global.as_ref(),
        &opt,
    );

    Ok(Json(TaintAnalysisView::from_results(
        &events,
        &block_states,
        &ssa,
    )))
}

/// GET /api/debug/abstract-interp?file=<path>&function=<name>
/// Return abstract interpretation state for a specific function.
async fn get_abstract_interp(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<AbstractInterpView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt) = debug::analyse_function_ssa(&analysis, &q.function)?;

    let global = load_global_summaries(&state);

    let (_events, block_states) = debug::analyse_function_taint(
        &ssa,
        &analysis.cfg,
        analysis.lang,
        &analysis.summaries,
        global.as_ref(),
        &opt,
    );

    Ok(Json(AbstractInterpView::from_taint_states(
        &block_states,
        &ssa,
        &opt,
    )))
}

/// GET /api/debug/summaries?file=<path>&function=<name>
/// Return interprocedural summaries.
async fn get_summaries(
    State(state): State<AppState>,
    Query(q): Query<SummaryQuery>,
) -> Result<Json<Vec<FuncSummaryView>>, StatusCode> {
    // Try DB first; fall back to on-demand single-file analysis
    let global = match load_global_summaries(&state) {
        Some(g) if !g.is_empty() => g,
        _ => {
            if let Some(ref file) = q.file {
                let path = validate_and_resolve(&state.scan_root, file)?;
                let config =
                    state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                debug::analyse_file_summaries(&path, &config)?
            } else {
                return Ok(Json(vec![]));
            }
        }
    };

    let views: Vec<FuncSummaryView> = global
        .iter()
        .filter(|(key, summary)| {
            let name_matches = q
                .function
                .as_ref()
                .map(|f| key.name == *f)
                .unwrap_or(true);
            let file_matches = q
                .file
                .as_ref()
                .map(|f| summary.file_path.contains(f.as_str()))
                .unwrap_or(true);
            name_matches && file_matches
        })
        .map(|(key, summary)| {
            let ssa_summary = global.get_ssa(key);
            FuncSummaryView::from_global(key, summary, ssa_summary)
        })
        .collect();

    Ok(Json(views))
}

/// GET /api/debug/call-graph?scope=file|project&file=<path>
/// Return the call graph.
async fn get_call_graph(
    State(state): State<AppState>,
    Query(q): Query<CallGraphQuery>,
) -> Result<Json<CallGraphView>, StatusCode> {
    let scope = q.scope.as_deref().unwrap_or("project");

    let global = if scope == "file" {
        // On-demand: parse the specified file and extract summaries
        let file = q.file.as_deref().ok_or(StatusCode::BAD_REQUEST)?;
        let path = validate_and_resolve(&state.scan_root, file)?;
        let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        debug::analyse_file_summaries(&path, &config)?
    } else {
        // Project scope: try DB, fall back to empty graph
        load_global_summaries(&state).unwrap_or_default()
    };

    let cg = crate::callgraph::build_call_graph(&global, &[]);
    let analysis = crate::callgraph::analyse(&cg);

    Ok(Json(CallGraphView::from_call_graph(&cg, &analysis)))
}

/// GET /api/debug/symex?file=<path>&function=<name>
/// Return symbolic execution state for a function.
async fn get_symex(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<SymexView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt) = debug::analyse_function_ssa(&analysis, &q.function)?;

    let global = load_global_summaries(&state);

    let sym_state = debug::analyse_function_symex(
        &ssa,
        &analysis.cfg,
        analysis.lang,
        &opt,
        global.as_ref(),
    );

    Ok(Json(SymexView::from_symbolic_state(&sym_state, &ssa)))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Load global summaries from DB if available.
fn load_global_summaries(state: &AppState) -> Option<crate::summary::GlobalSummaries> {
    let pool = state.db_pool.as_ref()?;
    let indexer = crate::database::index::Indexer::from_pool("", pool).ok()?;

    let func_summaries = indexer.load_all_summaries().ok()?;
    let ssa_rows = indexer.load_all_ssa_summaries().ok()?;

    let mut global = crate::summary::merge_summaries(func_summaries, None);
    for (_file_path, name, lang_str, arity, namespace, summary) in ssa_rows {
        let lang = crate::symbol::Lang::from_slug(&lang_str).unwrap_or(crate::symbol::Lang::C);
        let key = crate::symbol::FuncKey {
            lang,
            namespace,
            name,
            arity: Some(arity as usize),
        };
        global.insert_ssa(key, summary);
    }

    Some(global)
}
