use criterion::{Criterion, criterion_group, criterion_main};
use nyx_scanner::utils::Config;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

const FIXTURES: &str = "benches/fixtures";

fn bench_ast_only_scan(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Ast;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("ast_only_scan", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, None, Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_full_scan(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("full_scan", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();

            // Pass 1: extract summaries
            let mut all_sums = Vec::new();
            for path in &paths {
                if let Ok(sums) = nyx_scanner::ast::extract_summaries_from_file(path, &cfg) {
                    all_sums.extend(sums);
                }
            }
            let root_str = fixtures.to_string_lossy();
            let global = nyx_scanner::summary::merge_summaries(all_sums, Some(&root_str));

            // Pass 2: full analysis
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, Some(&global), Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_full_scan_with_state(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("full_scan_with_state", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();

            // Pass 1: extract summaries
            let mut all_sums = Vec::new();
            for path in &paths {
                if let Ok(sums) = nyx_scanner::ast::extract_summaries_from_file(path, &cfg) {
                    all_sums.extend(sums);
                }
            }
            let root_str = fixtures.to_string_lossy();
            let global = nyx_scanner::summary::merge_summaries(all_sums, Some(&root_str));

            // Pass 2: full analysis with state
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, Some(&global), Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_single_file_parse_and_cfg(c: &mut Criterion) {
    let fixture = Path::new(FIXTURES).join("sample.rs");
    let fixture = fixture.canonicalize().expect("sample.rs fixture");
    let cfg = Config::default();

    c.bench_function("single_file_parse_cfg", |b| {
        b.iter(|| {
            nyx_scanner::ast::extract_summaries_from_file(&fixture, &cfg)
                .expect("extract summaries")
        });
    });
}

fn bench_state_analysis_only(c: &mut Criterion) {
    let fixture = Path::new(FIXTURES)
        .join("state_bench.c")
        .canonicalize()
        .expect("state_bench.c fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;

    // Parse and build CFG once (outside benchmark loop)
    let (file_cfg, lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg)
        .expect("build cfg")
        .expect("supported language");
    let source_bytes = std::fs::read(&fixture).expect("read fixture");
    let top = file_cfg.toplevel();

    c.bench_function("state_analysis_only", |b| {
        b.iter(|| {
            nyx_scanner::state::run_state_analysis(
                &top.graph,
                top.entry,
                lang,
                &source_bytes,
                &file_cfg.summaries,
                None,
                true,
                &[],
                &[],
                &std::collections::HashSet::new(),
                None,
                None,
            )
        });
    });
}

fn bench_classify(c: &mut Criterion) {
    c.bench_function("classify_hit", |b| {
        b.iter(|| nyx_scanner::labels::classify("rust", "std::env::var", None));
    });

    c.bench_function("classify_miss", |b| {
        b.iter(|| nyx_scanner::labels::classify("rust", "some_random_function", None));
    });
}

/// Per-file fused analysis throughput on a realistic ~1.5k-line Go module
/// (gin context.go, ~147 fns).  Guards the
/// `ParsedFile::body_const_facts_cache` optimization that collapses the
/// 2-3× per-body re-lowering that previously dominated `analyse_file_fused`
/// (~14% of wall-clock on the gin-scan profile).  Regressions here mean
/// per-body work is being recomputed across passes again.
fn bench_analyse_file_fused_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    // One-shot diagnostic: count `build_body_const_facts` calls per fused
    // analysis so a regression that removes the per-file cache surfaces here
    // (expected ~148 calls on this fixture; pre-cache was ~444).
    nyx_scanner::cfg_analysis::BUILD_BODY_CONST_FACTS_CALLS
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");
    let calls = nyx_scanner::cfg_analysis::BUILD_BODY_CONST_FACTS_CALLS
        .load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("[diag] build_body_const_facts calls per analyse_file_fused: {calls}");

    c.bench_function("analyse_file_fused_large_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// Per-file `extract_authorization_model` throughput on the realistic
/// ~1.5k-line Go fixture (gin context.go).  Guards the
/// `extract_authorization_model` orchestrator hoist that pulled the
/// shared `collect_top_level_units` AST walk out of every supporting
/// extractor's `extract()` (one walk per file instead of one per
/// matching extractor).  On Go files both `EchoExtractor` and
/// `GinExtractor` match by default — pre-hoist this bench measured the
/// AST being walked twice; regressions here mean the hoist has been
/// broken or a new Go extractor was added that re-walks the tree.
fn bench_extract_authorization_model_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    let cfg = Config::default();
    let rules = nyx_scanner::auth_analysis::config::build_auth_rules(&cfg, "go");

    c.bench_function("extract_authorization_model_go", |b| {
        b.iter(|| {
            nyx_scanner::auth_analysis::extract::extract_authorization_model(
                "go",
                cfg.framework_ctx.as_ref(),
                &tree,
                &bytes,
                &fixture,
                &rules,
                None,
            )
        });
    });
}

/// Per-file shared-vs-double `extract_authorization_model` cost on a
/// realistic Go fixture (gin context.go).  Pre-fix
/// `analyse_file_fused` called `extract_authorization_model` twice per
/// file (once for diagnostics via `run_auth_analysis`, once for
/// per-file summary keying via `extract_auth_summaries_by_key`).  This
/// bench records the **shared-model path** only (extract once, derive
/// both summaries + diagnostics) so a regression that re-introduces
/// the double-call surfaces as a ≥1.7× slowdown here.
fn bench_extract_authorization_model_shared_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    let cfg = Config::default();
    let rules = nyx_scanner::auth_analysis::config::build_auth_rules(&cfg, "go");

    c.bench_function("extract_authorization_model_shared_go", |b| {
        b.iter(|| {
            // Mirror `analyse_file_fused`: extract once, derive both
            // per-file summaries (cheap iter over units) AND run the
            // full diagnostic pipeline against the same model.
            let model = nyx_scanner::auth_analysis::extract::extract_authorization_model(
                "go",
                cfg.framework_ctx.as_ref(),
                &tree,
                &bytes,
                &fixture,
                &rules,
                None,
            );
            let summaries = nyx_scanner::auth_analysis::extract_auth_summaries_from_model(
                &model, "go", &fixture, None,
            );
            let diags = nyx_scanner::auth_analysis::run_auth_analysis_with_model(
                model, &tree, "go", &fixture, &rules, None, None, None,
            );
            (summaries, diags)
        });
    });
}

/// Per-file `collect_top_level_units` cost on a realistic Go fixture
/// (gin context.go, ~147 functions).  Targets the inner per-function
/// AST-walk path: `collect_top_level_units` →
/// `build_function_unit_with_meta` → `collect_unit_state` (recursive
/// per-AST-node walk that emits per-node value-refs).
///
/// Pre-fix (2026-05-04 perfhunt session-0009) `collect_unit_state`
/// called `extract_value_refs(node, bytes)` at every AST node, and that
/// helper recursively walked the node's full subtree.  Combined with
/// the recursion below, every descendant got walked once for each of
/// its ancestors — total work O(N²) per function body.  The fix
/// replaced that call with an O(1)-per-node `append_shallow_value_ref`
/// helper.  A regression that re-introduces the deep walk surfaces
/// here as a ≥2× slowdown.
fn bench_collect_top_level_units_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    let cfg = Config::default();
    let rules = nyx_scanner::auth_analysis::config::build_auth_rules(&cfg, "go");

    c.bench_function("collect_top_level_units_go", |b| {
        b.iter(|| {
            let mut model = nyx_scanner::auth_analysis::model::AuthorizationModel::default();
            nyx_scanner::auth_analysis::extract::common::collect_top_level_units(
                tree.root_node(),
                &bytes,
                &rules,
                &mut model,
            );
            model
        });
    });
}

/// SCCP throughput on every SSA body lowered from the gin context.go
/// fixture.  Targets `nyx_scanner::ssa::const_prop::const_propagate`
/// directly, isolating it from the surrounding `optimize_ssa` pass and
/// the full-fused per-file analysis.
///
/// Pre-fix (2026-05-04 perfhunt) `const_propagate` stored its lattice in
/// `HashMap<SsaValue, ConstLattice>` and walked
/// `inst_uses(inst).contains(&val)` for every block re-evaluation in the
/// SSA worklist — both shapes paid `SipHash` cost on every operand, and
/// the `inst_uses` factory allocated a fresh `Vec<SsaValue>` on every
/// call.  Switching the lattice + executable-edge maps to dense
/// `Vec`-indexed storage and the use-check to a zero-allocation
/// predicate cut `const_propagate` self-time roughly in half on the
/// large-Go fixture.  A regression that re-introduces the hash-keyed
/// inner loop will surface here as a ≥1.4× slowdown.
fn bench_const_propagate_large_go(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");

    // Lower every body once outside the bench loop so we measure only
    // SCCP cost.  The collected `(SsaBody, Cfg)` pairs are the input to
    // the inner loop.
    let mut bodies: Vec<ssa::ir::SsaBody> = Vec::new();
    for body in &file_cfg.bodies {
        // Use `body.meta.name` as the scope filter so the SSA lowering
        // pulls only this function's nodes; `scope_all=true` is reserved
        // for the synthetic top-level body where `name` is None.
        let scope = body.meta.name.as_deref();
        let scope_all = scope.is_none();
        match ssa::lower_to_ssa(&body.graph, body.entry, scope, scope_all) {
            Ok(ssa_body) => bodies.push(ssa_body),
            Err(_) => continue,
        }
    }
    eprintln!(
        "[diag] const_propagate bench: {} bodies lowered",
        bodies.len()
    );

    c.bench_function("const_propagate_large_go", |b| {
        b.iter(|| {
            let mut total_values = 0usize;
            for body in &bodies {
                let result = ssa::const_prop::const_propagate(body);
                total_values += result.values.len();
            }
            total_values
        });
    });
}

/// `GlobalSummaries::lookup_same_lang` cost on a populated index.  The
/// inner loop hashes `(Lang, String)` once per call, then `FuncKey` once
/// per candidate via `by_key.get(k)`.  Pre-fix the four secondary
/// indices used `std::collections::HashMap` (SipHash).  Post-fix
/// (2026-05-04 perfhunt session-0015) they use `rustc_hash::FxHashMap`,
/// trading DoS hardening (irrelevant for in-process program-keyed
/// indices) for ~5x faster hashing on the 30+ byte 3-string `FuncKey`
/// hash workload.  A regression that re-introduces SipHash would
/// surface here as a ≥3x slowdown.
fn bench_global_summaries_lookup_same_lang_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg = Config::default();

    let summaries =
        nyx_scanner::ast::extract_summaries_from_file(&fixture, &cfg).expect("extract summaries");
    let names: Vec<String> = summaries.iter().map(|s| s.name.clone()).collect();
    let global = nyx_scanner::summary::merge_summaries(summaries, None);
    let lang = nyx_scanner::symbol::Lang::Go;

    eprintln!("[diag] lookup_same_lang bench: {} names", names.len());

    c.bench_function("global_summaries_lookup_same_lang_go", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for name in &names {
                total += global.lookup_same_lang(lang, name).len();
            }
            total
        });
    });
}

/// Callee-resolution throughput on a high-function-count, high-call-density
/// Go file (`callee_resolve_stress.go`: ~400 functions, ~1680 intra-file
/// call sites).  Guards the per-file [`FuncNameIndex`] that replaced the
/// linear `local_summaries.keys()` scans inside `resolve_callee_full`
/// (`caller_container_for`, `resolve_local_func_key_query`,
/// `resolve_local_func_key`, and the ambiguity probe).  Before the index
/// each of the ~1680 call-site resolutions scanned all ~400 functions
/// (`O(C·F)` ≈ `O(F²)` per file, run once per taint pass — summary
/// extraction, the main analysis, child-sink augmentation).  A regression
/// that reintroduces the linear scan surfaces here as a large slowdown
/// that grows quadratically with the fixture's function count.
fn bench_taint_callee_resolve_stress_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/callee_resolve_stress.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");

    c.bench_function("taint_callee_resolve_stress_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// Stresses the SSA taint worklist's state-clone path
/// (`run_ssa_taint_internal` in `src/taint/ssa_transfer/mod.rs`).  The
/// fixture is branch- and constraint-dense: every function threads a
/// tainted source through a long chain of `if`/`else` guards plus a loop,
/// so `SsaTaintState::path_env` is non-empty across many basic blocks.  The
/// worklist clones the full state on every block pop, exit store, and
/// per-successor push; before the `Arc`-COW change each clone deep-copied
/// the `PathEnv` (`UnionFind` + five `SmallVec`s — ≈3.9% of static CPU on
/// Go corpora).  After the change those clones are refcount bumps and the
/// `PathEnv` is copied at most once per block (only when it actually
/// mutates).  Measured −12% on this bench when the COW landed
/// (2026-06-12); a regression that drops the `Arc` (or makes `make_mut`
/// fire per instruction) surfaces here as a slowdown proportional to
/// block × constraint density.  `Arc` (not `Rc`) keeps `SsaTaintState`
/// `Send` for the rayon-parallel file scan.
///
/// Also guards the `block_exit_states` clone elision (2026-07-14): the
/// worklist used to `SsaTaintState::clone()` the exit state into
/// `block_exit_states[bid]` on *every* block pop, but the dominant callers
/// (`run_ssa_taint_full`: summary extraction + main analysis + sink
/// augmentation) discard that vector.  It is now built only when the caller
/// asks (`track_exit_states`), and even then the state is *moved* in after
/// its last borrow instead of cloned.  This block-dense fixture maximises
/// pops, so re-introducing the per-pop exit clone surfaces here (measured
/// −1.8% end-to-end when the elision landed; the worklist itself is ~1/3 of
/// `analyse_file_fused`, so the isolated worklist gain is proportionally
/// larger).
fn bench_taint_branch_stress_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/taint_branch_stress.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");

    c.bench_function("taint_branch_stress_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// Branch conditions INSIDE nested loops, so the taint worklist re-visits
/// loop-body blocks until fixpoint and (before the memo) re-classified the
/// same condition text on every re-visit.  Isolates the per-condition
/// classification cache: each branch's `classify_condition_with_target` /
/// `has_semantic_negation` / PathFact-classifier `str::find`/`str::contains`
/// scans run once per distinct condition text via the persistent per-thread
/// `COND_CLASS_CACHE`, rather than once per re-visit / pass.  `analyse_file_fused`
/// runs the body's worklist ~5× (summary extraction + main + sink
/// augmentation), and criterion keeps the thread-local warm across `b.iter()`
/// iterations, so this bench captures the cross-pass / cross-iteration reuse
/// the persistent cache adds over the worklist-local memo
/// (session-0018: −2.5% vs worklist-local, −12.5% vs `NYX_DISABLE_COND_MEMO=1`).
/// Reverting the cache to per-`run_ssa_taint_internal` (or recompute-per-visit)
/// surfaces here proportional to the loop re-visit count × pass count.
fn bench_taint_cond_revisit_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/taint_cond_revisit.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");

    c.bench_function("taint_cond_revisit_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// CFG-construction throughput on the large gin Go module (~1.5k lines,
/// selector-expression-dense).  Targets `build_cfg_for_file`, whose hot
/// inner path runs `push_node` → `first_member_label` → `member_expr_text`
/// on every `CallWrapper`/`Assignment` node.  Pre-fix `member_expr_text`
/// built its dot-joined member path bottom-up via a `format!("{o}.{p}")`
/// chain, allocating one intermediate `String` per nesting level (and the
/// `first_member_label` classify path threw every one of those Strings away
/// after a single `classify(&str)` call).  The fix rewrote the builder to
/// append directly into a single reused buffer (`member_expr_text_into`),
/// collapsing the O(depth) intermediate allocations to one final allocation
/// (zero on the `first_member_label` classify path, which uses a thread-local
/// scratch buffer).  This bench isolates that allocation churn — the biggest
/// self-time bucket on the mm/channels/app static profile — from the taint /
/// SSA passes.  A regression that reintroduces the per-level `format!` chain
/// surfaces here proportional to member-expression nesting depth.
fn bench_cfg_build_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg = Config::default();

    c.bench_function("cfg_build_large_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg)
                .expect("build cfg")
                .expect("supported language")
        });
    });
}

/// AST pattern-query pass throughput on the large gin Go module.
///
/// Targets `ParsedSource::run_ast_queries` (via the `bench_run_ast_queries`
/// hook), isolating it from the rest of the per-file pipeline. Pre-fix the
/// pass issued one `QueryCursor::matches` — i.e. one full tree walk — per rule
/// (Go: 8 rules, JS/TS: 23), so traversal cost was `O(rules × nodes)`. The
/// combined multi-pattern query walks the AST once and tests every rule in a
/// single matcher pass (`O(nodes)`); on the mm/channels/app profile
/// `run_ast_queries` was the single biggest active nyx self-time bucket
/// (tree-sitter-cursor work). A/B the two paths on one binary via
/// `NYX_DISABLE_QUERY_COMBINE=1 … --save-baseline legacy` then `… --baseline
/// legacy`. A regression that reverts to per-rule walks surfaces here
/// proportional to the rule count.
fn bench_ast_queries_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let cfg = Config::default();

    // Warm the per-language combined-query cache before timing.
    let _ = nyx_scanner::ast::bench_run_ast_queries(&bytes, &fixture, &cfg);

    c.bench_function("ast_queries_large_go", |b| {
        b.iter(|| nyx_scanner::ast::bench_run_ast_queries(&bytes, &fixture, &cfg).len());
    });
}

/// `lower_to_ssa` cost on the large-Go fixture.  This is the CFG→SSA
/// lowering path: `form_blocks` (basic-block formation over the reachable
/// node set) plus `rename_variables`/`process_block` (Cytron dominator-tree
/// rename, which pushes/pops per-variable SSA stacks).  Pre-2026-07-13 the
/// node-keyed maps in `form_blocks` (`successors`, `in_degree`,
/// `has_branching_in`, `is_leader`, `block_of_node`, and the BFS visited
/// sets) and the string-keyed `var_stacks` used `std::collections::HashMap`
/// (SipHash), which profiling showed as ~26% of all SipHash self-time on
/// mattermost (`process_block` + `lower_to_ssa_inner`).  Post-fix they use
/// `rustc_hash::FxHashMap`/`FxHashSet`: keys are dense `NodeIndex` integers
/// or short variable-name strings, none are iterated in an output-observable
/// order, so the cheaper deterministic hasher is bit-identical.  A
/// regression that re-introduces SipHash on this path surfaces here.
///
/// 2026-07-14 (perfhunt session-0015) extended the conversion to the four
/// maps `lower_to_ssa` *returns* inside `SsaBody` — `cfg_node_map`
/// (`NodeIndex`→`SsaValue`), `field_writes`, `synthetic_externals`,
/// `slot_scoped_assigns` — which had stayed `std::collections::HashMap`/
/// `HashSet` because they cross the return boundary into the taint / guards /
/// symex consumers and the `CalleeSsaBody` DB blob.  All consumer accesses are
/// point lookups (audited: the only iteration is the order-insensitive
/// `ssa::invariants` validation), and `FxHashMap` serialises to the identical
/// msgpack map form, so the swap is bit-identical and blob-compatible.  This
/// bench builds `cfg_node_map` on every lowered body, so a regression that
/// reverts those fields to SipHash surfaces here proportional to node count.
fn bench_ssa_lower_large_go(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");

    // Snapshot the (graph, entry, scope) inputs once; the bench loop re-runs
    // `lower_to_ssa` on each so we measure only lowering cost, not CFG build.
    let inputs: Vec<(usize, bool)> = file_cfg
        .bodies
        .iter()
        .enumerate()
        .map(|(i, body)| (i, body.meta.name.is_none()))
        .collect();

    c.bench_function("ssa_lower_large_go", |b| {
        b.iter(|| {
            let mut total_blocks = 0usize;
            for &(i, scope_all) in &inputs {
                let body = &file_cfg.bodies[i];
                let scope = body.meta.name.as_deref();
                if let Ok(ssa_body) =
                    ssa::lower_to_ssa(&body.graph, body.entry, scope, scope_all)
                {
                    total_blocks += ssa_body.blocks.len();
                }
            }
            total_blocks
        });
    });
}

/// Isolates the `cfg_node_map` **point-lookup** path — the map's hottest access
/// pattern (18 `.get()` sites across taint / guards / symex / const-prop resolve
/// a sink or source CFG node to its primary `SsaValue`).
///
/// Pre-2026-07-14 this was a `std::collections::HashMap<NodeIndex, SsaValue>`
/// (SipHash), then an `FxHashMap` (session-0015).  2026-07-14 (session-0018)
/// replaced it with a positional `CfgNodeMap` (`Vec<Option<SsaValue>>` indexed by
/// `NodeIndex::index()`) — the option-(b) deep fix in `PERF_DEFERRED.md`.  A
/// lookup is now a bounds-checked `Vec` index with **zero hashing** instead of an
/// `FxHash` of the `NodeIndex` plus a bucket probe.  A regression that re-hashes
/// the key surfaces here proportional to the number of value-defining nodes.
///
/// Sourced from `value_defs` (not `cfg_node_map.iter()`) so the bench compiles
/// identically against the old `FxHashMap` and the new `CfgNodeMap`, enabling a
/// clean `--save-baseline` before/after on the same bench.
fn bench_cfg_node_map_lookup(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");

    // Lower every body once (outside the measured loop); keep each lowered body
    // paired with the value-defining CFG node indices — the realistic lookup
    // keys.
    let probes: Vec<_> = file_cfg
        .bodies
        .iter()
        .filter_map(|body| {
            let scope = body.meta.name.as_deref();
            let scope_all = body.meta.name.is_none();
            ssa::lower_to_ssa(&body.graph, body.entry, scope, scope_all)
                .ok()
                .and_then(|ssa_body| {
                    let nodes: Vec<_> =
                        ssa_body.value_defs.iter().map(|vd| vd.cfg_node).collect();
                    if nodes.is_empty() {
                        None
                    } else {
                        Some((ssa_body, nodes))
                    }
                })
        })
        .collect();

    c.bench_function("cfg_node_map_lookup", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for (ssa_body, nodes) in &probes {
                for n in nodes {
                    if let Some(v) = ssa_body.cfg_node_map.get(n) {
                        acc = acc.wrapping_add(v.0 as u64);
                    }
                }
            }
            acc
        });
    });
}

/// Isolates `FuncKey` hashing on the pessimal map: a `std::collections::HashMap`
/// (SipHash `RandomState`), the exact type used by the interprocedural indices
/// `ssa_by_key` / `bodies_by_key` / `auth_by_key` in `GlobalSummaries`.
///
/// Pre-fix, `FuncKey` derived `Hash`, so every lookup walked all bytes of the
/// three `String` identity fields (project-relative namespace path ~40-50 B,
/// container, name) through SipHash's per-byte mixing.  Profiling attributed
/// 44.7% of all SipHash self-time (~3.8% active CPU) on mattermost's
/// `server/channels/app` to `FuncKey::hash` — the single largest hashed entity
/// in the engine (PERF_DEFERRED.md, 2026-07-13).
///
/// Post-fix (2026-07-14 perfhunt session-0012), `FuncKey` caches a `u64`
/// FxHash of its identity computed once at construction; the manual `Hash`
/// impl writes that single precomputed `u64`, so a lookup mixes 8 bytes
/// instead of the ~76 B of identity string this fixture uses.  The change is
/// asymptotic in the identity string length: `O(len)` → `O(1)` per hash.  A
/// regression that reverts to hashing the string fields surfaces here
/// proportional to the namespace + name lengths.
fn bench_funckey_hash_lookup(c: &mut Criterion) {
    use nyx_scanner::symbol::{FuncKey, Lang};
    use std::collections::HashMap;

    // Realistic identity shapes: deep namespace paths + service-method names,
    // mirroring how cross-file callee keys look on a large Go/Java repo.
    let keys: Vec<FuncKey> = (0..500)
        .map(|i| {
            FuncKey::new_function(
                Lang::Go,
                format!("server/channels/app/module_group_{}/handler_{:04}.go", i % 16, i),
                format!("Process{:04}RequestHandler", i),
                Some((i % 5) + 1),
            )
        })
        .collect();
    let map: HashMap<FuncKey, usize> =
        keys.iter().cloned().enumerate().map(|(i, k)| (k, i)).collect();

    c.bench_function("funckey_hash_lookup", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for k in &keys {
                if let Some(v) = map.get(k) {
                    hits += *v & 1;
                }
            }
            hits
        });
    });
}

criterion_group!(
    benches,
    bench_ast_only_scan,
    bench_full_scan,
    bench_full_scan_with_state,
    bench_single_file_parse_and_cfg,
    bench_state_analysis_only,
    bench_classify,
    bench_analyse_file_fused_large_go,
    bench_extract_authorization_model_go,
    bench_extract_authorization_model_shared_go,
    bench_collect_top_level_units_go,
    bench_const_propagate_large_go,
    bench_ssa_lower_large_go,
    bench_cfg_node_map_lookup,
    bench_global_summaries_lookup_same_lang_go,
    bench_funckey_hash_lookup,
    bench_taint_callee_resolve_stress_go,
    bench_taint_branch_stress_go,
    bench_taint_cond_revisit_go,
    bench_cfg_build_large_go,
    bench_ast_queries_large_go,
);
criterion_main!(benches);
