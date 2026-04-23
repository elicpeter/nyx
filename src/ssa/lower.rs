#![allow(
    clippy::collapsible_if,
    clippy::if_same_then_else,
    clippy::needless_range_loop,
    clippy::only_used_in_recursion,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_unwrap
)]

use crate::cfg::{Cfg, EdgeKind, StmtKind};
use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::graph::NodeIndex;
use petgraph::prelude::*;
use petgraph::visit::{Bfs, EdgeRef};
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use super::ir::*;

/// Lower a CFG to SSA form for a single function scope.
///
/// `scope` filters nodes by `enclosing_func`:
///   - `None` → top-level code only (`enclosing_func.is_none()`)
///   - `Some(name)` → only nodes with `enclosing_func == Some(name)`
///
/// If `scope_all` is true, all nodes reachable from `entry` are included
/// regardless of `enclosing_func`.
pub fn lower_to_ssa(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
) -> Result<SsaBody, SsaError> {
    lower_to_ssa_inner(cfg, entry, scope, scope_all, false, &[])
}

/// Like `lower_to_ssa` but with formal parameter names supplied in declaration
/// order. External variables that match these names are placed first (in
/// declaration order) so that `Param { index }` indices 0..N correspond to
/// call-site argument positions.
pub fn lower_to_ssa_with_params(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
    formal_params: &[String],
) -> Result<SsaBody, SsaError> {
    lower_to_ssa_inner(cfg, entry, scope, scope_all, false, formal_params)
}

/// Like `lower_to_ssa` but with `scope_nop`: when true, all nodes are included
/// in the SSA body for graph connectivity, but out-of-scope nodes become Nop
/// (their defines/uses are ignored). This is used for the JS two-level solve
/// where the CFG linearizes function bodies inline.
pub fn lower_to_ssa_scoped_nop(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
) -> Result<SsaBody, SsaError> {
    lower_to_ssa_inner(cfg, entry, scope, false, true, &[])
}

fn lower_to_ssa_inner(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
    scope_nop: bool,
    formal_params: &[String],
) -> Result<SsaBody, SsaError> {
    if cfg.node_count() == 0 {
        return Err(SsaError::EmptyCfg);
    }

    // When scope_nop is set, traverse all nodes (scope_all=true) for graph connectivity
    let traverse_all = scope_all || scope_nop;

    // Collect reachable nodes in scope, stripping exception edges.
    let (reachable, filtered_edges, raw_exception_edges) =
        collect_reachable(cfg, entry, scope, traverse_all);

    // Build the set of nodes that should be treated as Nop (out-of-scope but included)
    let nop_nodes: HashSet<NodeIndex> = if scope_nop {
        let in_scope = |node: NodeIndex| -> bool {
            let info = &cfg[node];
            match scope {
                None => info.ast.enclosing_func.is_none(),
                Some(name) => info.ast.enclosing_func.as_deref() == Some(name),
            }
        };
        reachable
            .iter()
            .filter(|&&n| !in_scope(n) && !matches!(cfg[n].kind, StmtKind::Entry | StmtKind::Exit))
            .copied()
            .collect()
    } else {
        HashSet::new()
    };
    if reachable.is_empty() {
        return Err(SsaError::EmptyCfg);
    }

    // 1. Form basic blocks
    let (blocks_nodes, block_of_node, block_succs, block_preds) =
        form_blocks(cfg, entry, &reachable, &filtered_edges);

    let num_blocks = blocks_nodes.len();
    if num_blocks == 0 {
        return Err(SsaError::EmptyCfg);
    }

    // 2. Compute dominators on block-level graph
    let (block_graph, block_graph_entry) = build_block_graph(num_blocks, &block_succs, BlockId(0));
    let doms = simple_fast(&block_graph, block_graph_entry);

    // 3. Compute dominance frontiers
    let dom_frontiers = compute_dominance_frontiers(num_blocks, &block_preds, &doms, &block_graph);

    // 4. Collect variable definitions per block (skip nop nodes)
    let mut var_defs = collect_var_defs(cfg, &blocks_nodes, &nop_nodes);

    // 4b. For per-function scope: identify external variables (used but not defined)
    //     and inject synthetic Param defs at entry block so rename can find them.
    //     When formal_params is supplied, reorder so formal params come first in
    //     declaration order — this makes Param indices correspond to call-site positions.
    //
    let external_vars = if scope.is_some() && !scope_all && !scope_nop {
        let raw = identify_external_uses(cfg, &blocks_nodes, &var_defs);
        reorder_external_vars(raw, formal_params)
    } else {
        vec![]
    };
    // Register external vars as defined in block 0 so phi insertion considers them
    for var in &external_vars {
        var_defs.entry(var.clone()).or_default().insert(0);
    }

    // 5. Phi insertion (Cytron algorithm)
    let phi_placements = insert_phis(&var_defs, &dom_frontiers, num_blocks);

    // 6. Rename variables (dominator tree preorder walk)
    let dom_tree_children = build_dom_tree_children(num_blocks, &doms, &block_graph);
    let (mut ssa_blocks, mut value_defs, cfg_node_map) = rename_variables(
        cfg,
        &blocks_nodes,
        &block_succs,
        &block_preds,
        &phi_placements,
        &dom_tree_children,
        &filtered_edges,
        &external_vars,
        &nop_nodes,
    );

    // 6b. Fill any missing phi operands with a shared Undef sentinel so
    // every phi has exactly one operand per predecessor. See
    // `fill_undef_phi_operands` for the invariant rationale.
    fill_undef_phi_operands(&mut ssa_blocks, &block_preds, &mut value_defs, &blocks_nodes);

    // 7. Fill in preds/succs on SsaBlocks
    for bid in 0..num_blocks {
        let id = BlockId(bid as u32);
        ssa_blocks[bid].id = id;
        ssa_blocks[bid].preds = block_preds[bid]
            .iter()
            .map(|&b| BlockId(b as u32))
            .collect();
        ssa_blocks[bid].succs = block_succs[bid]
            .iter()
            .map(|&b| BlockId(b as u32))
            .collect();
    }

    // 7b. Debug assertions: verify structural invariants.
    #[cfg(debug_assertions)]
    {
        debug_assert_bfs_ordering(&block_preds);
    }
    // Phi operand counts are a release-level invariant: every phi must
    // have exactly one operand per predecessor. Missing operands are
    // filled with an explicit Undef sentinel in
    // `fill_undef_phi_operands`; extra operands would reference
    // nonexistent predecessors and corrupt analysis silently.
    assert_phi_operand_counts(&ssa_blocks, &block_preds);

    // 8. Map exception edges from CFG node indices to SSA block IDs
    let exception_edges: Vec<(BlockId, BlockId)> = raw_exception_edges
        .iter()
        .filter_map(|(src_node, catch_node)| {
            let src_block = block_of_node.get(src_node)?;
            let catch_block = block_of_node.get(catch_node)?;
            Some((BlockId(*src_block as u32), BlockId(*catch_block as u32)))
        })
        .collect();

    let body = SsaBody {
        blocks: ssa_blocks,
        entry: BlockId(0),
        value_defs,
        cfg_node_map,
        exception_edges,
    };

    // 9. Catch-block reachability invariant (Phase 12.1).
    //
    // A CatchParam-carrying block that is neither reachable from entry nor
    // listed as an exception target indicates a CFG construction bug. Debug
    // builds panic loudly; release builds warn, record an engine note so
    // downstream findings carry "SSA lowering bailed" provenance, and fall
    // through to the existing orphan handling above (the "all definitions"
    // fallback) which remains sound for taint reachability.
    check_catch_block_reachability_gated(&body);

    Ok(body)
}

/// Runtime gate around [`check_catch_block_reachability`] that panics in
/// debug builds and warns + records an engine note in release builds.
///
/// The current lowering's orphan handling (`process_block` fallback in
/// `rename_variables`) already widens to an "all definitions" conservative
/// state for blocks without predecessors. That preserves soundness for
/// taint reachability but masks CFG-builder bugs: this gate surfaces them.
fn check_catch_block_reachability_gated(body: &SsaBody) {
    let result = super::invariants::check_catch_block_reachability(body);
    if let Err(err) = result {
        #[cfg(debug_assertions)]
        {
            if !catch_invariant_do_not_panic() {
                panic!(
                    "SSA catch-block reachability invariant violated:\n{}",
                    err.joined()
                );
            }
        }
        tracing::warn!(
            violations = %err.joined(),
            "SSA catch-block reachability invariant violated; proceeding with \
             conservative orphan fallback"
        );
        crate::taint::ssa_transfer::record_engine_note(
            crate::engine_notes::EngineNote::SsaLoweringBailed {
                reason: format!("catch_block_orphan: {}", err.joined()),
            },
        );
    }
}

// Test-only escape hatch: when set, `check_catch_block_reachability_gated`
// takes the release-build path (warn + engine note, no panic) even under
// `debug_assertions`. Used by the invariant test that constructs a
// synthetic orphan catch body.
#[cfg(debug_assertions)]
thread_local! {
    static CATCH_INVARIANT_DO_NOT_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
pub(crate) fn set_catch_invariant_do_not_panic(on: bool) {
    CATCH_INVARIANT_DO_NOT_PANIC.with(|c| c.set(on));
}

#[cfg(debug_assertions)]
fn catch_invariant_do_not_panic() -> bool {
    CATCH_INVARIANT_DO_NOT_PANIC.with(|c| c.get())
}

/// Collect reachable nodes (BFS from entry), filtering by scope and stripping exception edges.
/// Returns (reachable set, filtered edges, exception edges as (src_node, catch_node)).
fn collect_reachable(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
) -> (
    HashSet<NodeIndex>,
    Vec<(NodeIndex, NodeIndex, EdgeKind)>,
    Vec<(NodeIndex, NodeIndex)>,
) {
    let mut reachable = HashSet::new();
    let mut edges = Vec::new();
    let mut exception_edges = Vec::new();
    let mut queue = VecDeque::new();

    // Check if a node is in scope
    let in_scope = |node: NodeIndex| -> bool {
        if scope_all {
            return true;
        }
        let info = &cfg[node];
        match scope {
            None => info.ast.enclosing_func.is_none(),
            Some(name) => info.ast.enclosing_func.as_deref() == Some(name),
        }
    };

    if !in_scope(entry) && !scope_all {
        // Entry must be in scope; for top-level, Entry node often has no enclosing_func
        // Accept Entry/Exit nodes regardless of scope
        if !matches!(cfg[entry].kind, StmtKind::Entry | StmtKind::Exit) {
            return (reachable, edges, exception_edges);
        }
    }

    reachable.insert(entry);
    queue.push_back(entry);

    while let Some(node) = queue.pop_front() {
        for edge in cfg.edges(node) {
            let kind = *edge.weight();
            let target = edge.target();

            // Strip exception edges from the graph, but still visit targets
            // so catch-block nodes are included in the SSA body.
            if matches!(kind, EdgeKind::Exception) {
                if (in_scope(target)
                    || matches!(cfg[target].kind, StmtKind::Entry | StmtKind::Exit))
                    && reachable.insert(target)
                {
                    queue.push_back(target);
                }
                // Record exception edge for taint seeding
                exception_edges.push((node, target));
                continue;
            }

            // Allow Entry/Exit nodes and nodes in scope
            if !in_scope(target) && !matches!(cfg[target].kind, StmtKind::Entry | StmtKind::Exit) {
                continue;
            }

            edges.push((node, target, kind));

            if reachable.insert(target) {
                queue.push_back(target);
            }
        }
    }

    (reachable, edges, exception_edges)
}

/// Form basic blocks from filtered CFG nodes.
///
/// Returns:
/// - blocks_nodes: Vec<Vec<NodeIndex>> — nodes per block (in order)
/// - block_of_node: HashMap<NodeIndex, usize> — node → block index
/// - block_succs: Vec<Vec<usize>> — successors per block
/// - block_preds: Vec<Vec<usize>> — predecessors per block
fn form_blocks(
    cfg: &Cfg,
    entry: NodeIndex,
    reachable: &HashSet<NodeIndex>,
    filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
) -> (
    Vec<Vec<NodeIndex>>,
    HashMap<NodeIndex, usize>,
    Vec<Vec<usize>>,
    Vec<Vec<usize>>,
) {
    // Build adjacency from filtered edges
    let mut successors: HashMap<NodeIndex, Vec<(NodeIndex, EdgeKind)>> = HashMap::new();
    let mut in_degree: HashMap<NodeIndex, usize> = HashMap::new();
    let mut has_branching_in: HashMap<NodeIndex, bool> = HashMap::new();

    for node in reachable {
        in_degree.entry(*node).or_insert(0);
        has_branching_in.entry(*node).or_insert(false);
    }

    for &(src, tgt, kind) in filtered_edges {
        successors.entry(src).or_default().push((tgt, kind));
        *in_degree.entry(tgt).or_insert(0) += 1;
        if matches!(kind, EdgeKind::True | EdgeKind::False | EdgeKind::Back) {
            *has_branching_in.entry(tgt).or_insert(false) = true;
        }
    }

    // Determine block leaders
    let mut is_leader: HashSet<NodeIndex> = HashSet::new();
    is_leader.insert(entry); // entry is always a leader

    for &node in reachable {
        let in_deg = in_degree.get(&node).copied().unwrap_or(0);
        if in_deg > 1 || has_branching_in.get(&node).copied().unwrap_or(false) {
            is_leader.insert(node);
        }
        // Orphan nodes (reachable via exception edges but no filtered predecessors)
        // must be leaders so they get their own block (e.g. catch block entries).
        if in_deg == 0 && node != entry {
            is_leader.insert(node);
        }
        // Node following a multi-exit node
        let succs = successors.get(&node).map(|s| s.len()).unwrap_or(0);
        if succs > 1 {
            for &(tgt, _) in successors.get(&node).unwrap_or(&vec![]) {
                is_leader.insert(tgt);
            }
        }
    }

    // Build blocks by following single-successor Seq edges from each leader
    let mut blocks_nodes: Vec<Vec<NodeIndex>> = Vec::new();
    let mut block_of_node: HashMap<NodeIndex, usize> = HashMap::new();
    let mut visited: HashSet<NodeIndex> = HashSet::new();

    // BFS order to assign blocks deterministically (entry first)
    let mut leader_queue: VecDeque<NodeIndex> = VecDeque::new();
    leader_queue.push_back(entry);
    let mut leader_visited: HashSet<NodeIndex> = HashSet::new();
    leader_visited.insert(entry);

    // Also need BFS to discover leaders in order
    {
        let mut bfs = Bfs::new(cfg, entry);
        while let Some(node) = bfs.next(cfg) {
            if reachable.contains(&node) && is_leader.contains(&node) && leader_visited.insert(node)
            {
                leader_queue.push_back(node);
            }
        }
    }

    for leader in leader_queue {
        if visited.contains(&leader) {
            continue;
        }

        let block_idx = blocks_nodes.len();
        let mut block = vec![leader];
        visited.insert(leader);
        block_of_node.insert(leader, block_idx);

        // Follow single-successor Seq edges
        let mut current = leader;
        loop {
            let succs = successors.get(&current).cloned().unwrap_or_default();
            if succs.len() == 1
                && matches!(succs[0].1, EdgeKind::Seq)
                && !is_leader.contains(&succs[0].0)
            {
                let next = succs[0].0;
                if visited.insert(next) {
                    block.push(next);
                    block_of_node.insert(next, block_idx);
                    current = next;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        blocks_nodes.push(block);
    }

    // Build block-level successor/predecessor lists
    let num_blocks = blocks_nodes.len();
    let mut block_succs: Vec<Vec<usize>> = vec![vec![]; num_blocks];
    let mut block_preds: Vec<Vec<usize>> = vec![vec![]; num_blocks];

    for &(src, tgt, _kind) in filtered_edges {
        if let (Some(&src_blk), Some(&tgt_blk)) = (block_of_node.get(&src), block_of_node.get(&tgt))
        {
            if src_blk != tgt_blk && !block_succs[src_blk].contains(&tgt_blk) {
                block_succs[src_blk].push(tgt_blk);
                block_preds[tgt_blk].push(src_blk);
            }
        }
    }

    (blocks_nodes, block_of_node, block_succs, block_preds)
}

/// Build a block-level petgraph for dominator computation.
fn build_block_graph(
    num_blocks: usize,
    block_succs: &[Vec<usize>],
    _entry: BlockId,
) -> (Graph<BlockId, ()>, NodeIndex) {
    let mut g: Graph<BlockId, ()> = Graph::new();
    let mut block_nodes: Vec<NodeIndex> = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        block_nodes.push(g.add_node(BlockId(i as u32)));
    }

    for (i, succs) in block_succs.iter().enumerate() {
        for &s in succs {
            g.add_edge(block_nodes[i], block_nodes[s], ());
        }
    }

    let entry_gnode = block_nodes[0]; // block 0 is always entry
    (g, entry_gnode)
}

/// Compute dominance frontiers for all blocks.
fn compute_dominance_frontiers(
    num_blocks: usize,
    block_preds: &[Vec<usize>],
    doms: &Dominators<NodeIndex>,
    block_graph: &Graph<BlockId, ()>,
) -> Vec<HashSet<usize>> {
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); num_blocks];

    // Map block index → graph NodeIndex
    let block_node: Vec<NodeIndex> = block_graph.node_indices().collect();

    for n in 0..num_blocks {
        let preds = &block_preds[n];
        if preds.len() >= 2 {
            for &p in preds {
                let mut runner = p;
                // idom(n) in the block graph
                let n_gnode = block_node[n];
                let idom_n = doms.immediate_dominator(n_gnode);
                loop {
                    let runner_gnode = block_node[runner];
                    if idom_n == Some(runner_gnode) {
                        break;
                    }
                    df[runner].insert(n);
                    // Move runner to its immediate dominator
                    match doms.immediate_dominator(runner_gnode) {
                        Some(idom_runner) if idom_runner != runner_gnode => {
                            // Find block index from graph node
                            runner = block_graph[idom_runner].0 as usize;
                        }
                        _ => break, // reached root
                    }
                }
            }
        }
    }

    df
}

/// Identify variables used but not defined within the scoped blocks.
/// These represent external (e.g. global/top-level) variables that need
/// synthetic Param instructions so the SSA rename pass can reference them.
fn identify_external_uses(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    var_defs: &BTreeMap<String, HashSet<usize>>,
) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::new();
    for nodes in blocks_nodes {
        for &node in nodes {
            for u in &cfg[node].taint.uses {
                used.insert(u.clone());
            }
        }
    }
    // External = used but never defined in any block
    let mut external: Vec<String> = used
        .into_iter()
        .filter(|u| !var_defs.contains_key(u))
        .collect();
    external.sort(); // deterministic order
    external
}

/// True iff `name` is a language-reserved method receiver identifier
/// (Rust/Python `self`, JS/TS/Java/PHP/C++ `this`).
///
/// Receivers get their own IR node ([`SsaOp::SelfParam`]) and are therefore
/// tracked as a distinct channel from positional parameters.  Keeping the
/// check localised to one helper ensures the set of receiver names stays
/// consistent across lowering and summary extraction.
pub(crate) fn is_receiver_name(name: &str) -> bool {
    matches!(name, "self" | "this")
}

/// Reorder external variables so the receiver (`self`/`this`) comes first,
/// followed by formal positional parameters in declaration order, followed
/// by remaining external vars in alphabetical order.
///
/// This fixed order is what the synthetic-parameter injection step relies
/// on to emit one [`SsaOp::SelfParam`] (for the leading receiver slot, when
/// present) followed by a contiguous run of [`SsaOp::Param { index }`] values
/// whose indices 0..N correspond exactly to positional call-site argument
/// positions — no receiver offset required anywhere downstream.
fn reorder_external_vars(external: Vec<String>, formal_params: &[String]) -> Vec<String> {
    if formal_params.is_empty() {
        return external; // no reordering — preserve existing alphabetical sort
    }
    let ext_set: HashSet<&str> = external.iter().map(|s| s.as_str()).collect();
    let formal_set: HashSet<&str> = formal_params.iter().map(|s| s.as_str()).collect();
    let mut result = Vec::with_capacity(external.len());
    // Receiver first (highest priority), regardless of whether it appears in
    // formal_params or was discovered purely as an external reference.
    // Languages with explicit self (Rust/Python) put it in formal_params;
    // languages with implicit this (JS/TS/Java/PHP) have it only as an
    // external reference.  Either way, SelfParam should be emitted first.
    if ext_set.contains("self") {
        result.push("self".to_string());
    } else if ext_set.contains("this") {
        result.push("this".to_string());
    }
    // Formal positional params next (declaration order), skipping any
    // receiver that was already emitted above.
    for p in formal_params {
        if is_receiver_name(p) {
            continue;
        }
        if ext_set.contains(p.as_str()) {
            result.push(p.clone());
        }
    }
    // Remaining external vars alphabetically (external is already sorted),
    // excluding anything already placed.
    let placed: HashSet<String> = result.iter().cloned().collect();
    for v in external {
        if placed.contains(&v) {
            continue;
        }
        if !formal_set.contains(v.as_str()) && !is_receiver_name(&v) {
            result.push(v);
        }
    }
    result
}

/// Collect variable definitions per block: var_name → set of block indices.
/// Nodes in `nop_nodes` are skipped (they won't define variables in SSA).
fn collect_var_defs(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    nop_nodes: &HashSet<NodeIndex>,
) -> BTreeMap<String, HashSet<usize>> {
    let mut defs: BTreeMap<String, HashSet<usize>> = BTreeMap::new();

    for (block_idx, nodes) in blocks_nodes.iter().enumerate() {
        for &node in nodes {
            if nop_nodes.contains(&node) {
                continue;
            }
            if let Some(ref d) = cfg[node].taint.defines {
                defs.entry(d.clone()).or_default().insert(block_idx);
                // Register parent prefixes for synthetic base updates on field writes.
                // E.g. `obj.data` also registers `obj` so phi insertion works correctly.
                let mut path = d.as_str();
                while let Some(dot_pos) = path.rfind('.') {
                    path = &path[..dot_pos];
                    defs.entry(path.to_string()).or_default().insert(block_idx);
                }
            }
            // Register extra defines from destructuring patterns.
            for ed in &cfg[node].taint.extra_defines {
                defs.entry(ed.clone()).or_default().insert(block_idx);
            }
            // Implicit definitions for uninitialized declarations (e.g., C/C++
            // `char buf[256]`).  The variable appears in uses but not defines
            // because def_use() doesn't treat declarations without initializers
            // as definitions.  Registering here ensures phi insertion at join points.
            if cfg[node].taint.defines.is_none()
                && cfg[node].call.callee.is_none()
                && cfg[node].kind == StmtKind::Seq
                && cfg[node].taint.uses.len() == 1
            {
                defs.entry(cfg[node].taint.uses[0].clone())
                    .or_default()
                    .insert(block_idx);
            }
        }
    }

    defs
}

/// Cytron-style phi insertion: returns phi_placements[block] = set of var names needing phis.
///
/// Returns a `BTreeSet<String>` per block so downstream consumers that iterate
/// the set (notably `rename_variables`) observe a deterministic, alphabetical
/// order regardless of the underlying hasher state.  The Cytron algorithm
/// itself is order-independent — only its observers are.
fn insert_phis(
    var_defs: &BTreeMap<String, HashSet<usize>>,
    dom_frontiers: &[HashSet<usize>],
    _num_blocks: usize,
) -> Vec<BTreeSet<String>> {
    let num_blocks = dom_frontiers.len();
    let mut phi_placements: Vec<BTreeSet<String>> = vec![BTreeSet::new(); num_blocks];

    for (var, def_blocks) in var_defs {
        let mut worklist: VecDeque<usize> = def_blocks.iter().copied().collect();
        let mut has_phi: HashSet<usize> = HashSet::new();

        while let Some(b) = worklist.pop_front() {
            for &f in &dom_frontiers[b] {
                if has_phi.insert(f) {
                    phi_placements[f].insert(var.clone());
                    // Phi is a new definition — add to worklist
                    if !def_blocks.contains(&f) {
                        worklist.push_back(f);
                    }
                }
            }
        }
    }

    phi_placements
}

/// Build dominator tree children lists.
fn build_dom_tree_children(
    num_blocks: usize,
    doms: &Dominators<NodeIndex>,
    block_graph: &Graph<BlockId, ()>,
) -> Vec<Vec<usize>> {
    let mut children: Vec<Vec<usize>> = vec![vec![]; num_blocks];
    let block_nodes: Vec<NodeIndex> = block_graph.node_indices().collect();

    for i in 0..num_blocks {
        if let Some(idom) = doms.immediate_dominator(block_nodes[i]) {
            let idom_idx = block_graph[idom].0 as usize;
            if idom_idx != i {
                children[idom_idx].push(i);
            }
        }
    }

    children
}

/// Rename variables: dominator tree preorder walk with per-variable stacks.
///
/// Returns (ssa_blocks, value_defs, cfg_node_map).
fn rename_variables(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    block_succs: &[Vec<usize>],
    block_preds: &[Vec<usize>],
    phi_placements: &[BTreeSet<String>],
    dom_tree_children: &[Vec<usize>],
    filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
    external_vars: &[String],
    nop_nodes: &HashSet<NodeIndex>,
) -> (Vec<SsaBlock>, Vec<ValueDef>, HashMap<NodeIndex, SsaValue>) {
    let num_blocks = blocks_nodes.len();
    let mut next_value: u32 = 0;
    let mut value_defs: Vec<ValueDef> = Vec::new();
    let mut cfg_node_map: HashMap<NodeIndex, SsaValue> = HashMap::new();

    // Per-variable rename stacks
    let mut var_stacks: HashMap<String, Vec<SsaValue>> = HashMap::new();

    // Pre-allocate SSA blocks
    let mut ssa_blocks: Vec<SsaBlock> = (0..num_blocks)
        .map(|i| SsaBlock {
            id: BlockId(i as u32),
            phis: Vec::new(),
            body: Vec::new(),
            terminator: Terminator::Unreachable,
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        })
        .collect();

    // `BTreeMap` guarantees a deterministic (alphabetical) iteration order when
    // pushing phi values onto `var_stacks` and when filling operands on
    // successor phis — both sites are observable in SSA numbering if they
    // reordered between runs.
    let mut phi_values: Vec<BTreeMap<String, SsaValue>> = vec![BTreeMap::new(); num_blocks];

    // Pre-create phi instructions for all blocks (operands filled during rename)
    for (block_idx, vars) in phi_placements.iter().enumerate() {
        let block_id = BlockId(block_idx as u32);
        let cfg_node = blocks_nodes[block_idx][0]; // anchor to first node
        for var in vars {
            let v = SsaValue(next_value);
            next_value += 1;
            value_defs.push(ValueDef {
                var_name: Some(var.clone()),
                cfg_node,
                block: block_id,
            });
            phi_values[block_idx].insert(var.clone(), v);
            ssa_blocks[block_idx].phis.push(SsaInst {
                value: v,
                op: SsaOp::Phi(SmallVec::new()),
                cfg_node,
                var_name: Some(var.clone()),
                span: cfg[cfg_node].ast.span,
            });
        }
    }

    // Process blocks in dominator tree preorder
    // We need to track stack depths to restore after processing subtrees
    // Use iterative approach: process block, then process children, restore

    // Simpler approach: preorder walk with explicit save/restore
    fn process_block(
        block_idx: usize,
        cfg: &Cfg,
        blocks_nodes: &[Vec<NodeIndex>],
        block_succs: &[Vec<usize>],
        block_preds: &[Vec<usize>],
        phi_placements: &[BTreeSet<String>],
        dom_tree_children: &[Vec<usize>],
        filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
        var_stacks: &mut HashMap<String, Vec<SsaValue>>,
        ssa_blocks: &mut [SsaBlock],
        phi_values: &mut [BTreeMap<String, SsaValue>],
        value_defs: &mut Vec<ValueDef>,
        cfg_node_map: &mut HashMap<NodeIndex, SsaValue>,
        next_value: &mut u32,
        nop_nodes: &HashSet<NodeIndex>,
    ) {
        let block_id = BlockId(block_idx as u32);

        // Save stack depths for rollback
        let saved: Vec<(String, usize)> = var_stacks
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();

        // 1. Push pre-created phi values onto var stacks
        for (var, &v) in &phi_values[block_idx] {
            var_stacks.entry(var.clone()).or_default().push(v);
        }

        // 2. Process body nodes
        for &node in &blocks_nodes[block_idx] {
            let info = &cfg[node];

            // Helper: build Call args from arg_uses, falling back to info.taint.uses
            let build_call_args = |info: &crate::cfg::NodeInfo,
                                   var_stacks: &HashMap<String, Vec<SsaValue>>|
             -> (Vec<SmallVec<[SsaValue; 2]>>, Option<SsaValue>) {
                let receiver = info
                    .call
                    .receiver
                    .as_ref()
                    .and_then(|r| var_stacks.get(r).and_then(|s| s.last().copied()));
                let args = if !info.call.arg_uses.is_empty() {
                    let mut args: Vec<SmallVec<[SsaValue; 2]>> = info
                        .call
                        .arg_uses
                        .iter()
                        .map(|arg_idents| {
                            arg_idents
                                .iter()
                                .filter_map(|ident| {
                                    var_stacks.get(ident).and_then(|s| s.last().copied())
                                })
                                .collect()
                        })
                        .collect();
                    // For chained calls (e.g. fetch(url).then(fn)), arg_uses only
                    // captures the final call's args. Variables used by intermediate
                    // calls (like `url` in fetch) are in info.taint.uses but not arg_uses.
                    // Add them as an extra group so sink detection can see them.
                    //
                    // Exclude the receiver ident: it's carried on its own typed
                    // channel (`SsaOp::Call.receiver`).  Callers that care about
                    // positional arity must read it from `info.call.arg_uses.len()`,
                    // not `args.len()`, since this implicit group inflates args.
                    let arg_uses_flat: HashSet<&str> = info
                        .call
                        .arg_uses
                        .iter()
                        .flat_map(|g| g.iter().map(|s| s.as_str()))
                        .collect();
                    let receiver_ident = info.call.receiver.as_deref();
                    let implicit: SmallVec<[SsaValue; 2]> = info
                        .taint
                        .uses
                        .iter()
                        .filter(|u| !arg_uses_flat.contains(u.as_str()))
                        .filter(|u| Some(u.as_str()) != receiver_ident)
                        .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                        .collect();
                    if !implicit.is_empty() {
                        args.push(implicit);
                    }
                    args
                } else {
                    // Fallback: treat all uses as a single argument group
                    let all_uses: SmallVec<[SsaValue; 2]> = info
                        .taint
                        .uses
                        .iter()
                        .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                        .collect();
                    if all_uses.is_empty() {
                        vec![]
                    } else {
                        vec![all_uses]
                    }
                };
                (args, receiver)
            };

            // Determine operation and collect uses
            // Out-of-scope nodes (nop_nodes) become Nop: they preserve graph
            // connectivity but don't participate in taint flow.
            let op = if nop_nodes.contains(&node) {
                SsaOp::Nop
            } else if info.catch_param {
                SsaOp::CatchParam
            } else if info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
                && info.call.callee.is_none()
            {
                // Pure source (e.g. $_GET, env var) — no callee, so no args to track.
                // Source-labeled calls (e.g. file_get_contents) fall through to Call
                // so argument taint and sink detection still work.
                SsaOp::Source
            } else if info.call.callee.is_some() {
                let callee = info.call.callee.as_deref().unwrap_or("").to_string();
                let (args, receiver) = build_call_args(info, var_stacks);
                SsaOp::Call {
                    callee,
                    args,
                    receiver,
                }
            } else if info.taint.defines.is_some()
                && info.taint.uses.is_empty()
                && !info
                    .taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
            {
                // Reassignment kill: a node that defines a variable but has no
                // uses (operands) and is not a source is a constant/literal
                // assignment.  SSA rename allocates a fresh SsaValue, so
                // downstream references see this new (untainted) value — the
                // prior tainted definition is implicitly dead.
                SsaOp::Const(info.taint.const_text.clone())
            } else if info.taint.defines.is_some() {
                let mut uses: SmallVec<[SsaValue; 4]> = info
                    .taint
                    .uses
                    .iter()
                    .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                    .collect();
                // Inject Const for binary expression literal operand.
                // When a binary expression has one identifier and one numeric literal
                // (e.g., `flags & 0x07`), the literal isn't in `uses`. Inject a
                // synthetic Const instruction so the Assign has 2 uses, preventing
                // copy propagation from eliminating the operation.
                if uses.len() == 1 && info.bin_op.is_some() && info.bin_op_const.is_some() {
                    let const_val = info.bin_op_const.unwrap();
                    let const_v = SsaValue(*next_value);
                    *next_value += 1;
                    let const_inst = SsaInst {
                        value: const_v,
                        op: SsaOp::Const(Some(const_val.to_string())),
                        cfg_node: node,
                        var_name: None,
                        span: info.ast.span,
                    };
                    ssa_blocks[block_idx].body.push(const_inst);
                    value_defs.push(ValueDef {
                        var_name: None,
                        cfg_node: node,
                        block: block_id,
                    });
                    uses.push(const_v);
                }
                SsaOp::Assign(uses)
            } else if matches!(
                info.kind,
                StmtKind::Entry
                    | StmtKind::Exit
                    | StmtKind::If
                    | StmtKind::Loop
                    | StmtKind::Break
                    | StmtKind::Continue
                    | StmtKind::Return
                    | StmtKind::Throw
            ) {
                SsaOp::Nop
            } else if info.call.callee.is_some() {
                let callee = info.call.callee.as_deref().unwrap_or("").to_string();
                let (args, receiver) = build_call_args(info, var_stacks);
                SsaOp::Call {
                    callee,
                    args,
                    receiver,
                }
            } else {
                SsaOp::Nop
            };

            // Allocate SSA value
            let v = SsaValue(*next_value);
            *next_value += 1;
            let var_name_for_ssa = if nop_nodes.contains(&node) {
                None
            } else if info.taint.defines.is_some() {
                info.taint.defines.clone()
            } else if info.kind == StmtKind::Seq
                && info.call.callee.is_none()
                && info.taint.uses.len() == 1
                && !var_stacks.contains_key(&info.taint.uses[0])
            {
                // Implicit definition for uninitialized declarations (e.g.,
                // C/C++ `char buf[256]`).  Creates a reaching definition so
                // output-parameter sources like fgets() can taint the buffer
                // and subsequent uses (e.g., system(buf)) see the tainted value.
                Some(info.taint.uses[0].clone())
            } else {
                None
            };
            value_defs.push(ValueDef {
                var_name: var_name_for_ssa.clone(),
                cfg_node: node,
                block: block_id,
            });

            // Push defined variable onto stack (skip nop nodes)
            if let Some(ref d) = var_name_for_ssa {
                var_stacks.entry(d.clone()).or_default().push(v);
            }

            cfg_node_map.insert(node, v);

            // Clone op for potential extra_defines before moving into SsaInst
            let primary_op_for_extras = if info.taint.extra_defines.is_empty() {
                None
            } else {
                Some(op.clone())
            };
            ssa_blocks[block_idx].body.push(SsaInst {
                value: v,
                op,
                cfg_node: node,
                var_name: var_name_for_ssa.clone(),
                span: info.ast.span,
            });

            // Synthetic base update: when a dotted path is defined (e.g. `obj.data`),
            // create synthetic Assign instructions for parent prefixes (e.g. `obj`)
            // so that subsequent reads of the base variable see the field write.
            // Only includes the new field value (not the old base) so that field
            // overwrites properly kill taint: if obj.data is re-assigned to a
            // constant, the base `obj` no longer carries that field's taint.
            if !nop_nodes.contains(&node) {
                if let Some(ref d) = info.taint.defines {
                    let mut current = d.as_str();
                    let mut child_value = v;
                    while let Some(dot_pos) = current.rfind('.') {
                        let parent = &current[..dot_pos];
                        let synth_v = SsaValue(*next_value);
                        *next_value += 1;
                        let synth_uses: SmallVec<[SsaValue; 4]> =
                            SmallVec::from_elem(child_value, 1);
                        value_defs.push(ValueDef {
                            var_name: Some(parent.to_string()),
                            cfg_node: node,
                            block: block_id,
                        });
                        var_stacks
                            .entry(parent.to_string())
                            .or_default()
                            .push(synth_v);
                        ssa_blocks[block_idx].body.push(SsaInst {
                            value: synth_v,
                            op: SsaOp::Assign(synth_uses),
                            cfg_node: node,
                            var_name: Some(parent.to_string()),
                            span: info.ast.span,
                        });
                        child_value = synth_v;
                        current = parent;
                    }
                }
            }

            // Emit extra SSA instructions for destructuring bindings.
            // Each extra define inherits the same op (Source/Call/Assign) as the primary.
            if let Some(ref primary_op) = primary_op_for_extras {
                for extra_def in &info.taint.extra_defines {
                    let ev = SsaValue(*next_value);
                    *next_value += 1;
                    value_defs.push(ValueDef {
                        var_name: Some(extra_def.clone()),
                        cfg_node: node,
                        block: block_id,
                    });
                    var_stacks.entry(extra_def.clone()).or_default().push(ev);
                    ssa_blocks[block_idx].body.push(SsaInst {
                        value: ev,
                        op: primary_op.clone(),
                        cfg_node: node,
                        var_name: Some(extra_def.clone()),
                        span: info.ast.span,
                    });
                }
            }
        }

        // 3. Set terminator
        let succs = &block_succs[block_idx];
        let last_node = *blocks_nodes[block_idx].last().unwrap();
        let last_info = &cfg[last_node];

        ssa_blocks[block_idx].terminator = if succs.is_empty() {
            // Check if this block contains a Return node with no uses (constant
            // or void return). The Return node may not be the last_node — Exit
            // often follows Return in the same block.
            let has_const_return = blocks_nodes[block_idx].iter().any(|&n| {
                let info = &cfg[n];
                info.kind == StmtKind::Return && info.taint.uses.is_empty()
            });

            if has_const_return {
                // Return with no uses: the return expression is a constant literal
                // or the return is void. Emit a synthetic Const instruction so that
                // Return(Some(v_const)) correctly has no taint entry — preventing
                // the last body instruction (which may be an unrelated tainted
                // value) from being treated as the return value.
                //
                // Carry the literal text through when `cfg` captured it
                // on the Return node (populated by `extract_literal_rhs`
                // for `return []`, `return {}`, etc.).  Downstream
                // container-literal detection — including the
                // fresh-container-factory detector in
                // [`crate::ssa::param_points_to`] — depends on that text
                // surviving into `SsaOp::Const(Some(text))`.
                let return_node = blocks_nodes[block_idx]
                    .iter()
                    .copied()
                    .find(|&n| {
                        let info = &cfg[n];
                        info.kind == StmtKind::Return && info.taint.uses.is_empty()
                    })
                    .unwrap_or(last_node);
                let const_text = cfg[return_node].taint.const_text.clone();
                let const_v = SsaValue(*next_value);
                *next_value += 1;
                let block_id = BlockId(block_idx as u32);
                value_defs.push(ValueDef {
                    var_name: None,
                    cfg_node: last_node,
                    block: block_id,
                });
                ssa_blocks[block_idx].body.push(SsaInst {
                    value: const_v,
                    op: SsaOp::Const(const_text),
                    cfg_node: last_node,
                    var_name: None,
                    span: last_info.ast.span,
                });
                Terminator::Return(Some(const_v))
            } else {
                // Find the return value: last non-Nop body instruction that defines
                // a meaningful value.
                let ret_val = ssa_blocks[block_idx]
                    .body
                    .iter()
                    .rev()
                    .find(|inst| !matches!(inst.op, SsaOp::Nop))
                    .map(|inst| inst.value);
                Terminator::Return(ret_val)
            }
        } else if succs.len() == 1 {
            Terminator::Goto(BlockId(succs[0] as u32))
        } else if succs.len() == 2 {
            // Find the If/Loop node that branches
            let cond_node = blocks_nodes[block_idx]
                .iter()
                .rev()
                .find(|&&n| matches!(cfg[n].kind, StmtKind::If | StmtKind::Loop))
                .copied()
                .unwrap_or(last_node);

            // Determine which successor is true/false by looking at edge kinds
            let mut true_blk = succs[0];
            let mut false_blk = succs[1];

            // Check filtered edges from any node in this block to successors
            for &(src, tgt, kind) in filtered_edges {
                if blocks_nodes[block_idx].contains(&src) {
                    let tgt_blk_opt = succs.iter().position(|&s| {
                        blocks_nodes
                            .get(s)
                            .is_some_and(|nodes| nodes.contains(&tgt))
                    });
                    if let Some(tgt_blk_pos) = tgt_blk_opt {
                        match kind {
                            EdgeKind::True => true_blk = succs[tgt_blk_pos],
                            EdgeKind::False => false_blk = succs[tgt_blk_pos],
                            _ => {}
                        }
                    }
                }
            }

            // Lower structured condition from CFG metadata
            let cond_info = &cfg[cond_node];
            let condition = if cond_info.condition_text.is_some()
                && !cond_info.condition_vars.is_empty()
            {
                let expr =
                    crate::constraint::lower::lower_condition_with_stacks(cond_info, var_stacks);
                if matches!(expr, crate::constraint::lower::ConditionExpr::Unknown) {
                    None
                } else {
                    Some(Box::new(expr))
                }
            } else {
                None
            };

            Terminator::Branch {
                cond: cond_node,
                true_blk: BlockId(true_blk as u32),
                false_blk: BlockId(false_blk as u32),
                condition,
            }
        } else {
            // More than 2 successors — model as a multi-way Switch.
            //
            // This replaces the previous `Goto(first)` collapse: the
            // structured terminator now enumerates every target instead
            // of hiding N-1 of them behind `block.succs`. Flow consumers
            // (taint, const-prop, symex) still iterate `succs` as
            // authoritative, but downstream tooling that inspects the
            // terminator shape gets the full fanout.
            //
            // Note: today's switch-statement CFG construction decomposes
            // cases into a cascade of binary `Branch` headers (see
            // `build_switch` in src/cfg.rs), so real switch statements
            // never reach this arm. Folding the cascade back into a
            // single Switch node is a follow-up; in the meantime, this
            // arm fires only on genuine multi-way CFG fanouts (e.g.
            // future Go-switch / Java-arrow / Rust-match lowerings).
            //
            // Scrutinee: use the primary SSA value defined at the last
            // node in this block when one exists; fall back to
            // `SsaValue(0)` (a valid index — SSA numbering is 1-based
            // only conceptually, and value 0 is always present in a
            // non-empty body) when no value is defined. Downstream
            // consumers that care about the scrutinee (abstract interp,
            // symex per-case constraints) treat a missing/degenerate
            // scrutinee as "unknown" rather than panicking.
            let scrutinee = cfg_node_map.get(&last_node).copied().unwrap_or(SsaValue(0));
            let targets: SmallVec<[BlockId; 4]> =
                succs.iter().skip(1).map(|&s| BlockId(s as u32)).collect();
            let default = BlockId(succs[0] as u32);
            tracing::debug!(
                block = block_idx,
                num_succs = succs.len(),
                "emitting Terminator::Switch for ≥3-way fanout",
            );
            Terminator::Switch {
                scrutinee,
                targets,
                default,
            }
        };

        // 4. Fill phi operands in successor blocks
        for &succ in succs {
            for (var, &phi_val) in &phi_values[succ] {
                // The version of `var` reaching from this block
                let reaching_val = var_stacks.get(var).and_then(|s| s.last().copied());
                if let Some(rv) = reaching_val {
                    // Find the phi instruction and add this operand
                    for phi in &mut ssa_blocks[succ].phis {
                        if phi.value == phi_val {
                            if let SsaOp::Phi(ref mut operands) = phi.op {
                                operands.push((block_id, rv));
                            }
                        }
                    }
                }
            }
        }

        // 5. Recurse into dominator tree children
        for &child in &dom_tree_children[block_idx] {
            process_block(
                child,
                cfg,
                blocks_nodes,
                block_succs,
                block_preds,
                phi_placements,
                dom_tree_children,
                filtered_edges,
                var_stacks,
                ssa_blocks,
                phi_values,
                value_defs,
                cfg_node_map,
                next_value,
                nop_nodes,
            );
        }

        // 6. Restore stacks
        for (var, depth) in &saved {
            if let Some(stack) = var_stacks.get_mut(var) {
                stack.truncate(*depth);
            }
        }
        // Remove any new variables that weren't in saved
        let saved_vars: HashSet<&String> = saved.iter().map(|(k, _)| k).collect();
        var_stacks.retain(|k, _| saved_vars.contains(k));
    }

    // Inject synthetic Param instructions at START of block 0 for external variables.
    // These create SSA definitions so the rename pass can reference them.
    // Pre-seed var_stacks so process_block sees them.
    if !external_vars.is_empty() {
        let entry_cfg_node = blocks_nodes[0][0];
        let mut synthetic_body = Vec::with_capacity(external_vars.len());
        let mut positional_idx: usize = 0;
        for var in external_vars.iter() {
            let v = SsaValue(next_value);
            next_value += 1;
            value_defs.push(ValueDef {
                var_name: Some(var.clone()),
                cfg_node: entry_cfg_node,
                block: BlockId(0),
            });
            let op = if is_receiver_name(var) {
                SsaOp::SelfParam
            } else {
                let op = SsaOp::Param {
                    index: positional_idx,
                };
                positional_idx += 1;
                op
            };
            synthetic_body.push(SsaInst {
                value: v,
                op,
                cfg_node: entry_cfg_node,
                var_name: Some(var.clone()),
                span: (0, 0),
            });
            var_stacks.entry(var.clone()).or_default().push(v);
        }
        // Prepend synthetic params before any existing body instructions
        synthetic_body.append(&mut ssa_blocks[0].body);
        ssa_blocks[0].body = synthetic_body;
    }

    process_block(
        0, // entry block
        cfg,
        blocks_nodes,
        block_succs,
        block_preds,
        phi_placements,
        dom_tree_children,
        filtered_edges,
        &mut var_stacks,
        &mut ssa_blocks,
        &mut phi_values,
        &mut value_defs,
        &mut cfg_node_map,
        &mut next_value,
        nop_nodes,
    );

    // Process orphan blocks (e.g. catch blocks disconnected after exception edge removal).
    // These blocks have no predecessors and weren't reached by the dominator tree walk.
    //
    // Rebuild var_stacks from already-processed instructions so that catch blocks
    // can reference variables defined before the try block (e.g. `userInput`).
    let has_orphans =
        (1..num_blocks).any(|bid| block_preds[bid].is_empty() && ssa_blocks[bid].body.is_empty());
    if has_orphans {
        // Rebuild var_stacks from all SSA instructions created during the main walk.
        // This gives orphan blocks access to all variable definitions.
        var_stacks.clear();
        for block in &ssa_blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if let Some(ref name) = inst.var_name {
                    var_stacks.entry(name.clone()).or_default().push(inst.value);
                }
            }
        }

        for bid in 1..num_blocks {
            if block_preds[bid].is_empty() && ssa_blocks[bid].body.is_empty() {
                process_block(
                    bid,
                    cfg,
                    blocks_nodes,
                    block_succs,
                    block_preds,
                    phi_placements,
                    dom_tree_children,
                    filtered_edges,
                    &mut var_stacks,
                    &mut ssa_blocks,
                    &mut phi_values,
                    &mut value_defs,
                    &mut cfg_node_map,
                    &mut next_value,
                    nop_nodes,
                );
            }
        }
    }

    (ssa_blocks, value_defs, cfg_node_map)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Debug invariant checkers
// ─────────────────────────────────────────────────────────────────────────────

/// Verify BFS block ordering: every non-entry, non-orphan block must have at
/// least one predecessor with a smaller block ID.
#[cfg(debug_assertions)]
fn debug_assert_bfs_ordering(block_preds: &[Vec<usize>]) {
    for (i, preds) in block_preds.iter().enumerate() {
        if i == 0 {
            continue; // entry block
        }
        if preds.is_empty() {
            continue; // orphan block (e.g. catch block reached via exception edge)
        }
        let has_forward_pred = preds.iter().any(|&p| p < i);
        debug_assert!(
            has_forward_pred,
            "Block {} has no forward predecessor — BFS ordering violated. Preds: {:?}",
            i, preds
        );
    }
}

/// Verify phi operand counts: each phi must have exactly one operand
/// per predecessor, and every operand must reference an actual
/// predecessor of the block.
///
/// Runs in release builds because phi-operand mismatches are
/// load-bearing for soundness — downstream taint, const, and abstract
/// analyses iterate phi operands by `(pred_blk, value)` pairs, and
/// either a missing operand (silent "no contribution" on that edge)
/// or a phantom operand (garbage into the join) corrupts analysis
/// without surfacing.
///
/// The invariant is strict equality. Predecessors that carry no
/// reaching definition for the phi's variable are filled with the
/// [`SsaOp::Undef`] sentinel in `fill_undef_phi_operands`, rather than
/// being dropped — so consumers that look up by `(pred_blk, value)`
/// see a real operand for every control-flow edge.
fn assert_phi_operand_counts(ssa_blocks: &[SsaBlock], block_preds: &[Vec<usize>]) {
    use std::collections::HashSet;
    for (i, block) in ssa_blocks.iter().enumerate() {
        let pred_set: HashSet<u32> = block_preds[i].iter().map(|&p| p as u32).collect();
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                assert_eq!(
                    operands.len(),
                    block_preds[i].len(),
                    "SSA phi operand count does not match predecessor count: block {} phi v{} \
                     (var={:?}) has {} operands but block has {} predecessors. \
                     preds={:?}, operand_preds={:?}",
                    i,
                    phi.value.0,
                    phi.var_name,
                    operands.len(),
                    block_preds[i].len(),
                    block_preds[i],
                    operands.iter().map(|(b, _)| b.0).collect::<Vec<_>>(),
                );
                // Each operand's pred block must be an actual predecessor,
                // and no predecessor may appear more than once.
                let mut seen: HashSet<u32> = HashSet::new();
                for (pred_blk, _) in operands.iter() {
                    assert!(
                        pred_set.contains(&pred_blk.0),
                        "SSA phi operand references nonexistent predecessor: block {} phi v{} \
                         references pred B{} but block predecessors are {:?}",
                        i,
                        phi.value.0,
                        pred_blk.0,
                        block_preds[i],
                    );
                    assert!(
                        seen.insert(pred_blk.0),
                        "SSA phi operand duplicates predecessor: block {} phi v{} has two \
                         operands for pred B{}",
                        i,
                        phi.value.0,
                        pred_blk.0,
                    );
                }
            }
        }
    }
}

/// Post-rename pass: ensure every phi has one operand per predecessor.
///
/// During rename, phi operands are only pushed when the variable has a
/// live reaching definition on that predecessor edge. Edges where the
/// variable is not yet defined (e.g. a try-body rejoining after a
/// catch-only binding, an early-return branch on a later-defined
/// variable, an orphan catch block's implicit predecessors) leave the
/// phi with fewer operands than the block has predecessors.
///
/// This pass scans all phis, and for every missing `(pred_block, _)`
/// slot, pushes `(pred_block, undef_val)` where `undef_val` is a
/// single shared sentinel instruction ([`SsaOp::Undef`]) synthesized
/// at the end of block 0's body. Consumers iterate phi operands by
/// `(pred_blk, value)` and therefore see a real operand on every
/// control-flow edge — no implicit "missing = empty" semantics.
///
/// The Undef instruction is created lazily (only when at least one phi
/// has a gap) so functions with fully-dominating definitions pay zero
/// cost. All phis share the same Undef value: a phi operand is
/// identified by its `(pred_block, value)` pair, so sharing the value
/// across phis is safe and keeps the synthesized-instruction count at
/// most one per function body.
fn fill_undef_phi_operands(
    ssa_blocks: &mut [SsaBlock],
    block_preds: &[Vec<usize>],
    value_defs: &mut Vec<ValueDef>,
    blocks_nodes: &[Vec<NodeIndex>],
) {
    // Fast path: detect whether any phi has a gap. Avoid allocating
    // the Undef value in the common case where every phi is saturated.
    let needs_undef = ssa_blocks.iter().enumerate().any(|(bi, block)| {
        block.phis.iter().any(|phi| {
            if let SsaOp::Phi(ref operands) = phi.op {
                operands.len() < block_preds[bi].len()
            } else {
                false
            }
        })
    });
    if !needs_undef {
        return;
    }

    // Anchor the synthetic Undef instruction to the entry block's first
    // CFG node so span lookups don't hit an invalid NodeIndex.
    let anchor_node = blocks_nodes
        .first()
        .and_then(|b| b.first())
        .copied()
        .expect("entry block has at least one CFG node");

    let undef_val = SsaValue(value_defs.len() as u32);
    value_defs.push(ValueDef {
        var_name: None,
        cfg_node: anchor_node,
        block: BlockId(0),
    });
    // Place the Undef instruction at the end of block 0's body so it
    // appears after any synthetic Param / SelfParam emissions — its
    // only role is to anchor the SsaValue; ordering relative to other
    // body instructions is cosmetic (no consumer depends on its
    // position, only on the value lookup).
    ssa_blocks[0].body.push(SsaInst {
        value: undef_val,
        op: SsaOp::Undef,
        cfg_node: anchor_node,
        var_name: None,
        span: (0, 0),
    });

    // Fill missing operand slots. Iterate `block_preds[bi]` in its
    // natural order so the resulting phi operand list is deterministic
    // across runs.
    for (bi, block) in ssa_blocks.iter_mut().enumerate() {
        for phi in block.phis.iter_mut() {
            if let SsaOp::Phi(ref mut operands) = phi.op {
                if operands.len() == block_preds[bi].len() {
                    continue;
                }
                use std::collections::HashSet;
                let present: HashSet<u32> = operands.iter().map(|(b, _)| b.0).collect();
                for &pred in &block_preds[bi] {
                    let pid = pred as u32;
                    if !present.contains(&pid) {
                        operands.push((BlockId(pid), undef_val));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use petgraph::Graph;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn linear_cfg_no_phis() {
        // Entry → x=1 → y=x → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let n1 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let n2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, n1, EdgeKind::Seq);
        cfg.add_edge(n1, n2, EdgeKind::Seq);
        cfg.add_edge(n2, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Should be a single block (all Seq edges, no branches)
        assert_eq!(ssa.blocks.len(), 1);
        // No phis in a linear CFG
        assert!(ssa.blocks[0].phis.is_empty());
        // 4 body instructions (entry, x=1, y=x, exit)
        assert_eq!(ssa.blocks[0].body.len(), 4);
    }

    #[test]
    fn diamond_cfg_produces_phi() {
        // Entry → x=1 → If → [True: x=2] [False: x=3] → Join → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let true_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, true_node, EdgeKind::True);
        cfg.add_edge(if_node, false_node, EdgeKind::False);
        cfg.add_edge(true_node, join, EdgeKind::Seq);
        cfg.add_edge(false_node, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Should have multiple blocks
        assert!(ssa.blocks.len() >= 3);

        // The join block should have a phi for "x"
        let join_block = ssa
            .blocks
            .iter()
            .find(|b| !b.phis.is_empty())
            .expect("should have a block with a phi");
        assert_eq!(join_block.phis.len(), 1);
        assert_eq!(join_block.phis[0].var_name.as_deref(), Some("x"));

        // Phi should have 2 operands (from true and false branches)
        if let SsaOp::Phi(ref operands) = join_block.phis[0].op {
            assert_eq!(operands.len(), 2);
        } else {
            panic!("expected Phi op");
        }
    }

    #[test]
    fn loop_cfg_produces_phi() {
        // Entry → x=0 → Loop header → [Back: x=x+1] → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let loop_header = cfg.add_node(make_node(StmtKind::Loop));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, loop_header, EdgeKind::Seq);
        cfg.add_edge(loop_header, body, EdgeKind::True);
        cfg.add_edge(body, loop_header, EdgeKind::Back);
        cfg.add_edge(loop_header, exit, EdgeKind::False);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Loop header block should have a phi for "x" (from entry and back edge)
        let header_phis: Vec<_> = ssa.blocks.iter().filter(|b| !b.phis.is_empty()).collect();

        assert!(
            !header_phis.is_empty(),
            "loop header should have a phi for x"
        );

        let x_phi = header_phis[0]
            .phis
            .iter()
            .find(|p| p.var_name.as_deref() == Some("x"));
        assert!(x_phi.is_some(), "should have phi for variable x");
    }

    #[test]
    fn multiple_reassignments_distinct_values() {
        // Entry → x=1 → x=2 → x=3 → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let n1 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let n2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let n3 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, n1, EdgeKind::Seq);
        cfg.add_edge(n1, n2, EdgeKind::Seq);
        cfg.add_edge(n2, n3, EdgeKind::Seq);
        cfg.add_edge(n3, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Each definition of x should produce a distinct SsaValue
        let x_values: Vec<_> = ssa
            .value_defs
            .iter()
            .enumerate()
            .filter(|(_, vd)| vd.var_name.as_deref() == Some("x"))
            .map(|(i, _)| SsaValue(i as u32))
            .collect();

        assert_eq!(x_values.len(), 3, "three definitions of x");
        // All distinct
        let unique: HashSet<_> = x_values.iter().collect();
        assert_eq!(unique.len(), 3, "all SsaValues should be distinct");
    }

    #[test]
    fn empty_cfg_returns_error() {
        let cfg: Cfg = Graph::new();
        let result = lower_to_ssa(&cfg, NodeIndex::new(0), None, true);
        assert!(result.is_err());
    }

    // ── BFS ordering and phi invariant tests ─────────────────────────────

    #[test]
    fn bfs_ordering_holds_for_linear_cfg() {
        // Entry → A → B → Exit — all blocks should satisfy BFS ordering
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let a = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let b = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, a, EdgeKind::Seq);
        cfg.add_edge(a, b, EdgeKind::Seq);
        cfg.add_edge(b, exit, EdgeKind::Seq);

        // This exercises the debug_assert_bfs_ordering in debug builds
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());
    }

    #[test]
    fn bfs_ordering_holds_for_diamond_cfg() {
        // Entry → If → [True] [False] → Join → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let true_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, true_node, EdgeKind::True);
        cfg.add_edge(if_node, false_node, EdgeKind::False);
        cfg.add_edge(true_node, join, EdgeKind::Seq);
        cfg.add_edge(false_node, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        // Exercises both BFS ordering and phi operand count assertions
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        // The join block should have a phi with exactly 2 operands (== 2 preds)
        let phi_block = ssa.blocks.iter().find(|b| !b.phis.is_empty());
        if let Some(block) = phi_block {
            assert_eq!(
                block.preds.len(),
                2,
                "join block should have 2 predecessors"
            );
            for phi in &block.phis {
                if let SsaOp::Phi(ref ops) = phi.op {
                    assert!(
                        ops.len() <= block.preds.len(),
                        "phi operands should not exceed predecessor count"
                    );
                }
            }
        }
    }

    #[test]
    fn bfs_ordering_holds_for_loop_with_back_edge() {
        // Entry → x=0 → Loop → body(x=x+1) → [Back→Loop] → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let loop_h = cfg.add_node(make_node(StmtKind::Loop));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, loop_h, EdgeKind::Seq);
        cfg.add_edge(loop_h, body, EdgeKind::True);
        cfg.add_edge(body, loop_h, EdgeKind::Back);
        cfg.add_edge(loop_h, exit, EdgeKind::False);

        // Exercises BFS ordering with back edges and phi on loop header
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());
    }

    #[test]
    fn orphan_catch_block_does_not_violate_bfs_ordering() {
        // Entry → body → Exit, with an exception edge body → catch → Exit
        // The catch block becomes an orphan (no normal-flow predecessors)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let catch = cfg.add_node(NodeInfo {
            catch_param: true,
            taint: TaintMeta {
                defines: Some("e".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, body, EdgeKind::Seq);
        cfg.add_edge(body, exit, EdgeKind::Seq);
        cfg.add_edge(body, catch, EdgeKind::Exception);
        cfg.add_edge(catch, exit, EdgeKind::Seq);

        // The catch block is reached via exception edge (stripped from normal flow)
        // so it may appear as an orphan. The BFS assertion should skip it.
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());
    }

    #[test]
    fn phi_operand_count_equals_pred_count_in_diamond() {
        // Specific test: phi operands == predecessor count (not just <=)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let t = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("v".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let f = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("v".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["v".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, t, EdgeKind::True);
        cfg.add_edge(if_node, f, EdgeKind::False);
        cfg.add_edge(t, join, EdgeKind::Seq);
        cfg.add_edge(f, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        let phi_block = ssa
            .blocks
            .iter()
            .find(|b| !b.phis.is_empty())
            .expect("should have a phi block");

        for phi in &phi_block.phis {
            if let SsaOp::Phi(ref ops) = phi.op {
                assert_eq!(
                    ops.len(),
                    phi_block.preds.len(),
                    "phi operand count should equal predecessor count in a clean diamond"
                );
            }
        }
    }

    #[test]
    fn bfs_assertion_helper_accepts_valid_orderings() {
        // Direct unit test of the assertion helper with valid input
        let block_preds = vec![
            vec![],     // block 0: entry (no preds)
            vec![0],    // block 1: pred is block 0 (forward)
            vec![0, 1], // block 2: both forward preds
            vec![],     // block 3: orphan (no preds)
            vec![2],    // block 4: forward pred
        ];
        // Should not panic
        debug_assert_bfs_ordering(&block_preds);
    }

    /// Regression guard: a catch block that joins an exception
    /// predecessor and a normal control-flow predecessor must lower to a
    /// consistent phi. For variables defined before the try (live on
    /// *both* edges), the phi at the catch block has exactly two operands
    /// — one per predecessor — and the release assertion accepts it.
    #[test]
    fn catch_block_join_phi_has_operand_per_live_predecessor() {
        // Entry → defines `x` → Try → (Seq) → Join ← (Exception via body) Catch
        //                                                      ↑
        //                         A phi for `x` at the join block should carry
        //                         one operand from each of its two predecessors.
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let define_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let catch = cfg.add_node(NodeInfo {
            catch_param: true,
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, define_x, EdgeKind::Seq);
        cfg.add_edge(define_x, body, EdgeKind::Seq);
        cfg.add_edge(body, join, EdgeKind::Seq);
        cfg.add_edge(body, catch, EdgeKind::Exception);
        cfg.add_edge(catch, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        // Lowering must succeed — the assertion is active in release.
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Locate the block containing a phi for `x`; it must be the join
        // block with two reachable predecessors. The phi must have
        // exactly two operands.
        let phi_block = ssa
            .blocks
            .iter()
            .find(|b| {
                b.phis
                    .iter()
                    .any(|p| p.var_name.as_deref() == Some("x") && matches!(p.op, SsaOp::Phi(_)))
            })
            .expect("expected a phi for `x` at the catch/normal join");
        assert_eq!(
            phi_block.preds.len(),
            2,
            "catch/normal join block must have 2 predecessors, got {}",
            phi_block.preds.len()
        );
        let phi_for_x = phi_block
            .phis
            .iter()
            .find(|p| p.var_name.as_deref() == Some("x"))
            .unwrap();
        if let SsaOp::Phi(ref operands) = phi_for_x.op {
            assert_eq!(
                operands.len(),
                2,
                "phi for `x` at the catch/normal join must have one operand per \
                 predecessor, got {}",
                operands.len()
            );
        } else {
            panic!("expected SsaOp::Phi for `x`");
        }
    }

    /// Regression guard for the Undef fill pass. When a variable is
    /// only defined on one branch of a join (e.g. a catch-only binding
    /// rejoining the normal path), the lowering must still emit one
    /// phi operand per predecessor — the missing edge becoming a
    /// reference to the synthesized `SsaOp::Undef` sentinel rather
    /// than being dropped.
    #[test]
    fn partial_phi_edge_fills_with_undef_sentinel() {
        // Entry → Body → Join
        //           ↓
        //        Catch (defines `e`) → Join
        //
        // `e` is defined only on the exception path; on the normal path
        // from Body → Join it has no reaching definition. The phi for `e`
        // at Join must have two operands (one per predecessor), with the
        // Body-side operand pointing at the Undef sentinel.
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let body = cfg.add_node(make_node(StmtKind::Seq));
        let catch = cfg.add_node(NodeInfo {
            catch_param: true,
            taint: TaintMeta {
                defines: Some("e".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["e".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, body, EdgeKind::Seq);
        cfg.add_edge(body, join, EdgeKind::Seq);
        cfg.add_edge(body, catch, EdgeKind::Exception);
        cfg.add_edge(catch, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Find the phi for `e`.
        let phi_block = ssa
            .blocks
            .iter()
            .find(|b| b.phis.iter().any(|p| p.var_name.as_deref() == Some("e")))
            .expect("expected a phi for `e`");
        let phi_for_e = phi_block
            .phis
            .iter()
            .find(|p| p.var_name.as_deref() == Some("e"))
            .unwrap();
        let operands = match &phi_for_e.op {
            SsaOp::Phi(ops) => ops,
            _ => panic!("expected SsaOp::Phi for `e`"),
        };

        // Strict invariant: one operand per predecessor.
        assert_eq!(
            operands.len(),
            phi_block.preds.len(),
            "phi for `e` must have one operand per predecessor",
        );

        // At least one operand must reference the Undef sentinel (the
        // Body-side edge where `e` has no reaching definition).
        let found_inst = |v: SsaValue| -> Option<&SsaInst> {
            ssa.blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .find(|i| i.value == v)
        };
        let any_undef = operands.iter().any(|(_, v)| {
            found_inst(*v)
                .map(|i| matches!(i.op, SsaOp::Undef))
                .unwrap_or(false)
        });
        assert!(
            any_undef,
            "phi for `e` at the catch-join must reference SsaOp::Undef \
             on the normal-path predecessor edge",
        );
    }

    #[test]
    fn phi_assertion_helper_accepts_exact_operand_count() {
        // Direct test of the assertion helper: a phi with exactly as many
        // operands as the block has predecessors must not panic.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(1)),
                    (BlockId(2), SsaValue(2)),
                ]),
                cfg_node: dummy_node,
                var_name: Some("x".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2], vec![0]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![BlockId(0)],
                    succs: smallvec::smallvec![BlockId(1)],
                },
            ],
            &block_preds,
        );
    }

    #[test]
    #[should_panic(expected = "SSA phi operand count does not match predecessor count")]
    fn phi_assertion_helper_rejects_more_operands_than_preds() {
        // A phi with MORE operands than preds references a nonexistent
        // predecessor — unsound because downstream consumers either
        // panic on the lookup or silently feed garbage taint into the
        // join. Strict-equality invariant catches this.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(1)),
                    (BlockId(2), SsaValue(2)),
                    (BlockId(3), SsaValue(3)),
                ]),
                cfg_node: dummy_node,
                var_name: Some("x".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
            ],
            &block_preds,
        );
    }

    #[test]
    #[should_panic(expected = "SSA phi operand count does not match predecessor count")]
    fn phi_assertion_helper_rejects_fewer_operands_than_preds() {
        // A phi with fewer operands than preds violates the strict-equality
        // invariant: `fill_undef_phi_operands` is responsible for filling
        // every missing slot with an Undef sentinel, so the final body
        // should never have gaps. This test guards the post-pass.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![(BlockId(0), SsaValue(1))]),
                cfg_node: dummy_node,
                var_name: Some("e".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
            ],
            &block_preds,
        );
    }

    #[test]
    #[should_panic(expected = "SSA phi operand references nonexistent predecessor")]
    fn phi_assertion_helper_rejects_wrong_pred_block() {
        // A phi with the correct operand count but referencing a block
        // that isn't actually a predecessor must also fail the invariant.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(1)),
                    (BlockId(3), SsaValue(2)),
                ]),
                cfg_node: dummy_node,
                var_name: Some("x".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
            ],
            &block_preds,
        );
    }

    #[test]
    fn three_successor_collapse_produces_switch() {
        // Build a CFG where a single node has 3 successors. Phase 12.4
        // promotes the old `Goto(first)` collapse to a structured
        // `Terminator::Switch` so every target is visible on the
        // terminator shape (not only on `block.succs`).
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let branch = cfg.add_node(make_node(StmtKind::If));
        let s0 = cfg.add_node(make_node(StmtKind::Seq));
        let s1 = cfg.add_node(make_node(StmtKind::Seq));
        let s2 = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, branch, EdgeKind::Seq);
        cfg.add_edge(branch, s0, EdgeKind::True);
        cfg.add_edge(branch, s1, EdgeKind::False);
        cfg.add_edge(branch, s2, EdgeKind::Seq);
        cfg.add_edge(s0, exit, EdgeKind::Seq);
        cfg.add_edge(s1, exit, EdgeKind::Seq);
        cfg.add_edge(s2, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());

        let switch_block = ssa
            .blocks
            .iter()
            .find(|b| matches!(b.terminator, Terminator::Switch { .. }) && b.succs.len() >= 3)
            .expect("expected a block with a Switch terminator and ≥3 succs");

        assert_eq!(
            switch_block.succs.len(),
            3,
            "≥3-successor lowering must retain all succs on block.succs, got {:?}",
            switch_block.succs
        );

        if let Terminator::Switch {
            targets, default, ..
        } = &switch_block.terminator
        {
            // Default is the first succ (deterministic ordering); the
            // remaining N-1 succs populate `targets` in order.
            assert_eq!(
                *default, switch_block.succs[0],
                "Switch default must match succs[0]"
            );
            assert_eq!(
                targets.len(),
                switch_block.succs.len() - 1,
                "Switch targets must cover every succ except default"
            );
            for (i, t) in targets.iter().enumerate() {
                assert_eq!(
                    *t,
                    switch_block.succs[i + 1],
                    "Switch target[{i}] must match succs[{}]",
                    i + 1
                );
            }
        }
    }

    #[test]
    fn normal_two_successor_produces_branch() {
        // Regression: normal 2-successor case should still produce Branch
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let t = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let f = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, t, EdgeKind::True);
        cfg.add_edge(if_node, f, EdgeKind::False);
        cfg.add_edge(t, exit, EdgeKind::Seq);
        cfg.add_edge(f, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        let has_branch = ssa
            .blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Branch { .. }));
        assert!(
            has_branch,
            "normal 2-successor case must produce Branch, not Goto"
        );
    }
}
