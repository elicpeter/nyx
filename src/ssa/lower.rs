use crate::cfg::{Cfg, EdgeKind, StmtKind};
use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::graph::NodeIndex;
use petgraph::prelude::*;
use petgraph::visit::{Bfs, EdgeRef};
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet, VecDeque};

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
                None => info.enclosing_func.is_none(),
                Some(name) => info.enclosing_func.as_deref() == Some(name),
            }
        };
        reachable.iter()
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
    let (block_graph, block_graph_entry) =
        build_block_graph(num_blocks, &block_succs, BlockId(0));
    let doms = simple_fast(&block_graph, block_graph_entry);

    // 3. Compute dominance frontiers
    let dom_frontiers = compute_dominance_frontiers(num_blocks, &block_preds, &doms, &block_graph);

    // 4. Collect variable definitions per block (skip nop nodes)
    let mut var_defs = collect_var_defs(cfg, &blocks_nodes, &nop_nodes);

    // 4b. For per-function scope: identify external variables (used but not defined)
    //     and inject synthetic Param defs at entry block so rename can find them.
    //     When formal_params is supplied, reorder so formal params come first in
    //     declaration order — this makes Param indices correspond to call-site positions.
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
    let (mut ssa_blocks, value_defs, cfg_node_map) = rename_variables(
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

    // 8. Map exception edges from CFG node indices to SSA block IDs
    let exception_edges: Vec<(BlockId, BlockId)> = raw_exception_edges
        .iter()
        .filter_map(|(src_node, catch_node)| {
            let src_block = block_of_node.get(src_node)?;
            let catch_block = block_of_node.get(catch_node)?;
            Some((BlockId(*src_block as u32), BlockId(*catch_block as u32)))
        })
        .collect();

    Ok(SsaBody {
        blocks: ssa_blocks,
        entry: BlockId(0),
        value_defs,
        cfg_node_map,
        exception_edges,
    })
}

/// Collect reachable nodes (BFS from entry), filtering by scope and stripping exception edges.
/// Returns (reachable set, filtered edges, exception edges as (src_node, catch_node)).
fn collect_reachable(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
) -> (HashSet<NodeIndex>, Vec<(NodeIndex, NodeIndex, EdgeKind)>, Vec<(NodeIndex, NodeIndex)>) {
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
            None => info.enclosing_func.is_none(),
            Some(name) => info.enclosing_func.as_deref() == Some(name),
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
            if !in_scope(target)
                && !matches!(cfg[target].kind, StmtKind::Entry | StmtKind::Exit)
            {
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
            if succs.len() == 1 && matches!(succs[0].1, EdgeKind::Seq) && !is_leader.contains(&succs[0].0) {
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
/// synthetic Param instructions so the SSA rename phase can reference them.
fn identify_external_uses(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    var_defs: &HashMap<String, HashSet<usize>>,
) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::new();
    for nodes in blocks_nodes {
        for &node in nodes {
            for u in &cfg[node].uses {
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

/// Reorder external variables so that formal function parameters come first
/// in their declaration order, followed by remaining external vars in
/// alphabetical order. This ensures `SsaOp::Param { index }` indices 0..N
/// correspond to call-site argument positions rather than alphabetical order.
fn reorder_external_vars(external: Vec<String>, formal_params: &[String]) -> Vec<String> {
    if formal_params.is_empty() {
        return external; // no reordering — preserve existing alphabetical sort
    }
    let ext_set: HashSet<&str> = external.iter().map(|s| s.as_str()).collect();
    let formal_set: HashSet<&str> = formal_params.iter().map(|s| s.as_str()).collect();
    let mut result = Vec::with_capacity(external.len());
    // Formal params first, in declaration order (only those present in external set)
    for p in formal_params {
        if ext_set.contains(p.as_str()) {
            result.push(p.clone());
        }
    }
    // Remaining external vars alphabetically (external is already sorted)
    for v in external {
        if !formal_set.contains(v.as_str()) {
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
) -> HashMap<String, HashSet<usize>> {
    let mut defs: HashMap<String, HashSet<usize>> = HashMap::new();

    for (block_idx, nodes) in blocks_nodes.iter().enumerate() {
        for &node in nodes {
            if nop_nodes.contains(&node) {
                continue;
            }
            if let Some(ref d) = cfg[node].defines {
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
            for ed in &cfg[node].extra_defines {
                defs.entry(ed.clone()).or_default().insert(block_idx);
            }
        }
    }

    defs
}

/// Cytron-style phi insertion: returns phi_placements[block] = set of var names needing phis.
fn insert_phis(
    var_defs: &HashMap<String, HashSet<usize>>,
    dom_frontiers: &[HashSet<usize>],
    _num_blocks: usize,
) -> Vec<HashSet<String>> {
    let num_blocks = dom_frontiers.len();
    let mut phi_placements: Vec<HashSet<String>> = vec![HashSet::new(); num_blocks];

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
    phi_placements: &[HashSet<String>],
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

    let mut phi_values: Vec<HashMap<String, SsaValue>> = vec![HashMap::new(); num_blocks];

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
                span: cfg[cfg_node].span,
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
        phi_placements: &[HashSet<String>],
        dom_tree_children: &[Vec<usize>],
        filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
        var_stacks: &mut HashMap<String, Vec<SsaValue>>,
        ssa_blocks: &mut [SsaBlock],
        phi_values: &mut [HashMap<String, SsaValue>],
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

            // Helper: build Call args from arg_uses, falling back to info.uses
            let build_call_args = |info: &crate::cfg::NodeInfo,
                                   var_stacks: &HashMap<String, Vec<SsaValue>>|
                -> (Vec<SmallVec<[SsaValue; 2]>>, Option<SsaValue>) {
                let receiver = info.receiver.as_ref().and_then(|r| {
                    var_stacks.get(r).and_then(|s| s.last().copied())
                });
                let args = if !info.arg_uses.is_empty() {
                    let mut args: Vec<SmallVec<[SsaValue; 2]>> = info.arg_uses
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
                    // calls (like `url` in fetch) are in info.uses but not arg_uses.
                    // Add them as an extra group so sink detection can see them.
                    let arg_uses_flat: HashSet<&str> = info.arg_uses
                        .iter()
                        .flat_map(|g| g.iter().map(|s| s.as_str()))
                        .collect();
                    let implicit: SmallVec<[SsaValue; 2]> = info
                        .uses
                        .iter()
                        .filter(|u| !arg_uses_flat.contains(u.as_str()))
                        .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                        .collect();
                    if !implicit.is_empty() {
                        args.push(implicit);
                    }
                    args
                } else {
                    // Fallback: treat all uses as a single argument group
                    let all_uses: SmallVec<[SsaValue; 2]> = info
                        .uses
                        .iter()
                        .filter_map(|u| {
                            var_stacks.get(u).and_then(|s| s.last().copied())
                        })
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
            } else if info.labels.iter().any(|l| {
                matches!(l, crate::labels::DataLabel::Source(_))
            }) && info.callee.is_none() {
                // Pure source (e.g. $_GET, env var) — no callee, so no args to track.
                // Source-labeled calls (e.g. file_get_contents) fall through to Call
                // so argument taint and sink detection still work.
                SsaOp::Source
            } else if info.callee.is_some() {
                let callee = info.callee.as_deref().unwrap_or("").to_string();
                let (args, receiver) = build_call_args(info, var_stacks);
                SsaOp::Call {
                    callee,
                    args,
                    receiver,
                }
            } else if info.defines.is_some() && info.uses.is_empty()
                && !info.labels.iter().any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
            {
                // Reassignment kill: a node that defines a variable but has no
                // uses (operands) and is not a source is a constant/literal
                // assignment.  SSA rename allocates a fresh SsaValue, so
                // downstream references see this new (untainted) value — the
                // prior tainted definition is implicitly dead.
                SsaOp::Const(info.const_text.clone())
            } else if info.defines.is_some() {
                let uses: SmallVec<[SsaValue; 4]> = info
                    .uses
                    .iter()
                    .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                    .collect();
                SsaOp::Assign(uses)
            } else if matches!(info.kind, StmtKind::Entry | StmtKind::Exit | StmtKind::If | StmtKind::Loop | StmtKind::Break | StmtKind::Continue | StmtKind::Return) {
                SsaOp::Nop
            } else if info.callee.is_some() {
                let callee = info.callee.as_deref().unwrap_or("").to_string();
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
            let var_name_for_ssa = if nop_nodes.contains(&node) { None } else { info.defines.clone() };
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
            let primary_op_for_extras = if info.extra_defines.is_empty() {
                None
            } else {
                Some(op.clone())
            };
            ssa_blocks[block_idx].body.push(SsaInst {
                value: v,
                op,
                cfg_node: node,
                var_name: var_name_for_ssa.clone(),
                span: info.span,
            });

            // Synthetic base update: when a dotted path is defined (e.g. `obj.data`),
            // create synthetic Assign instructions for parent prefixes (e.g. `obj`)
            // so that subsequent reads of the base variable see the field write.
            // Only includes the new field value (not the old base) so that field
            // overwrites properly kill taint: if obj.data is re-assigned to a
            // constant, the base `obj` no longer carries that field's taint.
            if !nop_nodes.contains(&node) {
                if let Some(ref d) = info.defines {
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
                            span: info.span,
                        });
                        child_value = synth_v;
                        current = parent;
                    }
                }
            }

            // Emit extra SSA instructions for destructuring bindings.
            // Each extra define inherits the same op (Source/Call/Assign) as the primary.
            if let Some(ref primary_op) = primary_op_for_extras {
                for extra_def in &info.extra_defines {
                    let ev = SsaValue(*next_value);
                    *next_value += 1;
                    value_defs.push(ValueDef {
                        var_name: Some(extra_def.clone()),
                        cfg_node: node,
                        block: block_id,
                    });
                    var_stacks
                        .entry(extra_def.clone())
                        .or_default()
                        .push(ev);
                    ssa_blocks[block_idx].body.push(SsaInst {
                        value: ev,
                        op: primary_op.clone(),
                        cfg_node: node,
                        var_name: Some(extra_def.clone()),
                        span: info.span,
                    });
                }
            }
        }

        // 3. Set terminator
        let succs = &block_succs[block_idx];
        let last_node = *blocks_nodes[block_idx].last().unwrap();
        let last_info = &cfg[last_node];

        ssa_blocks[block_idx].terminator = if succs.is_empty() {
            if last_info.kind == StmtKind::Return {
                Terminator::Return
            } else {
                Terminator::Return // Exit or dead end
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
                        blocks_nodes.get(s).is_some_and(|nodes| nodes.contains(&tgt))
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
                let expr = crate::constraint::lower::lower_condition_with_stacks(
                    cond_info, var_stacks,
                );
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
            // More than 2 successors — use Goto to first (shouldn't happen in practice)
            Terminator::Goto(BlockId(succs[0] as u32))
        };

        // 4. Fill phi operands in successor blocks
        for &succ in succs {
            for (var, &phi_val) in &phi_values[succ] {
                // The version of `var` reaching from this block
                let reaching_val = var_stacks
                    .get(var)
                    .and_then(|s| s.last().copied());
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
    // These create SSA definitions so the rename phase can reference them.
    // Pre-seed var_stacks so process_block sees them.
    if !external_vars.is_empty() {
        let entry_cfg_node = blocks_nodes[0][0];
        let mut synthetic_body = Vec::with_capacity(external_vars.len());
        for (i, var) in external_vars.iter().enumerate() {
            let v = SsaValue(next_value);
            next_value += 1;
            value_defs.push(ValueDef {
                var_name: Some(var.clone()),
                cfg_node: entry_cfg_node,
                block: BlockId(0),
            });
            synthetic_body.push(SsaInst {
                value: v,
                op: SsaOp::Param { index: i },
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
    let has_orphans = (1..num_blocks).any(|bid| {
        block_preds[bid].is_empty() && ssa_blocks[bid].body.is_empty()
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{EdgeKind, NodeInfo, StmtKind};
    use petgraph::Graph;
    use smallvec::SmallVec;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            span: (0, 0),
            labels: SmallVec::new(),
            defines: None,
            extra_defines: vec![],
            uses: vec![],
            callee: None,
            receiver: None,
            enclosing_func: None,
            call_ordinal: 0,
            condition_text: None,
            condition_vars: vec![],
            condition_negated: false,
            arg_uses: vec![],
            sink_payload_args: None,
            all_args_literal: false,
            catch_param: false,
            const_text: None,
            arg_callees: Vec::new(),
            outer_callee: None,
            cast_target_type: None,
            bin_op: None,
        }
    }

    #[test]
    fn linear_cfg_no_phis() {
        // Entry → x=1 → y=x → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let n1 = cfg.add_node(NodeInfo {
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let n2 = cfg.add_node(NodeInfo {
            defines: Some("y".into()),
            uses: vec!["x".into()],
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
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let true_node = cfg.add_node(NodeInfo {
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let false_node = cfg.add_node(NodeInfo {
            defines: Some("x".into()),
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
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let loop_header = cfg.add_node(make_node(StmtKind::Loop));
        let body = cfg.add_node(NodeInfo {
            defines: Some("x".into()),
            uses: vec!["x".into()],
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
        let header_phis: Vec<_> = ssa
            .blocks
            .iter()
            .filter(|b| !b.phis.is_empty())
            .collect();

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
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let n2 = cfg.add_node(NodeInfo {
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let n3 = cfg.add_node(NodeInfo {
            defines: Some("x".into()),
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, n1, EdgeKind::Seq);
        cfg.add_edge(n1, n2, EdgeKind::Seq);
        cfg.add_edge(n2, n3, EdgeKind::Seq);
        cfg.add_edge(n3, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Each definition of x should produce a distinct SsaValue
        let x_values: Vec<_> = ssa.value_defs
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
}
