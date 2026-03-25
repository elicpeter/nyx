import type {
  GraphCompactionResult,
  GraphEdgeModel,
  GraphModel,
  GraphNodeModel,
} from '../types';

const CONTROL_KINDS = new Set([
  'Entry',
  'Exit',
  'If',
  'Loop',
  'Return',
  'Break',
  'Continue',
]);

function buildLineRange(nodes: GraphNodeModel[]): string | undefined {
  const lines = nodes
    .map((node) => node.line)
    .filter((line): line is number => typeof line === 'number' && line > 0);

  if (lines.length === 0) return undefined;
  const minLine = Math.min(...lines);
  const maxLine = Math.max(...lines);
  return minLine === maxLine ? `L${minLine}` : `L${minLine}-L${maxLine}`;
}

export function compactGraph(graph: GraphModel): GraphCompactionResult {
  if (graph.kind !== 'cfg' || graph.nodes.length <= 3) {
    return { graph, compounds: new Map() };
  }

  const seqOut = new Map<string, string>();
  const seqIn = new Map<string, string>();
  const seqOutCount = new Map<string, number>();
  const seqInCount = new Map<string, number>();
  const totalOutCount = new Map<string, number>();
  const totalInCount = new Map<string, number>();

  for (const node of graph.nodes) {
    seqOutCount.set(node.key, 0);
    seqInCount.set(node.key, 0);
    totalOutCount.set(node.key, 0);
    totalInCount.set(node.key, 0);
  }

  for (const edge of graph.edges) {
    totalOutCount.set(edge.source, (totalOutCount.get(edge.source) ?? 0) + 1);
    totalInCount.set(edge.target, (totalInCount.get(edge.target) ?? 0) + 1);

    if (edge.kind !== 'Seq') continue;
    seqOutCount.set(edge.source, (seqOutCount.get(edge.source) ?? 0) + 1);
    seqInCount.set(edge.target, (seqInCount.get(edge.target) ?? 0) + 1);
    seqOut.set(edge.source, edge.target);
    seqIn.set(edge.target, edge.source);
  }

  const nodeMap = new Map(graph.nodes.map((node) => [node.key, node]));
  const chainable = new Set<string>();

  for (const node of graph.nodes) {
    if (CONTROL_KINDS.has(node.kind)) continue;

    if (
      totalInCount.get(node.key) === 1 &&
      totalOutCount.get(node.key) === 1 &&
      seqInCount.get(node.key) === 1 &&
      seqOutCount.get(node.key) === 1
    ) {
      chainable.add(node.key);
    }
  }

  const consumed = new Set<string>();
  const chains: string[][] = [];

  for (const node of graph.nodes) {
    if (consumed.has(node.key) || chainable.has(node.key)) continue;
    if (seqOutCount.get(node.key) !== 1) continue;

    const next = seqOut.get(node.key);
    if (!next || !chainable.has(next)) continue;

    const chain: string[] = [];
    let cursor: string | undefined = next;
    while (cursor && chainable.has(cursor) && !consumed.has(cursor)) {
      chain.push(cursor);
      consumed.add(cursor);
      cursor = seqOut.get(cursor);
    }

    if (chain.length >= 2) chains.push(chain);
  }

  if (chains.length === 0) return { graph, compounds: new Map() };

  const removedKeys = new Set<string>();
  const compounds = new Map<string, string[]>();
  const compoundNodes: GraphNodeModel[] = [];
  const replacement = new Map<string, string>();

  let nextCompoundIndex = 0;
  for (const chain of chains) {
    const members = chain
      .map((key) => nodeMap.get(key))
      .filter((member): member is GraphNodeModel => member != null);
    if (members.length !== chain.length) continue;

    for (const key of chain) removedKeys.add(key);

    const compoundKey = `compound:${nextCompoundIndex}`;
    nextCompoundIndex += 1;
    compounds.set(compoundKey, chain);
    for (const key of chain) replacement.set(key, compoundKey);

    compoundNodes.push({
      key: compoundKey,
      rawId: -1,
      label: `${chain.length} statements`,
      kind: 'Compound',
      detail: buildLineRange(members),
      line: members[0].line,
      metadata: {
        isCompound: true,
        memberKeys: chain,
        memberRawIds: members.map((member) => member.rawId),
      },
    });
  }

  const nodes = graph.nodes
    .filter((node) => !removedKeys.has(node.key))
    .concat(compoundNodes);

  const dedupe = new Set<string>();
  const edges: GraphEdgeModel[] = [];

  for (const edge of graph.edges) {
    const source = replacement.get(edge.source) ?? edge.source;
    const target = replacement.get(edge.target) ?? edge.target;

    if (source === target) continue;

    const dedupeKey = `${source}:${target}:${edge.kind}`;
    if (dedupe.has(dedupeKey)) continue;
    dedupe.add(dedupeKey);

    edges.push({
      ...edge,
      key: `${edge.key}:compact:${source}:${target}`,
      source,
      target,
    });
  }

  return {
    graph: {
      kind: graph.kind,
      nodes,
      edges,
    },
    compounds,
  };
}
