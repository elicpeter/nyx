import { describe, it, expect } from 'vitest';
import { compactGraph } from '@/graph/reduction/cfgCompaction';
import type { GraphEdge, GraphNode } from '@/graph/types';

function makeNode(id: number, type = 'Stmt'): GraphNode {
  return {
    key: String(id),
    rawId: id,
    label: `Node ${id}`,
    kind: type,
  };
}

function seqEdge(source: number, target: number): GraphEdge {
  return {
    key: `seq:${source}:${target}`,
    source: String(source),
    target: String(target),
    kind: 'Seq',
  };
}

describe('compactGraph', () => {
  it('returns the graph unchanged when there are 3 or fewer nodes', () => {
    const nodes = [makeNode(1), makeNode(2), makeNode(3)];
    const edges = [seqEdge(1, 2), seqEdge(2, 3)];
    const result = compactGraph({ kind: 'cfg', nodes, edges });
    expect(result.graph.nodes).toEqual(nodes);
    expect(result.graph.edges).toEqual(edges);
    expect(result.compounds.size).toBe(0);
  });

  it('returns unchanged graph when no chainable sequences exist', () => {
    // All nodes are control-flow types – nothing to compact
    const nodes = [
      makeNode(1, 'Entry'),
      makeNode(2, 'If'),
      makeNode(3, 'Return'),
      makeNode(4, 'Exit'),
    ];
    const edges = [seqEdge(1, 2), seqEdge(2, 3), seqEdge(3, 4)];
    const result = compactGraph({ kind: 'cfg', nodes, edges });
    expect(result.graph.nodes.length).toBe(4);
    expect(result.compounds.size).toBe(0);
  });

  it('collapses a straight-line sequence of stmt nodes', () => {
    // Entry -> Stmt2 -> Stmt3 -> Stmt4 -> Exit
    // Stmt2/3/4 are all chainable (1 in / 1 out each)
    const nodes = [
      makeNode(1, 'Entry'),
      makeNode(2, 'Stmt'),
      makeNode(3, 'Stmt'),
      makeNode(4, 'Stmt'),
      makeNode(5, 'Exit'),
    ];
    const edges = [seqEdge(1, 2), seqEdge(2, 3), seqEdge(3, 4), seqEdge(4, 5)];
    const result = compactGraph({ kind: 'cfg', nodes, edges });

    // The three stmts should be collapsed into one compound node
    const compound = result.graph.nodes.find((n) => n.kind === 'Compound');
    expect(compound).toBeDefined();
    expect(compound?.label).toMatch(/statements/);

    // Entry and Exit should still be present
    expect(result.graph.nodes.some((n) => n.kind === 'Entry')).toBe(true);
    expect(result.graph.nodes.some((n) => n.kind === 'Exit')).toBe(true);
  });

  it('records the compacted node ids in expandedIds', () => {
    const nodes = [
      makeNode(1, 'Entry'),
      makeNode(2, 'Stmt'),
      makeNode(3, 'Stmt'),
      makeNode(4, 'Stmt'),
      makeNode(5, 'Exit'),
    ];
    const edges = [seqEdge(1, 2), seqEdge(2, 3), seqEdge(3, 4), seqEdge(4, 5)];
    const result = compactGraph({ kind: 'cfg', nodes, edges });

    expect(result.compounds.size).toBe(1);
    const [, origIds] = [...result.compounds.entries()][0];
    expect(origIds).toContain('2');
    expect(origIds).toContain('3');
    expect(origIds).toContain('4');
  });

  it('does not collapse control-flow node types', () => {
    const nodes = [
      makeNode(1, 'Entry'),
      makeNode(2, 'If'),
      makeNode(3, 'Stmt'),
      makeNode(4, 'Stmt'),
      makeNode(5, 'Exit'),
    ];
    const edges = [
      seqEdge(1, 2),
      {
        key: 'true:2:3',
        source: '2',
        target: '3',
        kind: 'True',
      } as GraphEdge,
      seqEdge(3, 4),
      seqEdge(4, 5),
    ];
    const result = compactGraph({ kind: 'cfg', nodes, edges });
    // If node should remain
    expect(result.graph.nodes.some((n) => n.kind === 'If')).toBe(true);
  });

  it('returns unchanged graph when no chains have length >= 2', () => {
    // A single stmt between two non-chainable nodes – chain length 1, not compacted
    const nodes = [
      makeNode(1, 'Entry'),
      makeNode(2, 'Stmt'),
      makeNode(3, 'Exit'),
    ];
    const edges = [seqEdge(1, 2), seqEdge(2, 3)];
    // Only 3 nodes, so early return applies anyway
    const result = compactGraph({ kind: 'cfg', nodes, edges });
    expect(result.compounds.size).toBe(0);
  });

  it('computes a line range label when nodes have line numbers', () => {
    const nodes = [
      makeNode(1, 'Entry'),
      { ...makeNode(2, 'Stmt'), line: 10 },
      { ...makeNode(3, 'Stmt'), line: 11 },
      { ...makeNode(4, 'Stmt'), line: 12 },
      makeNode(5, 'Exit'),
    ];
    const edges = [seqEdge(1, 2), seqEdge(2, 3), seqEdge(3, 4), seqEdge(4, 5)];
    const result = compactGraph({ kind: 'cfg', nodes, edges });
    const compound = result.graph.nodes.find((n) => n.kind === 'Compound');
    expect(compound?.detail).toMatch(/L10/);
    expect(compound?.detail).toMatch(/L12/);
  });
});
