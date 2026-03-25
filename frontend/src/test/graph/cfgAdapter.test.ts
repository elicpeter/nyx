import { describe, expect, it } from 'vitest';
import { adaptCfgGraph, normalizeCfgEdges } from '@/graph/adapters/cfg';
import type { CfgGraphView } from '@/api/types';

describe('normalizeCfgEdges', () => {
  it('prefers branch edges over duplicate sequential edges', () => {
    expect(
      normalizeCfgEdges([
        { source: 10, target: 11, kind: 'Seq' },
        { source: 10, target: 11, kind: 'True' },
        { source: 10, target: 12, kind: 'Seq' },
        { source: 10, target: 12, kind: 'False' },
      ]),
    ).toEqual([
      { source: 10, target: 11, kind: 'True' },
      { source: 10, target: 12, kind: 'False' },
    ]);
  });

  it('keeps non-duplicate edges intact', () => {
    expect(
      normalizeCfgEdges([
        { source: 1, target: 2, kind: 'Seq' },
        { source: 2, target: 3, kind: 'Back' },
      ]),
    ).toEqual([
      { source: 1, target: 2, kind: 'Seq' },
      { source: 2, target: 3, kind: 'Back' },
    ]);
  });
});

describe('adaptCfgGraph', () => {
  it('does not emit duplicate rendered edges for the same branch target', () => {
    const graph: CfgGraphView = {
      entry: 1,
      nodes: [
        {
          id: 1,
          kind: 'If',
          span: [0, 0],
          line: 20,
          uses: [],
          labels: [],
          condition_text: 'flag',
        },
        {
          id: 2,
          kind: 'Seq',
          span: [0, 0],
          line: 21,
          uses: [],
          labels: [],
        },
      ],
      edges: [
        { source: 1, target: 2, kind: 'Seq' },
        { source: 1, target: 2, kind: 'True' },
      ],
    };

    const adapted = adaptCfgGraph(graph);

    expect(adapted.edges).toHaveLength(1);
    expect(adapted.edges[0]?.kind).toBe('True');
  });

  it('prefers concise CFG labels over enormous rhs expressions', () => {
    const graph: CfgGraphView = {
      entry: 1,
      nodes: [
        {
          id: 1,
          kind: 'Seq',
          span: [0, 0],
          line: 10,
          defines: 'el.innerHTML',
          callee:
            'el.innerHTML = `<div style="padding:60px 0;"> giant html blob giant html blob giant html blob</div>`',
          uses: [],
          labels: [],
        },
      ],
      edges: [],
    };

    const adapted = adaptCfgGraph(graph);

    expect(adapted.nodes[0]?.label).toBe('Seq: el.innerHTML');
  });
});
