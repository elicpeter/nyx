import { MultiDirectedGraph } from 'graphology';
import { getEdgeStyle, getNodeStyle } from '../../styles';
import type {
  GraphThemePalette,
  LayoutGraphModel,
  SigmaEdgeAttributes,
  SigmaNodeAttributes,
} from '../../types';

function addNodes(
  sigmaGraph: MultiDirectedGraph<SigmaNodeAttributes, SigmaEdgeAttributes>,
  graph: LayoutGraphModel,
  palette: GraphThemePalette,
) {
  for (const node of graph.nodes) {
    const style = getNodeStyle(node.kind, graph.kind, node.metadata, palette);
    sigmaGraph.addNode(node.key, {
      ...node,
      x: node.x,
      y: node.y,
      size: node.sigmaSize,
      color: style.fill,
      hidden: false,
    });
  }
}

export function buildSigmaGraph(
  graph: LayoutGraphModel,
  palette: GraphThemePalette,
  includeEdges = true,
): MultiDirectedGraph<SigmaNodeAttributes, SigmaEdgeAttributes> {
  const sigmaGraph = new MultiDirectedGraph<
    SigmaNodeAttributes,
    SigmaEdgeAttributes
  >();

  addNodes(sigmaGraph, graph, palette);

  if (includeEdges) {
    for (const edge of graph.edges) {
      const style = getEdgeStyle(edge.kind, graph.kind, palette);
      sigmaGraph.addDirectedEdgeWithKey(edge.key, edge.source, edge.target, {
        ...edge,
        color: style.color,
        size: style.width,
        hidden: false,
      });
    }
  }

  return sigmaGraph;
}
