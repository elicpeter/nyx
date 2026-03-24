export interface GraphNode {
  id: number;
  label: string;
  type: string;
  detail?: string;
  sublabel?: string;
  badges?: string[];
  line?: number;
}

export interface GraphEdge {
  source: number;
  target: number;
  label?: string;
  type: string;
}

export interface LayoutNode {
  id: number;
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  type: string;
  detail?: string;
  sublabel?: string;
  badges?: string[];
  line?: number;
}

export interface LayoutEdge {
  source: number;
  target: number;
  label?: string;
  type: string;
  points: { x: number; y: number }[];
}

export interface LayoutResult {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  width: number;
  height: number;
}

export interface GraphRendererProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (id: number) => void;
  selectedNode?: number | null;
  mode?: 'cfg' | 'callgraph';
  compact?: boolean;
  className?: string;
}
