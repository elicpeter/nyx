export interface NodeStyle {
  fill: string;
  stroke: string;
  textFill: string;
  secondaryFill: string;
  shape: 'rect' | 'terminal' | 'double';
  strokeWidth: number;
}

const STYLES: Record<string, NodeStyle> = {
  Entry: {
    fill: '#22c55e',
    stroke: '#16a34a',
    textFill: '#fff',
    secondaryFill: 'rgba(255,255,255,0.7)',
    shape: 'double',
    strokeWidth: 1.5,
  },
  Exit: {
    fill: '#6b7280',
    stroke: '#4b5563',
    textFill: '#fff',
    secondaryFill: 'rgba(255,255,255,0.7)',
    shape: 'double',
    strokeWidth: 1.5,
  },
  If: {
    fill: '#7c3aed',
    stroke: '#6d28d9',
    textFill: '#fff',
    secondaryFill: 'rgba(255,255,255,0.7)',
    shape: 'rect',
    strokeWidth: 2,
  },
  Loop: {
    fill: '#a855f7',
    stroke: '#9333ea',
    textFill: '#fff',
    secondaryFill: 'rgba(255,255,255,0.7)',
    shape: 'rect',
    strokeWidth: 2.5,
  },
  Call: {
    fill: '#f59e0b',
    stroke: '#d97706',
    textFill: '#fff',
    secondaryFill: 'rgba(255,255,255,0.75)',
    shape: 'rect',
    strokeWidth: 1.5,
  },
  Return: {
    fill: '#ef4444',
    stroke: '#dc2626',
    textFill: '#fff',
    secondaryFill: 'rgba(255,255,255,0.7)',
    shape: 'terminal',
    strokeWidth: 1.5,
  },
};

const DEFAULT_STYLE: NodeStyle = {
  fill: '#e5e7eb',
  stroke: '#d1d5db',
  textFill: '#374151',
  secondaryFill: '#6b7280',
  shape: 'rect',
  strokeWidth: 1,
};

export function getNodeStyle(type: string): NodeStyle {
  return STYLES[type] ?? DEFAULT_STYLE;
}

export interface EdgeStyle {
  color: string;
  width: number;
  dash: string;
}

export function getEdgeStyle(type: string): EdgeStyle {
  switch (type) {
    case 'True':
      return { color: '#22c55e', width: 2, dash: '' };
    case 'False':
      return { color: '#ef4444', width: 2, dash: '' };
    case 'Back':
      return { color: '#a855f7', width: 1.5, dash: '6 3' };
    case 'Exception':
      return { color: '#f59e0b', width: 1.5, dash: '3 3' };
    default:
      return { color: '#9ca3af', width: 1.5, dash: '' };
  }
}
