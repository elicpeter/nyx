import type { LayoutEdge } from './types';
import { getEdgeStyle } from './nodeStyles';

interface Props {
  edge: LayoutEdge;
  dimmed: boolean;
  highlighted: boolean;
  markerId: string;
}

/** Build a smooth cubic bezier path through dagre's control points. */
function buildPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x} ${points[0].y}`;
  if (points.length === 2) {
    return `M ${points[0].x} ${points[0].y} L ${points[1].x} ${points[1].y}`;
  }

  // Use cubic bezier through control points
  let d = `M ${points[0].x} ${points[0].y}`;

  if (points.length === 3) {
    // Quadratic through midpoint
    d += ` Q ${points[1].x} ${points[1].y}, ${points[2].x} ${points[2].y}`;
    return d;
  }

  // For 4+ points, use cubic bezier segments
  // First segment: from p0 through p1 to midpoint(p1,p2)
  for (let i = 1; i < points.length - 2; i++) {
    const cp = points[i];
    const next = points[i + 1];
    const mx = (cp.x + next.x) / 2;
    const my = (cp.y + next.y) / 2;
    d += ` Q ${cp.x} ${cp.y}, ${mx} ${my}`;
  }

  // Last segment
  const cp = points[points.length - 2];
  const end = points[points.length - 1];
  d += ` Q ${cp.x} ${cp.y}, ${end.x} ${end.y}`;

  return d;
}

export function EdgePath({ edge, dimmed, highlighted, markerId }: Props) {
  const style = getEdgeStyle(edge.type);
  const path = buildPath(edge.points);
  const opacity = dimmed ? 0.1 : 1;
  const strokeWidth = highlighted ? style.width + 1 : style.width;

  // Place label near source for True/False, at midpoint for others
  const labelPoint = getLabelPoint(edge);

  return (
    <g
      className="cfg-edge"
      style={{ opacity, transition: 'opacity 150ms ease' }}
    >
      <path
        d={path}
        fill="none"
        stroke={style.color}
        strokeWidth={strokeWidth}
        strokeDasharray={style.dash}
        markerEnd={`url(#${markerId})`}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {edge.label && labelPoint && (
        <>
          <rect
            x={labelPoint.x - edge.label.length * 3.5 - 4}
            y={labelPoint.y - 8}
            width={edge.label.length * 7 + 8}
            height={16}
            rx={3}
            fill="var(--bg-secondary, #f7f7f8)"
            stroke={style.color}
            strokeWidth={0.5}
            opacity={0.9}
          />
          <text
            x={labelPoint.x}
            y={labelPoint.y}
            textAnchor="middle"
            dominantBaseline="central"
            fill={style.color}
            fontSize={10}
            fontWeight="600"
            fontFamily="var(--font-mono, 'SF Mono', monospace)"
            style={{ pointerEvents: 'none' }}
          >
            {edge.label}
          </text>
        </>
      )}
    </g>
  );
}

function getLabelPoint(edge: LayoutEdge): { x: number; y: number } | null {
  const pts = edge.points;
  if (pts.length < 2) return null;

  // For True/False, place label near source (25% along path)
  if (edge.type === 'True' || edge.type === 'False') {
    if (pts.length >= 3) {
      return { x: pts[1].x, y: pts[1].y - 2 };
    }
    const t = 0.25;
    return {
      x: pts[0].x + (pts[1].x - pts[0].x) * t,
      y: pts[0].y + (pts[1].y - pts[0].y) * t - 2,
    };
  }

  // For other labels, place at midpoint
  const mid = Math.floor(pts.length / 2);
  return { x: pts[mid].x, y: pts[mid].y - 2 };
}

/** Generate SVG marker definitions for each edge type. */
export function EdgeMarkers() {
  const types = [
    { id: 'arrow-default', color: '#9ca3af' },
    { id: 'arrow-true', color: '#22c55e' },
    { id: 'arrow-false', color: '#ef4444' },
    { id: 'arrow-back', color: '#a855f7' },
    { id: 'arrow-exception', color: '#f59e0b' },
  ];

  return (
    <>
      {types.map((t) => (
        <marker
          key={t.id}
          id={t.id}
          viewBox="0 0 10 7"
          refX="9"
          refY="3.5"
          markerWidth="8"
          markerHeight="6"
          orient="auto"
        >
          <polygon points="0 0.5, 8 3.5, 0 6.5" fill={t.color} />
        </marker>
      ))}
    </>
  );
}

export function getMarkerId(edgeType: string): string {
  switch (edgeType) {
    case 'True':
      return 'arrow-true';
    case 'False':
      return 'arrow-false';
    case 'Back':
      return 'arrow-back';
    case 'Exception':
      return 'arrow-exception';
    default:
      return 'arrow-default';
  }
}
