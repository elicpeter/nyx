import type { LayoutNode } from './types';
import { getNodeStyle } from './nodeStyles';

interface Props {
  node: LayoutNode;
  selected: boolean;
  dimmed: boolean;
  highlighted: boolean;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
  onClick: () => void;
}

export function CfgNode({
  node,
  selected,
  dimmed,
  highlighted,
  onMouseEnter,
  onMouseLeave,
  onClick,
}: Props) {
  const style = getNodeStyle(node.type);
  const x = node.x - node.w / 2;
  const y = node.y - node.h / 2;

  const strokeColor = selected
    ? 'var(--accent, #5856d6)'
    : highlighted
      ? style.stroke
      : style.stroke;
  const strokeW = selected ? 2.5 : style.strokeWidth;
  const opacity = dimmed ? 0.2 : 1;

  // Compute text lines
  const lines: { text: string; fill: string; size: number; weight: string }[] =
    [];
  lines.push({
    text: node.label,
    fill: style.textFill,
    size: 12,
    weight: '600',
  });
  if (node.detail) {
    lines.push({
      text: node.detail,
      fill: style.secondaryFill,
      size: 10,
      weight: '400',
    });
  }
  if (node.sublabel) {
    lines.push({
      text: node.sublabel,
      fill: style.secondaryFill,
      size: 10,
      weight: '400',
    });
  }

  const textStartY = node.y - ((lines.length - 1) * 16) / 2;

  return (
    <g
      className="cfg-node"
      style={{ cursor: 'pointer', opacity, transition: 'opacity 150ms ease' }}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      onClick={onClick}
    >
      {/* Selection glow */}
      {selected && (
        <rect
          x={x - 3}
          y={y - 3}
          width={node.w + 6}
          height={node.h + 6}
          rx={10}
          fill="none"
          stroke="var(--accent, #5856d6)"
          strokeWidth={1}
          opacity={0.4}
        />
      )}

      {/* Main shape */}
      {style.shape === 'double' ? (
        <DoubleRect
          x={x}
          y={y}
          w={node.w}
          h={node.h}
          fill={style.fill}
          stroke={strokeColor}
          strokeWidth={strokeW}
        />
      ) : style.shape === 'terminal' ? (
        <TerminalShape
          x={x}
          y={y}
          w={node.w}
          h={node.h}
          fill={style.fill}
          stroke={strokeColor}
          strokeWidth={strokeW}
        />
      ) : (
        <rect
          x={x}
          y={y}
          width={node.w}
          height={node.h}
          rx={6}
          fill={style.fill}
          stroke={strokeColor}
          strokeWidth={strokeW}
        />
      )}

      {/* Text lines */}
      {lines.map((line, i) => (
        <text
          key={i}
          x={node.x}
          y={textStartY + i * 16 + 1}
          textAnchor="middle"
          dominantBaseline="central"
          fill={line.fill}
          fontSize={line.size}
          fontWeight={line.weight}
          fontFamily="var(--font-mono, 'SF Mono', monospace)"
          style={{ pointerEvents: 'none' }}
        >
          {line.text}
        </text>
      ))}

      {/* Badges */}
      {node.badges && node.badges.length > 0 && (
        <g>
          {node.badges.slice(0, 3).map((badge, i) => {
            const bw = Math.min(badge.length * 5.5 + 8, node.w / 3);
            const bx =
              node.x -
              (node.badges!.length * (bw + 4)) / 2 +
              i * (bw + 4) +
              bw / 2;
            const by = node.y + node.h / 2 - 10;
            return (
              <g key={i}>
                <rect
                  x={bx - bw / 2}
                  y={by - 5}
                  width={bw}
                  height={11}
                  rx={3}
                  fill="rgba(0,0,0,0.25)"
                />
                <text
                  x={bx}
                  y={by + 1}
                  textAnchor="middle"
                  dominantBaseline="central"
                  fill="#fff"
                  fontSize={7.5}
                  fontFamily="var(--font-mono, 'SF Mono', monospace)"
                  style={{ pointerEvents: 'none' }}
                >
                  {badge.length > 12 ? badge.slice(0, 11) + '\u2026' : badge}
                </text>
              </g>
            );
          })}
        </g>
      )}

      {/* Loop indicator */}
      {node.type === 'Loop' && <LoopIcon cx={x + node.w - 10} cy={y + 10} />}
    </g>
  );
}

function DoubleRect({
  x,
  y,
  w,
  h,
  fill,
  stroke,
  strokeWidth,
}: {
  x: number;
  y: number;
  w: number;
  h: number;
  fill: string;
  stroke: string;
  strokeWidth: number;
}) {
  return (
    <g>
      <rect
        x={x}
        y={y}
        width={w}
        height={h}
        rx={6}
        fill={fill}
        stroke={stroke}
        strokeWidth={strokeWidth}
      />
      <rect
        x={x + 3}
        y={y + 3}
        width={w - 6}
        height={h - 6}
        rx={4}
        fill="none"
        stroke={stroke}
        strokeWidth={0.8}
        opacity={0.5}
      />
    </g>
  );
}

function TerminalShape({
  x,
  y,
  w,
  h,
  fill,
  stroke,
  strokeWidth,
}: {
  x: number;
  y: number;
  w: number;
  h: number;
  fill: string;
  stroke: string;
  strokeWidth: number;
}) {
  // Stadium / pill shape for terminal nodes
  const r = h / 2;
  return (
    <rect
      x={x}
      y={y}
      width={w}
      height={h}
      rx={r}
      fill={fill}
      stroke={stroke}
      strokeWidth={strokeWidth}
    />
  );
}

function LoopIcon({ cx, cy }: { cx: number; cy: number }) {
  return (
    <g opacity={0.7}>
      <path
        d={`M ${cx - 4} ${cy} A 4 4 0 1 1 ${cx + 4} ${cy}`}
        fill="none"
        stroke="#fff"
        strokeWidth={1.2}
      />
      <polygon
        points={`${cx + 4},${cy - 2.5} ${cx + 4},${cy + 2.5} ${cx + 7},${cy}`}
        fill="#fff"
      />
    </g>
  );
}
