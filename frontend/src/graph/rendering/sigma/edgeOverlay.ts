import type Sigma from 'sigma';
import type { MultiDirectedGraph } from 'graphology';
import { getEdgeStyle, getNodeStyle, withAlpha } from '../../styles';
import type {
  GraphThemePalette,
  GraphViewKind,
  SigmaEdgeAttributes,
  SigmaNodeAttributes,
} from '../../types';

export interface GraphInteractionState {
  activeNodeKey: string | null;
  hoveredNodeKey: string | null;
  selectedNodeKey: string | null;
  highlightedNodeKeys: Set<string>;
  highlightedEdgeKeys: Set<string>;
  searchMatchKeys: Set<string>;
}

const MIN_NODE_TEXT_WIDTH = 58;
const MIN_NODE_TEXT_HEIGHT = 18;
const DETAIL_EDGE_LABEL_KINDS = new Set(['True', 'False', 'Back', 'Exception']);

export function buildInteractionState(
  graph: MultiDirectedGraph<SigmaNodeAttributes, SigmaEdgeAttributes>,
  selectedNodeKey: string | null,
  hoveredNodeKey: string | null,
  searchMatchKeys: Set<string>,
): GraphInteractionState {
  const activeNodeKey = hoveredNodeKey ?? selectedNodeKey;
  const highlightedNodeKeys = new Set<string>(searchMatchKeys);
  const highlightedEdgeKeys = new Set<string>();

  if (selectedNodeKey) highlightedNodeKeys.add(selectedNodeKey);
  if (hoveredNodeKey) highlightedNodeKeys.add(hoveredNodeKey);

  if (activeNodeKey && graph.hasNode(activeNodeKey)) {
    highlightedNodeKeys.add(activeNodeKey);
    for (const neighbor of graph.neighbors(activeNodeKey)) {
      highlightedNodeKeys.add(neighbor);
    }
    for (const edge of graph.edges(activeNodeKey)) {
      highlightedEdgeKeys.add(edge);
    }
  }

  return {
    activeNodeKey,
    hoveredNodeKey,
    selectedNodeKey,
    highlightedNodeKeys,
    highlightedEdgeKeys,
    searchMatchKeys,
  };
}

function setCanvasSize(
  canvas: HTMLCanvasElement,
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
) {
  const { width, height } = renderer.getDimensions();
  const pixelRatio = window.devicePixelRatio || 1;
  const nextWidth = Math.max(1, Math.floor(width * pixelRatio));
  const nextHeight = Math.max(1, Math.floor(height * pixelRatio));

  if (canvas.width !== nextWidth) canvas.width = nextWidth;
  if (canvas.height !== nextHeight) canvas.height = nextHeight;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  const context = canvas.getContext('2d');
  if (!context) return null;
  context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  return context;
}

function parseColor(color: string): [number, number, number] | null {
  if (color.startsWith('#')) {
    const normalized = color.slice(1);
    const expanded =
      normalized.length === 3
        ? normalized
            .split('')
            .map((segment) => segment + segment)
            .join('')
        : normalized;
    const value = Number.parseInt(expanded, 16);
    if (Number.isNaN(value)) return null;
    return [(value >> 16) & 255, (value >> 8) & 255, value & 255];
  }

  const rgbaMatch = color.match(/rgba?\(([^)]+)\)/);
  if (!rgbaMatch) return null;
  const parts = rgbaMatch[1]
    .split(',')
    .slice(0, 3)
    .map((part) => part.trim());
  if (parts.length !== 3) return null;
  const rgb = parts.map((part) => Number.parseFloat(part));
  if (rgb.some((part) => Number.isNaN(part))) return null;
  return [rgb[0], rgb[1], rgb[2]];
}

function isLightColor(color: string): boolean {
  const rgb = parseColor(color);
  if (!rgb) return false;
  const [red, green, blue] = rgb.map((channel) => channel / 255);
  const luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  return luminance > 0.68;
}

function drawRoundedRect(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
) {
  drawLabelBackdrop(context, x, y, width, height, radius);
}

function drawDoubleRect(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
) {
  drawRoundedRect(context, x, y, width, height, radius);
  drawRoundedRect(context, x + 4, y + 4, width - 8, height - 8, radius - 2);
}

function drawTerminalRect(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
) {
  drawRoundedRect(context, x, y, width, height, height / 2);
}

function getViewportRect(
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
  node: SigmaNodeAttributes,
) {
  const center = renderer.graphToViewport({ x: node.x, y: node.y });
  const xExtent = renderer.graphToViewport({
    x: node.x + node.width / 2,
    y: node.y,
  });
  const yExtent = renderer.graphToViewport({
    x: node.x,
    y: node.y + node.height / 2,
  });

  const width = Math.max(8, Math.abs(xExtent.x - center.x) * 2);
  const height = Math.max(8, Math.abs(yExtent.y - center.y) * 2);

  return {
    x: center.x - width / 2,
    y: center.y - height / 2,
    width,
    height,
    centerX: center.x,
    centerY: center.y,
  };
}

function drawNodeBadges(
  context: CanvasRenderingContext2D,
  node: SigmaNodeAttributes,
  rect: { x: number; y: number; width: number; height: number },
  palette: GraphThemePalette,
  fill: string,
) {
  if (!node.badges?.length || rect.width < 90 || rect.height < 34) return;

  const badges = node.badges.slice(0, 3);
  const badgeHeight = 12;
  const gap = 4;
  const totalWidth = badges.reduce((sum, badge) => {
    const badgeWidth = Math.min(52, Math.max(22, badge.length * 5.2 + 10));
    return sum + badgeWidth;
  }, 0);
  const fullWidth = totalWidth + gap * (badges.length - 1);
  let cursor = rect.x + (rect.width - fullWidth) / 2;
  const y = rect.y + rect.height - badgeHeight - 4;
  const textColor = isLightColor(fill) ? palette.text : '#ffffff';

  context.save();
  context.font = '600 8px var(--font-mono, "SF Mono", monospace)';
  context.textAlign = 'center';
  context.textBaseline = 'middle';

  for (const badge of badges) {
    const badgeWidth = Math.min(52, Math.max(22, badge.length * 5.2 + 10));
    context.fillStyle = withAlpha(palette.background, 0.24);
    context.strokeStyle = withAlpha(textColor, 0.18);
    context.lineWidth = 0.8;
    drawRoundedRect(context, cursor, y, badgeWidth, badgeHeight, 4);
    context.fill();
    context.stroke();

    context.fillStyle = textColor;
    context.fillText(badge, cursor + badgeWidth / 2, y + badgeHeight / 2 + 0.5);
    cursor += badgeWidth + gap;
  }

  context.restore();
}

function drawNodeText(
  context: CanvasRenderingContext2D,
  node: SigmaNodeAttributes,
  rect: { x: number; y: number; width: number; height: number },
  palette: GraphThemePalette,
  fill: string,
) {
  const textLines = node.labelLines
    .map((text) => ({ text, secondary: false }))
    .concat(node.detailLines.map((text) => ({ text, secondary: true })))
    .concat(node.sublabelLines.map((text) => ({ text, secondary: true })));

  if (textLines.length === 0) return;

  const availableHeight = rect.height - (node.badges?.length ? 18 : 10);
  const lineBudget = Math.max(1, Math.floor(availableHeight / 11));
  const visibleLines = textLines.slice(0, lineBudget);
  if (
    rect.width < MIN_NODE_TEXT_WIDTH ||
    rect.height < MIN_NODE_TEXT_HEIGHT ||
    visibleLines.length === 0
  ) {
    return;
  }

  const primaryFont = Math.max(
    8,
    Math.min(12.5, rect.height / (visibleLines.length + 1.6)),
  );
  const secondaryFont = Math.max(7, primaryFont - 1.5);
  const lineHeight = primaryFont + 2;
  const blockHeight = visibleLines.reduce(
    (sum, line) => sum + (line.secondary ? secondaryFont + 2 : lineHeight),
    0,
  );
  const textColor = isLightColor(fill) ? palette.text : '#ffffff';
  const secondaryColor = isLightColor(fill)
    ? palette.textSecondary
    : withAlpha(textColor, 0.76);
  let cursorY = rect.y + (availableHeight - blockHeight) / 2 + primaryFont;

  context.save();
  context.beginPath();
  drawRoundedRect(context, rect.x, rect.y, rect.width, rect.height, 8);
  context.clip();
  context.textAlign = 'center';
  context.textBaseline = 'alphabetic';

  for (const line of visibleLines) {
    const fontSize = line.secondary ? secondaryFont : primaryFont;
    context.font = `${line.secondary ? '500' : '600'} ${fontSize}px var(--font-mono, "SF Mono", monospace)`;
    context.fillStyle = line.secondary ? secondaryColor : textColor;
    context.fillText(line.text, rect.x + rect.width / 2, cursorY);
    cursorY += line.secondary ? secondaryFont + 2 : lineHeight;
  }

  context.restore();
}

function drawNodes(
  context: CanvasRenderingContext2D,
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
  graph: MultiDirectedGraph<SigmaNodeAttributes, SigmaEdgeAttributes>,
  viewKind: GraphViewKind,
  palette: GraphThemePalette,
  interaction: GraphInteractionState,
) {
  const nodes = graph
    .mapNodes((key, attributes) => ({
      key,
      attributes,
    }))
    .sort((left, right) => {
      const leftPriority =
        interaction.selectedNodeKey === left.key
          ? 3
          : interaction.hoveredNodeKey === left.key
            ? 2
            : interaction.highlightedNodeKeys.has(left.key)
              ? 1
              : 0;
      const rightPriority =
        interaction.selectedNodeKey === right.key
          ? 3
          : interaction.hoveredNodeKey === right.key
            ? 2
            : interaction.highlightedNodeKeys.has(right.key)
              ? 1
              : 0;
      return leftPriority - rightPriority;
    });

  for (const { key, attributes } of nodes) {
    const style = getNodeStyle(
      attributes.kind,
      viewKind,
      attributes.metadata,
      palette,
    );
    const rect = getViewportRect(renderer, attributes);
    const isSelected = interaction.selectedNodeKey === key;
    const isHovered = interaction.hoveredNodeKey === key;
    const isHighlighted = interaction.highlightedNodeKeys.has(key);
    const isSearchMatch = interaction.searchMatchKeys.has(key);
    const shouldDim =
      Boolean(interaction.activeNodeKey) &&
      !isSelected &&
      !isHighlighted &&
      !isSearchMatch;

    let fill = style.fill;
    let stroke = style.stroke;
    const opacity = shouldDim ? 0.14 : 1;

    if (isSelected) {
      fill = style.accentFill;
      stroke = withAlpha(palette.accent, 0.96);
    } else if (isHovered || isHighlighted || isSearchMatch) {
      fill = style.neighborFill;
      stroke = withAlpha(style.accentFill, 0.85);
    }

    context.save();
    context.globalAlpha = opacity;

    if (isSelected) {
      context.strokeStyle = withAlpha(palette.accent, 0.32);
      context.lineWidth = 6;
      drawRoundedRect(
        context,
        rect.x - 4,
        rect.y - 4,
        rect.width + 8,
        rect.height + 8,
        12,
      );
      context.stroke();
    }

    context.fillStyle = fill;
    context.strokeStyle = stroke;
    context.lineWidth = isSelected
      ? style.strokeWidth + 0.8
      : style.strokeWidth;

    if (style.shape === 'double') {
      drawDoubleRect(context, rect.x, rect.y, rect.width, rect.height, 8);
    } else if (style.shape === 'terminal') {
      drawTerminalRect(context, rect.x, rect.y, rect.width, rect.height);
    } else {
      drawRoundedRect(context, rect.x, rect.y, rect.width, rect.height, 8);
    }
    context.fill();
    context.stroke();

    drawNodeText(context, attributes, rect, palette, fill);
    drawNodeBadges(context, attributes, rect, palette, fill);
    context.restore();
  }
}

function drawArrow(
  context: CanvasRenderingContext2D,
  from: { x: number; y: number },
  to: { x: number; y: number },
  color: string,
  size: number,
) {
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  const length = Math.max(5, size * 2.6);

  context.save();
  context.translate(to.x, to.y);
  context.rotate(angle);
  context.fillStyle = color;
  context.beginPath();
  context.moveTo(0, 0);
  context.lineTo(-length, length * 0.45);
  context.lineTo(-length, -length * 0.45);
  context.closePath();
  context.fill();
  context.restore();
}

function drawLabelBackdrop(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
) {
  const clampedRadius = Math.min(radius, width / 2, height / 2);
  context.beginPath();
  context.moveTo(x + clampedRadius, y);
  context.lineTo(x + width - clampedRadius, y);
  context.quadraticCurveTo(x + width, y, x + width, y + clampedRadius);
  context.lineTo(x + width, y + height - clampedRadius);
  context.quadraticCurveTo(
    x + width,
    y + height,
    x + width - clampedRadius,
    y + height,
  );
  context.lineTo(x + clampedRadius, y + height);
  context.quadraticCurveTo(x, y + height, x, y + height - clampedRadius);
  context.lineTo(x, y + clampedRadius);
  context.quadraticCurveTo(x, y, x + clampedRadius, y);
  context.closePath();
}

function resolveOpacity(
  interaction: GraphInteractionState,
  edgeKey: string,
  source: string,
  target: string,
): number {
  if (!interaction.activeNodeKey) return 0.8;
  if (interaction.highlightedEdgeKeys.has(edgeKey)) return 0.96;
  if (
    interaction.highlightedNodeKeys.has(source) &&
    interaction.highlightedNodeKeys.has(target)
  ) {
    return 0.7;
  }
  return 0.14;
}

function resolveLineWidth(
  baseWidth: number,
  interaction: GraphInteractionState,
  edgeKey: string,
): number {
  if (interaction.highlightedEdgeKeys.has(edgeKey)) return baseWidth + 0.8;
  return baseWidth;
}

function shouldDrawLabel(
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
  graph: MultiDirectedGraph<SigmaNodeAttributes, SigmaEdgeAttributes>,
  edge: SigmaEdgeAttributes,
  interaction: GraphInteractionState,
  graphOrder: number,
  source: string,
  target: string,
): boolean {
  if (!edge.label) return false;
  if (interaction.highlightedEdgeKeys.has(edge.key)) return true;

  if (DETAIL_EDGE_LABEL_KINDS.has(edge.kind)) {
    const sourceNode = graph.getNodeAttributes(source);
    const targetNode = graph.getNodeAttributes(target);
    const sourceRect = sourceNode
      ? getViewportRect(renderer, sourceNode)
      : undefined;
    const targetRect = targetNode
      ? getViewportRect(renderer, targetNode)
      : undefined;
    const nearReadableNode = [sourceRect, targetRect].some(
      (rect) =>
        rect != null &&
        rect.width >= MIN_NODE_TEXT_WIDTH &&
        rect.height >= MIN_NODE_TEXT_HEIGHT,
    );

    return nearReadableNode;
  }

  if (graphOrder <= 80) return true;
  return renderer.getCamera().getState().ratio < 0.42;
}

function measureSegmentLength(
  start: { x: number; y: number },
  end: { x: number; y: number },
): number {
  return Math.hypot(end.x - start.x, end.y - start.y);
}

function getLabelPlacement(
  points: Array<{ x: number; y: number }>,
  edgeKind: string,
) {
  if (points.length < 2) return null;

  const totalLength = points.reduce((sum, point, index) => {
    if (index === 0) return sum;
    return sum + measureSegmentLength(points[index - 1]!, point);
  }, 0);
  if (totalLength <= 0) return points[0] ?? null;

  const alongPathRatio =
    edgeKind === 'True' || edgeKind === 'False' ? 0.24 : 0.5;
  const targetDistance = totalLength * alongPathRatio;
  let traversed = 0;

  for (let index = 1; index < points.length; index += 1) {
    const start = points[index - 1]!;
    const end = points[index]!;
    const segmentLength = measureSegmentLength(start, end);
    if (segmentLength <= 0) continue;

    if (
      traversed + segmentLength >= targetDistance ||
      index === points.length - 1
    ) {
      const distanceOnSegment = Math.max(0, targetDistance - traversed);
      const t = Math.min(1, distanceOnSegment / segmentLength);
      const directionX = (end.x - start.x) / segmentLength;
      const directionY = (end.y - start.y) / segmentLength;
      const normalX = -directionY;
      const normalY = directionX;
      const offset = edgeKind === 'False' ? -10 : edgeKind === 'True' ? 10 : 8;

      return {
        x: start.x + (end.x - start.x) * t + normalX * offset,
        y: start.y + (end.y - start.y) * t + normalY * offset,
      };
    }

    traversed += segmentLength;
  }

  return points[Math.floor(points.length / 2)] ?? null;
}

interface EdgeLabelInstruction {
  color: string;
  strokeColor: string;
  text: string;
  x: number;
  y: number;
}

function drawEdgeLabels(
  context: CanvasRenderingContext2D,
  palette: GraphThemePalette,
  labels: EdgeLabelInstruction[],
) {
  for (const label of labels) {
    const textWidth = Math.max(18, label.text.length * 6.4);
    const rectX = label.x - textWidth / 2 - 5;
    const rectY = label.y - 10;

    context.fillStyle = withAlpha(palette.background, 0.92);
    context.strokeStyle = label.strokeColor;
    context.lineWidth = 1;
    drawLabelBackdrop(context, rectX, rectY, textWidth + 10, 18, 4);
    context.fill();
    context.stroke();

    context.fillStyle = label.color;
    context.font = `600 10px var(--font-mono, "SF Mono", monospace)`;
    context.textAlign = 'center';
    context.textBaseline = 'middle';
    context.fillText(label.text, label.x, label.y - 0.5);
  }
}

export function drawGraphOverlay(
  canvas: HTMLCanvasElement,
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
  graph: MultiDirectedGraph<SigmaNodeAttributes, SigmaEdgeAttributes>,
  viewKind: GraphViewKind,
  palette: GraphThemePalette,
  interaction: GraphInteractionState,
) {
  const context = setCanvasSize(canvas, renderer);
  if (!context) return;

  const { width, height } = renderer.getDimensions();
  context.clearRect(0, 0, width, height);
  context.lineCap = 'round';
  context.lineJoin = 'round';
  const edgeLabels: EdgeLabelInstruction[] = [];

  graph.forEachEdge((edgeKey, edge, source, target) => {
    const style = getEdgeStyle(edge.kind, viewKind, palette);
    const points =
      edge.route.length > 1
        ? edge.route.map((point) => renderer.graphToViewport(point))
        : [
            renderer.graphToViewport(graph.getNodeAttributes(source)),
            renderer.graphToViewport(graph.getNodeAttributes(target)),
          ];

    if (points.length < 2) return;

    const opacity = resolveOpacity(interaction, edgeKey, source, target);
    const lineWidth = resolveLineWidth(style.width, interaction, edgeKey);
    const color = withAlpha(style.color, opacity);

    context.save();
    context.strokeStyle = color;
    context.lineWidth = lineWidth;
    context.setLineDash(style.dash);
    context.beginPath();
    context.moveTo(points[0].x, points[0].y);
    for (let index = 1; index < points.length; index += 1) {
      context.lineTo(points[index].x, points[index].y);
    }
    context.stroke();

    const from = points[points.length - 2];
    const to = points[points.length - 1];
    drawArrow(context, from, to, color, lineWidth + 0.5);

    if (
      shouldDrawLabel(
        renderer,
        graph,
        edge,
        interaction,
        graph.order,
        source,
        target,
      )
    ) {
      const labelPoint = getLabelPlacement(points, edge.kind);
      if (labelPoint) {
        const labelColor = withAlpha(
          interaction.highlightedEdgeKeys.has(edgeKey)
            ? palette.text
            : style.color,
          interaction.highlightedEdgeKeys.has(edgeKey) ? 0.96 : 0.8,
        );
        edgeLabels.push({
          color: labelColor,
          strokeColor: withAlpha(labelColor, 0.25),
          text: edge.label!,
          x: labelPoint.x,
          y: labelPoint.y,
        });
      }
    }

    context.restore();
  });

  drawNodes(context, renderer, graph, viewKind, palette, interaction);
  drawEdgeLabels(context, palette, edgeLabels);
}
