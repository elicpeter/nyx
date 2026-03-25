import type { MutableRefObject, ReactNode } from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import Sigma from 'sigma';
import { GraphToolbar } from '../../components/GraphToolbar';
import { readGraphPalette } from '../../styles';
import type {
  GraphThemePalette,
  GraphViewKind,
  SigmaEdgeAttributes,
  SigmaNodeAttributes,
} from '../../types';
import { buildSigmaGraph } from './buildGraph';
import { buildInteractionState, drawGraphOverlay } from './edgeOverlay';
import type { LayoutGraphModel } from '../../types';

interface SigmaGraphProps {
  graph: LayoutGraphModel;
  viewKind: GraphViewKind;
  selectedNodeKey: string | null;
  onNodeClick?: (key: string) => void;
  searchMatchKeys?: Set<string>;
  toolbarExtras?: ReactNode;
  loading?: boolean;
}

const EMPTY_MATCHES = new Set<string>();
const MIN_CAMERA_RATIO = 0.001;
const NOOP_NODE_HOVER = () => {};

function zoomPercentage(
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes> | null,
): number {
  if (!renderer) return 100;
  const ratio = renderer.getCamera().getState().ratio;
  return Math.max(10, Math.round(100 / ratio));
}

function clampCameraRatio(
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
  ratio: number,
): number {
  const minCameraRatio = renderer.getSetting('minCameraRatio') ?? 0;
  const maxCameraRatio =
    renderer.getSetting('maxCameraRatio') ?? Number.POSITIVE_INFINITY;

  return Math.min(maxCameraRatio, Math.max(minCameraRatio, ratio));
}

function getReadableFocusRatio(
  renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>,
  graph: LayoutGraphModel,
  nodeKey: string,
): number {
  const currentRatio = renderer.getCamera().getState().ratio;
  const node = graph.nodes.find((entry) => entry.key === nodeKey);
  if (!node) return currentRatio;

  const center = renderer.graphToViewport({ x: node.x, y: node.y });
  const rightEdge = renderer.graphToViewport({
    x: node.x + node.width / 2,
    y: node.y,
  });
  const bottomEdge = renderer.graphToViewport({
    x: node.x,
    y: node.y + node.height / 2,
  });
  const renderedWidth = Math.max(1, Math.abs(rightEdge.x - center.x) * 2);
  const renderedHeight = Math.max(1, Math.abs(bottomEdge.y - center.y) * 2);
  const totalLines =
    node.labelLines.length + node.detailLines.length + node.sublabelLines.length;
  const maxLineChars = Math.max(
    1,
    ...node.labelLines.map((line) => line.length),
    ...node.detailLines.map((line) => line.length),
    ...node.sublabelLines.map((line) => line.length),
  );
  const { width, height } = renderer.getDimensions();
  const desiredWidth = Math.min(
    width * 0.4,
    Math.max(170, maxLineChars * 9.5 + 40),
  );
  const desiredHeight = Math.min(
    height * 0.28,
    Math.max(72, totalLines * 16 + (node.badges?.length ? 18 : 12)),
  );
  const widthRatio = currentRatio * (renderedWidth / desiredWidth);
  const heightRatio = currentRatio * (renderedHeight / desiredHeight);
  const targetRatio = Math.min(widthRatio, heightRatio, currentRatio);

  return clampCameraRatio(renderer, Math.max(MIN_CAMERA_RATIO, targetRatio));
}

function createNodeReducer(
  interactionRef: MutableRefObject<ReturnType<typeof buildInteractionState>>,
) {
  return (nodeKey: string, data: SigmaNodeAttributes) => {
    const interaction = interactionRef.current;
    const isFocused =
      interaction.selectedNodeKey === nodeKey ||
      interaction.hoveredNodeKey === nodeKey ||
      interaction.highlightedNodeKeys.has(nodeKey) ||
      interaction.searchMatchKeys.has(nodeKey);

    return {
      ...data,
      color: 'rgba(0, 0, 0, 0)',
      size: data.size,
      highlighted: false,
      forceLabel: false,
      zIndex: isFocused ? 2 : 1,
    };
  };
}

export function SigmaGraph({
  graph,
  viewKind,
  selectedNodeKey,
  onNodeClick,
  searchMatchKeys = EMPTY_MATCHES,
  toolbarExtras,
  loading = false,
}: SigmaGraphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rendererRef = useRef<Sigma<
    SigmaNodeAttributes,
    SigmaEdgeAttributes
  > | null>(null);
  const overlayCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const [hoveredNodeKey, setHoveredNodeKey] = useState<string | null>(null);
  const [zoom, setZoom] = useState(100);
  const palette = useMemo(() => readGraphPalette(), []);
  const renderGraph = useMemo(
    () => buildSigmaGraph(graph, palette, false),
    [graph, palette],
  );
  const overlayGraph = useMemo(
    () => buildSigmaGraph(graph, palette, true),
    [graph, palette],
  );
  const interactionRef = useRef(
    buildInteractionState(
      overlayGraph,
      selectedNodeKey,
      hoveredNodeKey,
      searchMatchKeys,
    ),
  );

  interactionRef.current = buildInteractionState(
    overlayGraph,
    selectedNodeKey,
    hoveredNodeKey,
    searchMatchKeys,
  );

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const renderer = new Sigma<SigmaNodeAttributes, SigmaEdgeAttributes>(
      renderGraph,
      container,
      {
        allowInvalidContainer: true,
        autoCenter: true,
        autoRescale: true,
        defaultEdgeType: 'arrow',
        defaultDrawNodeHover: NOOP_NODE_HOVER,
        enableEdgeEvents: false,
        renderEdgeLabels: false,
        renderLabels: false,
        hideLabelsOnMove: true,
        labelDensity: viewKind === 'callgraph' ? 0.85 : 0.95,
        labelRenderedSizeThreshold: viewKind === 'callgraph' ? 10 : 8,
        minCameraRatio: MIN_CAMERA_RATIO,
        maxCameraRatio: 4,
        nodeReducer: createNodeReducer(interactionRef),
        edgeReducer: () => ({
          hidden: true,
        }),
        stagePadding: 24,
        zIndex: true,
      },
    );

    rendererRef.current = renderer;
    setZoom(zoomPercentage(renderer));

    const overlayCanvas = renderer.createCanvas('graphOverlay', {
      afterLayer: 'edges',
      style: {
        pointerEvents: 'none',
      },
    });
    overlayCanvasRef.current = overlayCanvas;

    const redraw = () => {
      if (!overlayCanvasRef.current || !rendererRef.current) return;
      drawGraphOverlay(
        overlayCanvasRef.current,
        rendererRef.current,
        overlayGraph,
        viewKind,
        palette,
        interactionRef.current,
      );
    };

    const handleClickNode = ({ node }: { node: string }) => {
      onNodeClick?.(node);
      const nodeDisplay = renderer.getNodeDisplayData(node);
      if (!nodeDisplay) return;

      const camera = renderer.getCamera();
      const targetRatio = getReadableFocusRatio(renderer, graph, node);
      void camera.animate(
        {
          x: nodeDisplay.x,
          y: nodeDisplay.y,
          ratio: targetRatio,
        },
        { duration: 240 },
      );
    };

    const handleEnterNode = ({ node }: { node: string }) => {
      setHoveredNodeKey(node);
    };

    const handleLeaveNode = () => {
      setHoveredNodeKey(null);
    };

    const handleAfterRender = () => {
      setZoom(zoomPercentage(renderer));
      redraw();
    };

    renderer.on('clickNode', handleClickNode);
    renderer.on('enterNode', handleEnterNode);
    renderer.on('leaveNode', handleLeaveNode);
    renderer.on('afterRender', handleAfterRender);

    const resizeObserver =
      typeof ResizeObserver === 'undefined'
        ? null
        : new ResizeObserver(() => {
            renderer.resize();
            renderer.refresh({ schedule: true });
          });
    resizeObserver?.observe(container);

    redraw();

    return () => {
      resizeObserver?.disconnect();
      renderer.off('clickNode', handleClickNode);
      renderer.off('enterNode', handleEnterNode);
      renderer.off('leaveNode', handleLeaveNode);
      renderer.off('afterRender', handleAfterRender);
      if (overlayCanvasRef.current) {
        renderer.killLayer('graphOverlay');
        overlayCanvasRef.current = null;
      }
      renderer.kill();
      rendererRef.current = null;
    };
  }, [graph, onNodeClick, overlayGraph, palette, renderGraph, viewKind]);

  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer) return;
    renderer.refresh({ schedule: true, skipIndexation: true });
  }, [hoveredNodeKey, overlayGraph, searchMatchKeys, selectedNodeKey]);

  const handleZoomIn = () => {
    void rendererRef.current?.getCamera().animatedZoom();
  };

  const handleZoomOut = () => {
    void rendererRef.current?.getCamera().animatedUnzoom();
  };

  const handleFitGraph = () => {
    void rendererRef.current?.getCamera().animatedReset();
  };

  const handleFocusSelection = () => {
    if (!selectedNodeKey) return;
    const renderer = rendererRef.current;
    if (!renderer) return;
    const nodeDisplay = renderer.getNodeDisplayData(selectedNodeKey);
    if (!nodeDisplay) return;
    const camera = renderer.getCamera();
    const targetRatio = getReadableFocusRatio(
      renderer,
      graph,
      selectedNodeKey,
    );
    void camera.animate(
      { x: nodeDisplay.x, y: nodeDisplay.y, ratio: targetRatio },
      { duration: 240 },
    );
  };

  return (
    <div className="graph-renderer-container">
      <GraphToolbar
        zoomPercentage={zoom}
        onZoomIn={handleZoomIn}
        onZoomOut={handleZoomOut}
        onFitGraph={handleFitGraph}
        onFocusSelection={handleFocusSelection}
        focusDisabled={!selectedNodeKey}
        extras={toolbarExtras}
        status={
          loading ? (
            <span className="graph-toolbar-pill">Layouting…</span>
          ) : (
            <span className="graph-toolbar-pill">
              {graph.nodes.length} nodes
            </span>
          )
        }
      />
      <div className="graph-surface" ref={containerRef}>
        {loading ? (
          <div className="graph-loading-overlay">Computing ELK layout…</div>
        ) : null}
      </div>
    </div>
  );
}
