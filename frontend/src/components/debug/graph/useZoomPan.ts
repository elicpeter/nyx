import { useState, useCallback, useRef, useEffect } from 'react';

interface ZoomPanState {
  x: number;
  y: number;
  scale: number;
}

interface UseZoomPanResult {
  state: ZoomPanState;
  handlers: {
    onWheel: (e: React.WheelEvent) => void;
    onMouseDown: (e: React.MouseEvent) => void;
    onMouseMove: (e: React.MouseEvent) => void;
    onMouseUp: () => void;
    onMouseLeave: () => void;
  };
  dragging: boolean;
  fitToView: (graphWidth: number, graphHeight: number) => void;
  zoomIn: () => void;
  zoomOut: () => void;
  resetView: (graphWidth: number, graphHeight: number) => void;
  centerOnNode: (nx: number, ny: number) => void;
  containerRef: React.RefObject<HTMLDivElement>;
}

const MIN_SCALE = 0.1;
const MAX_SCALE = 3.0;
const ZOOM_STEP = 0.2;

export function useZoomPan(): UseZoomPanResult {
  const [state, setState] = useState<ZoomPanState>({ x: 0, y: 0, scale: 1 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ mx: 0, my: 0, sx: 0, sy: 0 });
  const containerRef = useRef<HTMLDivElement>(null!); // eslint-disable-line @typescript-eslint/no-non-null-assertion

  const clampScale = (s: number) => Math.max(MIN_SCALE, Math.min(MAX_SCALE, s));

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;

    setState((prev) => {
      const oldScale = prev.scale;
      const factor = e.deltaY > 0 ? 0.92 : 1.08;
      const newScale = clampScale(oldScale * factor);

      // Zoom toward cursor position
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const svgX = (cx - prev.x) / oldScale;
      const svgY = (cy - prev.y) / oldScale;

      return {
        x: cx - svgX * newScale,
        y: cy - svgY * newScale,
        scale: newScale,
      };
    });
  }, []);

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (e.button !== 0) return;
      setDragging(true);
      dragStart.current = {
        mx: e.clientX,
        my: e.clientY,
        sx: state.x,
        sy: state.y,
      };
    },
    [state.x, state.y],
  );

  const onMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!dragging) return;
      setState((prev) => ({
        ...prev,
        x: dragStart.current.sx + (e.clientX - dragStart.current.mx),
        y: dragStart.current.sy + (e.clientY - dragStart.current.my),
      }));
    },
    [dragging],
  );

  const onMouseUp = useCallback(() => setDragging(false), []);

  const fitToView = useCallback((graphWidth: number, graphHeight: number) => {
    const container = containerRef.current;
    if (!container || graphWidth === 0 || graphHeight === 0) return;
    const cw = container.clientWidth;
    const ch = container.clientHeight;
    const pad = 60;
    const scaleX = (cw - pad * 2) / graphWidth;
    const scaleY = (ch - pad * 2) / graphHeight;
    const scale = clampScale(Math.min(scaleX, scaleY, 1.5));

    setState({
      x: (cw - graphWidth * scale) / 2,
      y: (ch - graphHeight * scale) / 2,
      scale,
    });
  }, []);

  const zoomIn = useCallback(() => {
    setState((prev) => {
      const container = containerRef.current;
      if (!container) return prev;
      const cw = container.clientWidth / 2;
      const ch = container.clientHeight / 2;
      const newScale = clampScale(prev.scale + ZOOM_STEP);
      const svgX = (cw - prev.x) / prev.scale;
      const svgY = (ch - prev.y) / prev.scale;
      return {
        x: cw - svgX * newScale,
        y: ch - svgY * newScale,
        scale: newScale,
      };
    });
  }, []);

  const zoomOut = useCallback(() => {
    setState((prev) => {
      const container = containerRef.current;
      if (!container) return prev;
      const cw = container.clientWidth / 2;
      const ch = container.clientHeight / 2;
      const newScale = clampScale(prev.scale - ZOOM_STEP);
      const svgX = (cw - prev.x) / prev.scale;
      const svgY = (ch - prev.y) / prev.scale;
      return {
        x: cw - svgX * newScale,
        y: ch - svgY * newScale,
        scale: newScale,
      };
    });
  }, []);

  const resetView = useCallback(
    (graphWidth: number, graphHeight: number) => {
      fitToView(graphWidth, graphHeight);
    },
    [fitToView],
  );

  const centerOnNode = useCallback((nx: number, ny: number) => {
    const container = containerRef.current;
    if (!container) return;
    const cw = container.clientWidth / 2;
    const ch = container.clientHeight / 2;
    setState((prev) => ({
      ...prev,
      x: cw - nx * prev.scale,
      y: ch - ny * prev.scale,
    }));
  }, []);

  return {
    state,
    handlers: {
      onWheel,
      onMouseDown,
      onMouseMove,
      onMouseUp,
      onMouseLeave: onMouseUp,
    },
    dragging,
    fitToView,
    zoomIn,
    zoomOut,
    resetView,
    centerOnNode,
    containerRef,
  };
}
