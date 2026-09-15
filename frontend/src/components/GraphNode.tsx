// src/components/GraphNode.tsx
import React, { useCallback, useEffect, useRef, useMemo } from "react";
import type { GraphNode as GraphNodeType } from "../types/graph";
import { NODE_RADIUS } from "../utils/graphLayout";
import { entityIconName } from "../utils/classify";
import { IconSvg } from "./Icons";
import ProgressOverlay from "./ProgressOverlay";
import { useGraphState } from "../hooks/useGraphState";
import { useTheme } from "../hooks/useTheme";

interface Props {
  node:         GraphNodeType;
  /**
   * Current zoom only — deliberately NOT the whole viewport object.
   *
   * Nodes used to sit as direct SVG-space siblings and compute their
   * own screen position from a `viewport` prop. Because `viewport` is a
   * fresh object on every store update, React.memo never held during a
   * pan: every node re-rendered and recomputed its transform, ring
   * radii, icon size and label metrics on every pointermove of a
   * canvas drag. Nodes now live inside the same
   * `translate(...) scale(...)` group the edges already use, so pan is
   * a single attribute change handled by the browser and does not
   * reach React at all. Zoom is still needed here because the label
   * metrics use a non-linear clamp that a pure scale cannot express.
   */
  zoom:         number;
  selected:     boolean;
  highlighted:  boolean;
  dimmed:       boolean;
  compact?:     boolean;
  onSelect:     (id: string) => void;
  onDragEnd:    (id: string, newLogicalPos: { x: number; y: number }) => void;
}

const RING: Record<string, string> = {
  email:          "#38bdf8",
  username:       "#a78bfa",
  social_profile: "#c084fc",
  phone:          "#fb7185",
  domain:         "#f59e0b",
  url:            "#22d3ee",
  image:          "#f472b6",
  breach:         "#f43f5e",
  ip:             "#34d399",
  name:           "#fbbf24",
  location:       "#10b981",
  unknown:        "#94a3b8",
};

// Confidence is rendered as an extra thin ring between the accent ring
// and the fill. A tight, opaque ring reads as "high confidence"; a
// wide, transparent one reads as "weak signal". The visual weight is
// deliberately subtle so the accent ring stays the dominant cue.
function confidenceStyle(confidence: number | undefined) {
  if (confidence === undefined || confidence === null) {
    return { offset: 0, opacity: 0, width: 0 };
  }
  const c = Math.max(0, Math.min(1, confidence));
  // High confidence → thin ring close to the fill.
  // Low confidence  → wider ring, but translucent.
  return {
    offset:  1.5 + (1 - c) * 3.5,       // 1.5px at c=1, 5px at c=0
    opacity: 0.15 + c * 0.55,           // 0.15 at c=0, 0.70 at c=1
    width:   1 + c * 0.8,               // 1.0 at c=0, 1.8 at c=1
  };
}

function GraphNode({
  node, zoom, selected, highlighted, dimmed, compact = false,
  onSelect, onDragEnd,
}: Props) {
  const dragging = useRef(false);
  const lastPos  = useRef({ x: 0, y: 0 });
  const moved    = useRef(false);

  const setHoveredNode = useGraphState(s => s.setHoveredNode);
  const {
    entityColors,
    nodeHoverRingColor,
    nodeSelectedRingColor,
    nodeStrokeColor,
  } = useTheme();

  // Graph-space geometry. The parent <g> applies scale(zoom), so the
  // base radius is unscaled here and the browser scales it.
  const r = NODE_RADIUS;

  // Decorations (ring gaps, icon, label) were sized in *screen* pixels
  // against a pre-scaled radius, e.g. `r + 10` where r was
  // NODE_RADIUS * zoom. Inside a scaled group the same constants would
  // themselves be scaled, so divide by zoom to keep every gap the same
  // number of screen pixels it was before. `k` is that conversion.
  const k = 1 / (zoom || 1);

  const ring       = RING[node.entityType] ?? RING.unknown;
  const glyph      = entityIconName(node.entityType);
  const entityFill = entityColors[node.entityType] || node.colour || "#ffffff";

  const conf = confidenceStyle(node.confidence);

  // Live drag offset, applied imperatively to this node's own <g>.
  // Nothing is written to the store until the pointer is released.
  //
  // onDragEnd used to be called from onPointerMove — despite the name —
  // so every pixel of a drag ran updateNode(), which copies the whole
  // nodes array, re-rendered the canvas, and invalidated every edge's
  // path memo (see EdgeLine). Pointer events fire well above 60/sec, so
  // one drag across a 150-node graph produced tens of thousands of
  // array allocations and obstacle-intersection tests. Now the gesture
  // costs one transform write per frame and exactly one store commit.
  const gRef  = useRef<SVGGElement | null>(null);
  const drag  = useRef({ dx: 0, dy: 0 });
  const raf   = useRef<number | null>(null);

  const applyDragTransform = useCallback(() => {
    raf.current = null;
    const g = gRef.current;
    if (!g) return;
    g.setAttribute(
      "transform",
      `translate(${node.position.x + drag.current.dx}, ` +
      `${node.position.y + drag.current.dy})`,
    );
  }, [node.position.x, node.position.y]);

  const onPointerDown = useCallback((e: React.PointerEvent<SVGGElement>) => {
    e.stopPropagation();
    dragging.current = true;
    moved.current    = false;
    drag.current     = { dx: 0, dy: 0 };
    lastPos.current  = { x: e.clientX, y: e.clientY };
    (e.target as SVGGElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent<SVGGElement>) => {
    if (!dragging.current) return;
    const dx = e.clientX - lastPos.current.x;
    const dy = e.clientY - lastPos.current.y;
    lastPos.current = { x: e.clientX, y: e.clientY };
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) moved.current = true;
    drag.current = {
      dx: drag.current.dx + dx / zoom,
      dy: drag.current.dy + dy / zoom,
    };
    // Coalesce bursts of pointer events into one paint per frame.
    if (raf.current === null) {
      raf.current = requestAnimationFrame(applyDragTransform);
    }
  }, [zoom, applyDragTransform]);

  const onPointerUp = useCallback(() => {
    if (!dragging.current) return;
    dragging.current = false;
    if (raf.current !== null) {
      cancelAnimationFrame(raf.current);
      raf.current = null;
    }
    const { dx, dy } = drag.current;
    drag.current = { dx: 0, dy: 0 };
    if (!moved.current) {
      onSelect(node.id);
      return;
    }
    // Single commit for the whole gesture.
    onDragEnd(node.id, {
      x: node.position.x + dx,
      y: node.position.y + dy,
    });
  }, [node.id, node.position.x, node.position.y, onSelect, onDragEnd]);

  // If a drag is interrupted (pointercancel, unmount mid-gesture) the
  // pending frame must not fire against a stale node.
  useEffect(() => () => {
    if (raf.current !== null) cancelAnimationFrame(raf.current);
  }, []);

  const onEnter = useCallback(
    () => setHoveredNode(node.id),
    [node.id, setHoveredNode],
  );
  const onLeave = useCallback(
    () => setHoveredNode(null),
    [setHoveredNode],
  );

  const label = useMemo(
    () => (node.label.length > 22 ? node.label.slice(0, 20) + "…" : node.label),
    [node.label],
  );

  const iconColor = isLight(entityFill) ? "#0a0a0d" : "#f4f4f5";
  // Screen-space size, converted back into local units.
  const iconSize  = Math.max(12, NODE_RADIUS * zoom * 1.05) * k;

  const showLabel = !compact || selected || highlighted;

  return (
    <g
      ref={gRef}
      transform={`translate(${node.position.x}, ${node.position.y})`}
      style={{
        opacity:    dimmed ? 0.14 : 1,
        cursor:     dragging.current ? "grabbing" : "grab",
        transition: "opacity .2s",
      }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onPointerEnter={onEnter}
      onPointerLeave={onLeave}
    >
      {(selected || highlighted) && (
        <circle
          cx={0} cy={0} r={r + 10 * k}
          fill={selected ? "rgba(139,92,246,.14)" : "rgba(245,158,11,.14)"}
        />
      )}

      {/* Confidence ring — thin, sits between the accent ring and the
          fill. Its presence and weight encode how much to trust the
          finding. */}
      {conf.width > 0 && (
        <circle
          cx={0} cy={0} r={r + conf.offset * k}
          fill="none"
          stroke={ring}
          strokeOpacity={conf.opacity}
          strokeWidth={conf.width}
          vectorEffect="non-scaling-stroke"
        />
      )}

      {/* Accent ring (per entity type — fixed colour) */}
      <circle
        cx={0} cy={0} r={r + 3.5 * k}
        fill="none"
        stroke={ring}
        strokeOpacity={selected ? 1 : 0.55}
        strokeWidth={selected ? 2 : 1.4}
        vectorEffect="non-scaling-stroke"
      />

      {selected && (
        <circle
          cx={0} cy={0} r={r + 6 * k}
          fill="none" stroke={nodeSelectedRingColor} strokeWidth="1"
          strokeDasharray="3 4" opacity=".8" vectorEffect="non-scaling-stroke"
        >
          <animateTransform
            attributeName="transform" type="rotate"
            from="0" to="360" dur="14s" repeatCount="indefinite"
          />
        </circle>
      )}

      {highlighted && !selected && (
        <circle
          cx={0} cy={0} r={r + 7 * k}
          fill="none" stroke={nodeHoverRingColor} strokeWidth="2"
          vectorEffect="non-scaling-stroke"
        >
          <animate attributeName="opacity" values="1;0;1" dur="1.1s" repeatCount="3" />
        </circle>
      )}

      <circle
        cx={0} cy={0} r={r + 1 * k}
        fill="none"
        stroke="rgba(0,0,0,.35)"
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
        style={{ pointerEvents: "none" }}
      />

      <circle
        cx={0} cy={0} r={r}
        fill={entityFill}
        stroke={nodeStrokeColor}
        strokeWidth="1"
        vectorEffect="non-scaling-stroke"
      />

      <circle
        cx={0} cy={0} r={r}
        fill="url(#node-glass)"
        style={{ pointerEvents: "none" }}
      />

      <IconSvg
        name={glyph}
        x={0} y={0}
        size={iconSize}
        color={iconColor}
        strokeWidth={2}
      />

      {node.investigating && <ProgressOverlay progress={node.progress} radius={r} />}

      {showLabel && (
        <text
          className="node-label"
          y={r + 15 * Math.max(0.7, zoom) * k}
          textAnchor="middle"
          fontSize={Math.max(9, 11 * Math.max(0.7, zoom)) * k}
          fontFamily="Inter, system-ui, sans-serif"
          fontWeight={600}
          fill="#e4e4e7"
          style={{ pointerEvents: "none", userSelect: "none" }}
        >
          {label}
        </text>
      )}
    </g>
  );
}

function isLight(hex: string): boolean {
  const c = hex.replace("#", "");
  const full = c.length === 3 ? c.split("").map(x => x + x).join("") : c;
  const n = parseInt(full, 16);
  if (Number.isNaN(n)) return false;
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  return (0.299 * r + 0.587 * g + 0.114 * b) > 168;
}

export default React.memo(GraphNode);