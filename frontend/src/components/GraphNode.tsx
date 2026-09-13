// src/components/GraphNode.tsx
import React, { useCallback, useRef, useMemo } from "react";
import type { GraphNode as GraphNodeType } from "../types/graph";
import { NODE_RADIUS } from "../utils/graphLayout";
import { entityIconName } from "../utils/classify";
import { IconSvg } from "./Icons";
import ProgressOverlay from "./ProgressOverlay";
import { useGraphState } from "../hooks/useGraphState";
import { useTheme } from "../hooks/useTheme";

interface Props {
  node:         GraphNodeType;
  viewport:     { x: number; y: number; zoom: number };
  selected:     boolean;
  highlighted:  boolean;
  dimmed:       boolean;
  /** When true, labels are hidden for non-selected nodes (used on dense maps). */
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

function GraphNode({
  node, viewport, selected, highlighted, dimmed, compact = false,
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

  const { zoom, x: panX, y: panY } = viewport;
  const sx = node.position.x * zoom + panX;
  const sy = node.position.y * zoom + panY;
  const r  = NODE_RADIUS * zoom;

  const ring       = RING[node.entityType] ?? RING.unknown;
  const glyph      = entityIconName(node.entityType);
  const entityFill = entityColors[node.entityType] || node.colour || "#ffffff";

  const onPointerDown = useCallback((e: React.PointerEvent<SVGGElement>) => {
    e.stopPropagation();
    dragging.current = true;
    moved.current    = false;
    lastPos.current  = { x: e.clientX, y: e.clientY };
    (e.target as SVGGElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent<SVGGElement>) => {
    if (!dragging.current) return;
    const dx = e.clientX - lastPos.current.x;
    const dy = e.clientY - lastPos.current.y;
    lastPos.current = { x: e.clientX, y: e.clientY };
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) moved.current = true;
    onDragEnd(node.id, {
      x: node.position.x + dx / zoom,
      y: node.position.y + dy / zoom,
    });
  }, [node.id, node.position, zoom, onDragEnd]);

  const onPointerUp = useCallback(() => {
    dragging.current = false;
    if (!moved.current) onSelect(node.id);
  }, [node.id, onSelect]);

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
  const iconSize  = Math.max(12, r * 1.05);

  // In compact mode, hide labels on un-focused nodes to save text rendering.
  const showLabel = !compact || selected || highlighted;

  return (
    <g
      transform={`translate(${sx}, ${sy})`}
      style={{
        opacity:    dimmed ? 0.14 : 1,
        cursor:     dragging.current ? "grabbing" : "grab",
        transition: "opacity .2s",
      }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerEnter={onEnter}
      onPointerLeave={onLeave}
    >
      {/* Aura on select/highlight */}
      {(selected || highlighted) && (
        <circle
          cx={0} cy={0} r={r + 10}
          fill={selected ? "rgba(139,92,246,.14)" : "rgba(245,158,11,.14)"}
        />
      )}

      {/* Accent ring (per entity type — fixed colour) */}
      <circle
        cx={0} cy={0} r={r + 3.5}
        fill="none"
        stroke={ring}
        strokeOpacity={selected ? 1 : 0.55}
        strokeWidth={selected ? 2 : 1.4}
      />

      {/* Selection ring (themed) */}
      {selected && (
        <circle
          cx={0} cy={0} r={r + 6}
          fill="none" stroke={nodeSelectedRingColor} strokeWidth="1"
          strokeDasharray="3 4" opacity=".8"
        >
          <animateTransform
            attributeName="transform" type="rotate"
            from="0" to="360" dur="14s" repeatCount="indefinite"
          />
        </circle>
      )}

      {/* Highlight ring (themed) */}
      {highlighted && !selected && (
        <circle
          cx={0} cy={0} r={r + 7}
          fill="none" stroke={nodeHoverRingColor} strokeWidth="2"
        >
          <animate attributeName="opacity" values="1;0;1" dur="1.1s" repeatCount="3" />
        </circle>
      )}

      {/* Cheap drop shadow — an outer dark ring instead of a per-node filter. */}
      <circle
        cx={0} cy={0} r={r + 1}
        fill="none"
        stroke="rgba(0,0,0,.35)"
        strokeWidth="1.5"
        style={{ pointerEvents: "none" }}
      />

      {/* Main fill (solid — no per-node gradient defs). */}
      <circle
        cx={0} cy={0} r={r}
        fill={entityFill}
        stroke={nodeStrokeColor}
        strokeWidth="1"
      />

      {/* Shared highlight gradient — defined once in GraphCanvas. */}
      <circle
        cx={0} cy={0} r={r}
        fill="url(#node-glass)"
        style={{ pointerEvents: "none" }}
      />

      {/* Vector icon */}
      <IconSvg
        name={glyph}
        x={0} y={0}
        size={iconSize}
        color={iconColor}
        strokeWidth={2}
      />

      {/* Progress ring while investigating */}
      {node.investigating && <ProgressOverlay progress={node.progress} radius={r} />}

      {/* Label */}
      {showLabel && (
        <text
          className="node-label"
          y={r + 15 * Math.max(0.7, zoom)}
          textAnchor="middle"
          fontSize={Math.max(9, 11 * Math.max(0.7, zoom))}
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

// Memoize — props are either primitives or stable references, so this
// eliminates re-renders of the other 200+ nodes on selection / popup / etc.
export default React.memo(GraphNode);