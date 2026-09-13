// src/components/EdgeLine.tsx
// ─────────────────────────────────────────────────────────────────────────────
// Renders a single edge between two nodes.
//
// Perf: memoized; draw-in animation removed (was creating a style tick per
// edge); hover-driven glow remains, driven by node hover via graph store.

import React, { useMemo } from "react";
import type { GraphEdge, GraphNode } from "../types/graph";
import { calculateEdgePath } from "../utils/graphLayout";
import { useGraphState } from "../hooks/useGraphState";
import { useTheme } from "../hooks/useTheme";

interface Props {
  edge:      GraphEdge;
  source:    GraphNode;
  target:    GraphNode;
  allNodes:  GraphNode[];
  viewport:  { x: number; y: number; zoom: number };
  dimmed?:   boolean;
}

function EdgeLine({
  edge, source, target, allNodes, viewport, dimmed = false,
}: Props) {
  // Read hovered node — the store only notifies when the id changes.
  const hoveredNodeId = useGraphState(s => s.hoveredNodeId);

  const {
    edgeColor,
    edgeThickness,
    edgeOpacity,
    edgeHoverColor,
    edgeHoverGlow,
  } = useTheme();

  const { zoom } = viewport;
  const screenPath = useMemo(() => {
    const tx = (n: GraphNode) => ({
      ...n,
      position: {
        x: n.position.x * zoom + viewport.x,
        y: n.position.y * zoom + viewport.y,
      },
    });
    return calculateEdgePath(tx(source), tx(target), allNodes.map(tx));
  }, [source, target, allNodes, viewport]);

  const isGlowing = hoveredNodeId !== null
    && (hoveredNodeId === source.id || hoveredNodeId === target.id);

  const stroke  = isGlowing ? edgeHoverColor : (edge.colour || edgeColor);
  const width   = isGlowing ? edgeThickness + 1.2 : edgeThickness;
  const opacity = isGlowing ? Math.min(1, edgeOpacity + 0.35) : edgeOpacity;

  return (
    <g style={{ opacity: dimmed ? 0.08 : 1, transition: "opacity .2s" }}>
      <path
        d={screenPath}
        fill="none"
        stroke={stroke}
        strokeWidth={width}
        strokeOpacity={opacity}
        strokeLinecap="round"
        style={{
          filter: isGlowing
            ? `drop-shadow(0 0 ${4 * edgeHoverGlow}px ${edgeHoverColor})`
            : undefined,
        }}
      />
    </g>
  );
}

export default React.memo(EdgeLine);