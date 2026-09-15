// src/components/EdgeLine.tsx
// ─────────────────────────────────────────────────────────────────────────────
// Renders a single edge between two nodes.
//
// Perf: the path is computed in GRAPH space and the viewport transform is
// applied once by the parent <g> in GraphCanvas. Previously each edge
// transformed every node itself (allNodes.map(tx) — an N-object allocation
// per edge) and the memo listed `viewport` as a dependency, so a single pan
// frame invalidated all E memos and cost O(N x E) allocations plus O(N x E)
// obstacle tests. Pan and zoom are now pure SVG transforms: zero JS recompute.
//
// This also fixes a latent visual bug. GraphNode draws at r = NODE_RADIUS *
// zoom, but calculateEdgePath trimmed endpoints by a constant NODE_RADIUS.
// At zoom != 1 the edge ends did not meet the node boundary — short of it
// when zoomed out, inside the circle when zoomed in. Computing in graph
// space makes the trim scale with the node automatically.

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
  /**
   * Signature of all node positions, supplied by the canvas. Used as
   * the memo key instead of `allNodes` identity — the store rebuilds
   * the nodes array on every update, so keying on the array made any
   * node change invalidate every edge's path.
   */
  nodePosKey: string;
  dimmed?:   boolean;
}

function EdgeLine({
  edge, source, target, allNodes, nodePosKey, dimmed = false,
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

  // Graph-space path. Independent of pan and zoom, so this only
  // recomputes when a node actually moves.
  // `allNodes` is intentionally absent from the dependency list:
  // nodePosKey already changes whenever any position moves, and the
  // obstacle scan only reads positions. Depending on the array itself
  // would reintroduce the invalidate-everything behaviour.
  const path = useMemo(
    () => calculateEdgePath(source, target, allNodes),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      source.id, source.position.x, source.position.y,
      target.id, target.position.x, target.position.y,
      nodePosKey,
    ],
  );

  const isGlowing = hoveredNodeId !== null
    && (hoveredNodeId === source.id || hoveredNodeId === target.id);

  const stroke  = isGlowing ? edgeHoverColor : (edge.colour || edgeColor);
  const width   = isGlowing ? edgeThickness + 1.2 : edgeThickness;
  const opacity = isGlowing ? Math.min(1, edgeOpacity + 0.35) : edgeOpacity;

  return (
    <g style={{ opacity: dimmed ? 0.08 : 1, transition: "opacity .2s" }}>
      <path
        d={path}
        fill="none"
        stroke={stroke}
        strokeWidth={width}
        strokeOpacity={opacity}
        strokeLinecap="round"
        // The parent <g> scales by zoom; without this the stroke would
        // scale too, which is a behaviour change from the old
        // screen-space rendering.
        vectorEffect="non-scaling-stroke"
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
