// src/utils/graphLayout.ts
// ─────────────────────────────────────────────────────────────────────────────
// Edge routing and node layout for the Investigation Canvas.
//
// Performance: obstacle-avoidance scanning is O(N) per edge.  When the graph
// has more than _OBSTACLE_SCAN_LIMIT nodes, we skip the scan and emit a
// straight line — the visual difference is minor but the render cost drops
// from O(E × N) to O(E).

import type { GraphNode } from "../types/graph";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const NODE_RADIUS = 36;
const MIN_SEP = NODE_RADIUS * 2 + 32;
const SPIRAL_B = MIN_SEP / (2 * Math.PI);
const SPIRAL_START_R = MIN_SEP * 2.2;

/**
 * Above this node count, edges render as straight lines (no obstacle scan).
 * Tuned empirically — at 150 nodes a curved-edge pass is still smooth; at
 * 400+ it stalls the main thread.
 */
const _OBSTACLE_SCAN_LIMIT = 150;

// ---------------------------------------------------------------------------
// Geometry helpers
// ---------------------------------------------------------------------------

interface Point { x: number; y: number; }

function dist(a: Point, b: Point): number {
  return Math.hypot(b.x - a.x, b.y - a.y);
}

export function midpoint(a: Point, b: Point): Point {
  return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
}

function perpendicular(a: Point, b: Point, length: number): Point {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const d  = Math.hypot(dx, dy) || 1;
  return { x: -dy / d * length, y: dx / d * length };
}

export function doesLineIntersectNode(
  a: Point,
  b: Point,
  node: Point,
  radius: number = NODE_RADIUS + 8,
): boolean {
  const ab  = { x: b.x - a.x, y: b.y - a.y };
  const an  = { x: node.x - a.x, y: node.y - a.y };
  const len = ab.x * ab.x + ab.y * ab.y;
  if (len === 0) return false;
  const t       = Math.max(0, Math.min(1, (an.x * ab.x + an.y * ab.y) / len));
  const closest = { x: a.x + t * ab.x, y: a.y + t * ab.y };
  return dist(closest, node) < radius;
}

// ---------------------------------------------------------------------------
// Edge path calculator
// ---------------------------------------------------------------------------

export function calculateEdgePath(
  source: GraphNode,
  target: GraphNode,
  obstacles: GraphNode[],
): string {
  const a = source.position;
  const b = target.position;

  const d     = dist(a, b) || 1;
  const normX = (b.x - a.x) / d;
  const normY = (b.y - a.y) / d;

  const startX = a.x + normX * NODE_RADIUS;
  const startY = a.y + normY * NODE_RADIUS;
  const endX   = b.x - normX * NODE_RADIUS;
  const endY   = b.y - normY * NODE_RADIUS;

  // Fast path — dense graphs skip obstacle avoidance entirely.
  if (obstacles.length > _OBSTACLE_SCAN_LIMIT) {
    return `M ${startX} ${startY} L ${endX} ${endY}`;
  }

  const start: Point = { x: startX, y: startY };
  const end:   Point = { x: endX,   y: endY   };

  let maxPenetration = 0;
  let worstObstacle: GraphNode | null = null;

  for (const obs of obstacles) {
    if (obs.id === source.id || obs.id === target.id) continue;
    if (doesLineIntersectNode(start, end, obs.position)) {
      const m   = midpoint(start, end);
      const pen = (NODE_RADIUS + 8) - dist(m, obs.position);
      if (pen > maxPenetration) {
        maxPenetration = pen;
        worstObstacle  = obs;
      }
    }
  }

  if (!worstObstacle) {
    return `M ${startX} ${startY} L ${endX} ${endY}`;
  }

  const mid  = midpoint(start, end);
  const perp = perpendicular(start, end, NODE_RADIUS + maxPenetration + 20);
  const cp1  = { x: mid.x + perp.x, y: mid.y + perp.y };
  const cp2  = { x: mid.x - perp.x, y: mid.y - perp.y };

  // Bow away from the obstacle. When the obstacle sits (almost) exactly
  // on the midpoint the two candidates are equidistant from it, and a
  // bare `>` resolved that degenerate tie on floating-point noise. While
  // edges were routed in screen space that made the curve flip sides
  // mid-pan, because panning changes the absolute coordinates and hence
  // the rounding. Routing in graph space already removes the pan
  // dependency; an explicit epsilon also stops the tie being decided by
  // rounding at all, so the choice is reproducible run to run.
  const d1 = dist(cp1, worstObstacle.position);
  const d2 = dist(cp2, worstObstacle.position);
  const control = Math.abs(d1 - d2) < 1e-6
    ? cp1                 // degenerate: pick a side, deterministically
    : (d1 > d2 ? cp1 : cp2);

  return `M ${startX} ${startY} Q ${control.x} ${control.y} ${endX} ${endY}`;
}

// ---------------------------------------------------------------------------
// Archimedean spiral position
// ---------------------------------------------------------------------------

export function childPosition(parent: Point, globalIndex: number): Point {
  let r     = SPIRAL_START_R;
  let theta = -Math.PI / 2;

  for (let i = 0; i < globalIndex; i++) {
    const dTheta = MIN_SEP / r;
    theta += dTheta;
    r      = SPIRAL_START_R + SPIRAL_B * theta;
  }

  return {
    x: parent.x + Math.cos(theta) * r,
    y: parent.y + Math.sin(theta) * r,
  };
}