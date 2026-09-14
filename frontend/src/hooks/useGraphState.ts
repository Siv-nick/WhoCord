// src/hooks/useGraphState.ts
// ─────────────────────────────────────────────────────────────────────────────
// Zustand store – single source of truth for canvas graph state.
//
// Change log
// ----------
// - New `removeNodes(ids)` batched method. Deleting a branch used to call
//   `removeNode(id)` once per node in a `.forEach`, producing N store
//   updates and N re-renders of every subscriber (edges, nodes, cards,
//   chat context). Bulk deletion now happens in one set() call.
// - `useSelectedNode` / `useFilteredNodeIds` remain memoized — the
//   original version built a fresh Set on every render which gave every
//   `<GraphNode>` a new `dimmed` prop identity and forced a full
//   re-render of the canvas on any state change. That fix is retained.
// - `removeNode` (singular) is preserved for the popup's single-node
//   deletion path where the N=1 case is trivially fine.

import { useMemo } from "react";
import { create } from "zustand";
import type {
  FilterState,
  GraphEdge,
  GraphNode,
  NodeEntityType,
  Viewport,
} from "../types/graph";

// ---------------------------------------------------------------------------
// ID helpers
// ---------------------------------------------------------------------------

let _nodeSeq = 0;
let _edgeSeq = 0;
export const newNodeId = () => `node_${++_nodeSeq}_${Date.now()}`;
export const newEdgeId = () => `edge_${++_edgeSeq}_${Date.now()}`;

// ---------------------------------------------------------------------------
// Store shape
// ---------------------------------------------------------------------------

interface GraphState {
  // Data
  nodes:          GraphNode[];
  edges:          GraphEdge[];
  viewport:       Viewport;

  // UI selection
  selectedNodeId: string | null;

  // Hover state for edge glow
  hoveredNodeId:  string | null;

  // Filters
  filter:         FilterState;

  // ── Node mutations ───────────────────────────────────────────────────
  addNode:    (node: GraphNode) => void;
  removeNode: (id: string) => void;
  removeNodes:(ids: string[]) => void;   // batched
  updateNode: (id: string, patch: Partial<GraphNode>) => void;

  // ── Edge mutations ───────────────────────────────────────────────────
  addEdge:    (edge: GraphEdge) => void;
  removeEdge: (id: string) => void;

  // ── Selection / hover ────────────────────────────────────────────────
  selectNode:     (id: string | null) => void;
  setHoveredNode: (id: string | null) => void;

  // ── Viewport ─────────────────────────────────────────────────────────
  setViewport:  (vp: Partial<Viewport>) => void;
  panBy:        (dx: number, dy: number) => void;
  zoomTo:       (zoom: number) => void;

  // ── Filters ──────────────────────────────────────────────────────────
  setTypeFilter:   (type: NodeEntityType, enabled: boolean) => void;
  setSearchFilter: (text: string) => void;
  clearFilters:    () => void;

  // ── Persistence ──────────────────────────────────────────────────────
  loadMap: (nodes: GraphNode[], edges: GraphEdge[], viewport: Viewport) => void;
  clearMap: () => void;
}

// ---------------------------------------------------------------------------
// Default entity types visible (all on)
// ---------------------------------------------------------------------------

const ALL_TYPES = new Set<NodeEntityType>([
  "username", "email", "phone", "domain", "url",
  "social_profile", "image", "breach", "ip", "name", "location", "unknown",
]);

// ---------------------------------------------------------------------------
// Store definition
// ---------------------------------------------------------------------------

export const useGraphState = create<GraphState>((set, get) => ({
  nodes:          [],
  edges:          [],
  viewport:       { x: 0, y: 0, zoom: 1 },
  selectedNodeId: null,
  hoveredNodeId:  null,
  filter: {
    types:      new Set(ALL_TYPES),
    searchText: "",
  },

  // ── Node mutations ─────────────────────────────────────────────────────

  addNode: (node) =>
    set((s) => ({ nodes: [...s.nodes, node] })),

  removeNode: (id) =>
    set((s) => ({
      nodes:          s.nodes.filter((n) => n.id !== id),
      edges:          s.edges.filter((e) => e.sourceId !== id && e.targetId !== id),
      selectedNodeId: s.selectedNodeId === id ? null : s.selectedNodeId,
      hoveredNodeId:  s.hoveredNodeId  === id ? null : s.hoveredNodeId,
    })),

  /**
   * Batched removal. Given a set of node ids, drops them and every edge
   * incident to any of them in a single state update. Use this when
   * deleting a whole branch — the singular removeNode() fires one
   * subscription notification per call which is fine for N=1 but
   * wasteful for the ten-to-fifty nodes a branch can have.
   */
  removeNodes: (ids) =>
    set((s) => {
      if (ids.length === 0) return s;
      const dropSet = new Set(ids);
      const nextSelected = dropSet.has(s.selectedNodeId ?? "")
        ? null
        : s.selectedNodeId;
      const nextHovered = dropSet.has(s.hoveredNodeId ?? "")
        ? null
        : s.hoveredNodeId;
      return {
        nodes: s.nodes.filter((n) => !dropSet.has(n.id)),
        edges: s.edges.filter(
          (e) => !dropSet.has(e.sourceId) && !dropSet.has(e.targetId),
        ),
        selectedNodeId: nextSelected,
        hoveredNodeId:  nextHovered,
      };
    }),

  updateNode: (id, patch) =>
    set((s) => ({
      nodes: s.nodes.map((n) => (n.id === id ? { ...n, ...patch } : n)),
    })),

  // ── Edge mutations ─────────────────────────────────────────────────────

  addEdge: (edge) =>
    set((s) => {
      const exists = s.edges.some(
        (e) => e.sourceId === edge.sourceId && e.targetId === edge.targetId,
      );
      return exists ? s : { edges: [...s.edges, edge] };
    }),

  removeEdge: (id) =>
    set((s) => ({ edges: s.edges.filter((e) => e.id !== id) })),

  // ── Selection / hover ──────────────────────────────────────────────────

  selectNode: (id) => set({ selectedNodeId: id }),

  setHoveredNode: (id) => set({ hoveredNodeId: id }),

  // ── Viewport ───────────────────────────────────────────────────────────

  setViewport: (vp) =>
    set((s) => ({ viewport: { ...s.viewport, ...vp } })),

  panBy: (dx, dy) =>
    set((s) => ({
      viewport: { ...s.viewport, x: s.viewport.x + dx, y: s.viewport.y + dy },
    })),

  zoomTo: (zoom) =>
    set((s) => ({
      viewport: { ...s.viewport, zoom: Math.min(3, Math.max(0.2, zoom)) },
    })),

  // ── Filters ────────────────────────────────────────────────────────────

  setTypeFilter: (type, enabled) =>
    set((s) => {
      const next = new Set(s.filter.types);
      if (enabled) next.add(type); else next.delete(type);
      return { filter: { ...s.filter, types: next } };
    }),

  setSearchFilter: (text) =>
    set((s) => ({ filter: { ...s.filter, searchText: text } })),

  clearFilters: () =>
    set({ filter: { types: new Set(ALL_TYPES), searchText: "" } }),

  // ── Persistence ────────────────────────────────────────────────────────

  loadMap: (nodes, edges, viewport) =>
    set({ nodes, edges, viewport, selectedNodeId: null, hoveredNodeId: null }),

  clearMap: () =>
    set({
      nodes:          [],
      edges:          [],
      selectedNodeId: null,
      hoveredNodeId:  null,
      viewport:       { x: 0, y: 0, zoom: 1 },
    }),
}));

// ---------------------------------------------------------------------------
// Selector helpers
// ---------------------------------------------------------------------------

/**
 * Returns the currently selected node, or null.
 *
 * The selector is memoized against the node array and the selected id, so
 * unrelated state updates (viewport pan, hover, etc.) do not produce a new
 * value and do not trigger re-renders of consumers.
 */
export function useSelectedNode(): GraphNode | null {
  const nodes          = useGraphState((s) => s.nodes);
  const selectedNodeId = useGraphState((s) => s.selectedNodeId);

  return useMemo(
    () => (selectedNodeId ? nodes.find((n) => n.id === selectedNodeId) ?? null : null),
    [nodes, selectedNodeId],
  );
}

/**
 * Returns the set of node ids that pass the current filter.
 *
 * Memoized on the node array and the filter object — the original version
 * rebuilt a fresh `Set` on every render, which gave every `<GraphNode>` a
 * new `dimmed` prop identity and forced a full re-render of the canvas on
 * any state change. Now it recomputes only when nodes or filters change.
 */
export function useFilteredNodeIds(): Set<string> {
  const nodes  = useGraphState((s) => s.nodes);
  const filter = useGraphState((s) => s.filter);

  return useMemo(() => {
    const result = new Set<string>();
    const q      = filter.searchText.trim().toLowerCase();

    for (const node of nodes) {
      if (!filter.types.has(node.entityType)) continue;

      if (q) {
        const match =
          node.label.toLowerCase().includes(q) ||
          node.infoFields.some((f) => f.value.toLowerCase().includes(q));
        if (!match) continue;
      }

      result.add(node.id);
    }
    return result;
  }, [nodes, filter]);
}