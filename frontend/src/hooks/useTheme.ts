// src/hooks/useTheme.ts
// ─────────────────────────────────────────────────────────────────────────────
// Persisted theme store.
//
// Every value lives in localStorage under the key `whocord-theme`, so
// customisations survive page reloads and full app restarts.  The store
// rehydrates synchronously on init so the canvas paints with the saved
// theme on first frame (no flash of defaults).

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { NodeEntityType } from "../types/graph";

export interface ThemeState {
  // Canvas
  canvasBackground: string;
  gridColor:        string;

  // Edges
  edgeColor:       string;   // default stroke
  edgeThickness:   number;   // 1 .. 5
  edgeOpacity:     number;   // 0.1 .. 1
  edgeHoverColor:  string;   // glow colour when a *node* is hovered
  edgeHoverGlow:   number;   // 0 .. 3  (drop-shadow blur multiplier)

  // Node rings
  nodeHoverRingColor:    string;
  nodeSelectedRingColor: string;
  nodeStrokeColor:       string;

  // Per-entity-type node fill colours
  entityColors: Record<NodeEntityType, string>;

  // Actions
  set: <K extends keyof ThemeState>(key: K, value: ThemeState[K]) => void;
  setEntityColor: (type: NodeEntityType, color: string) => void;
  reset: () => void;
}

// Default fills per entity type.  These are intentionally *dark* variants
// so the accent ring colour (which stays fixed) pops on top.
export const DEFAULT_ENTITY_COLORS: Record<NodeEntityType, string> = {
  email:          "#0b1220",
  username:       "#0d1117",
  social_profile: "#0b1220",
  phone:          "#1a0d13",
  domain:         "#1a1408",
  url:            "#0a171a",
  image:          "#1a0a17",
  breach:         "#1a0a0f",
  ip:             "#07130d",
  name:           "#1a1408",
  location:       "#08140f",
  unknown:        "#141414",
};

const DEFAULTS = {
  canvasBackground:      "#0a0a0d",
  gridColor:             "rgba(255,255,255,.09)",
  edgeColor:             "rgba(160,160,180,.55)",
  edgeThickness:         1.5,
  edgeOpacity:           0.6,
  edgeHoverColor:        "#8b5cf6",
  edgeHoverGlow:         1.4,
  nodeHoverRingColor:    "#f59e0b",
  nodeSelectedRingColor: "#8b5cf6",
  nodeStrokeColor:       "rgba(0,0,0,.35)",
  entityColors:          { ...DEFAULT_ENTITY_COLORS },
};

export const useTheme = create<ThemeState>()(
  persist(
    (set) => ({
      ...DEFAULTS,

      set: (key, value) => set({ [key]: value } as any),
      setEntityColor: (type, color) =>
        set((s) => ({ entityColors: { ...s.entityColors, [type]: color } })),
      reset: () =>
        set({
          ...DEFAULTS,
          entityColors: { ...DEFAULT_ENTITY_COLORS },
        }),
    }),
    {
      name: "whocord-theme",   // localStorage key
      version: 1,
    },
  ),
);