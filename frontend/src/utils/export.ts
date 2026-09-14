// src/utils/export.ts
// ─────────────────────────────────────────────────────────────────────────────
// Canvas export (PNG) and map serialisation (.whocord-map JSON).
//
// Change log
// ----------
// - PNG export no longer hardcodes `backgroundColor: "#ffffff"`. The
//   canvas is dark; a white background produced an inverted-looking image
//   with black-on-white nodes. The background is now read from the active
//   theme so exports match what the analyst sees.
// - The file picker uses both `change` and (where supported) `cancel` to
//   resolve the promise — older browsers that don't fire `cancel` still
//   work because `change` fires an empty file list on close in most cases.
//   A defensive timeout ensures the promise never hangs forever.

import type { GraphEdge, GraphNode, MapSaveFile, Viewport } from "../types/graph";

const MAP_VERSION = "1.0";

// ---------------------------------------------------------------------------
// Theme lookup
// ---------------------------------------------------------------------------

/**
 * Read the current canvas background from the persisted theme store.
 * Falls back to the theme default when localStorage is unavailable.
 */
function currentCanvasBackground(): string {
  try {
    const raw = localStorage.getItem("whocord-theme");
    if (raw) {
      const parsed = JSON.parse(raw);
      // zustand persist wraps state under `state`
      const bg = parsed?.state?.canvasBackground;
      if (typeof bg === "string" && bg.trim()) return bg;
    }
  } catch {
    /* ignore — fall through */
  }
  return "#0a0a0d";
}

// ---------------------------------------------------------------------------
// PNG export via html2canvas
// ---------------------------------------------------------------------------

/**
 * Capture the canvas element as a high-resolution PNG and trigger a download.
 * Falls back to an SVG snapshot if html2canvas is unavailable.
 */
export async function exportAsPNG(
  canvasElement: HTMLElement,
  filename: string = "whocord-map.png",
): Promise<void> {
  const bg = currentCanvasBackground();

  try {
    const html2canvas = (await import("html2canvas")).default;
    const canvas = await html2canvas(canvasElement, {
      backgroundColor: bg,
      scale: 2,                // 2× for retina quality
      useCORS: true,
      logging: false,
    });
    const link     = document.createElement("a");
    link.download  = filename;
    link.href      = canvas.toDataURL("image/png");
    link.click();
  } catch (err) {
    console.warn("html2canvas unavailable; falling back to SVG snapshot.", err);

    const svg = canvasElement.querySelector("svg");
    if (!svg) return;

    // Clone so we can inline the current background as a <rect>.
    const clone = svg.cloneNode(true) as SVGSVGElement;
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("width", "100%");
    rect.setAttribute("height", "100%");
    rect.setAttribute("fill", bg);
    clone.insertBefore(rect, clone.firstChild);

    const svgText = new XMLSerializer().serializeToString(clone);
    const blob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
    const url  = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.download = filename.replace(/\.png$/i, ".svg");
    link.href     = url;
    link.click();

    // Revoke after the browser has had a chance to start the download.
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
}

// ---------------------------------------------------------------------------
// Map serialisation
// ---------------------------------------------------------------------------

/**
 * Serialise the current graph state into a MapSaveFile.
 */
export function serializeMap(
  nodes:    GraphNode[],
  edges:    GraphEdge[],
  viewport: Viewport,
): MapSaveFile {
  return {
    version:  MAP_VERSION,
    savedAt:  new Date().toISOString(),
    nodes:    nodes.map(n => ({ ...n })),
    edges,
    viewport,
  };
}

/**
 * Deserialise a MapSaveFile back to {nodes, edges, viewport}.
 * Throws when the file format is unrecognised.
 */
export function deserializeMap(data: unknown): {
  nodes: GraphNode[];
  edges: GraphEdge[];
  viewport: Viewport;
} {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid map file: expected a JSON object.");
  }
  const file = data as Partial<MapSaveFile>;

  if (!Array.isArray(file.nodes) || !Array.isArray(file.edges)) {
    throw new Error("Invalid map file: missing nodes or edges arrays.");
  }

  return {
    nodes:    file.nodes    as GraphNode[],
    edges:    file.edges    as GraphEdge[],
    viewport: file.viewport ?? { x: 0, y: 0, zoom: 1 },
  };
}

// ---------------------------------------------------------------------------
// Trigger JSON file download
// ---------------------------------------------------------------------------

export function downloadMapFile(
  nodes:    GraphNode[],
  edges:    GraphEdge[],
  viewport: Viewport,
  filename: string = "investigation.whocord-map",
): void {
  const data = serializeMap(nodes, edges, viewport);
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.download = filename;
  link.href     = url;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ---------------------------------------------------------------------------
// Open file picker and read a .whocord-map file
// ---------------------------------------------------------------------------

export function openMapFilePicker(): Promise<{
  nodes: GraphNode[];
  edges: GraphEdge[];
  viewport: Viewport;
}> {
  return new Promise((resolve, reject) => {
    const input   = document.createElement("input");
    input.type    = "file";
    input.accept  = ".whocord-map,application/json";

    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) {
        // Some browsers fire `change` with an empty list when the picker
        // is dismissed — treat that as cancel rather than hanging.
        settle(() => reject(new Error("File picker cancelled.")));
        return;
      }
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        settle(() => resolve(deserializeMap(data)));
      } catch (err) {
        settle(() => reject(new Error(`Could not parse map file: ${err}`)));
      }
    };

    // `oncancel` is not universally supported. Attach defensively —
    // browsers that don't fire it rely on the empty-list change above.
    const onCancel = () => settle(() => reject(new Error("File picker cancelled.")));
    if ("oncancel" in input) {
      (input as any).oncancel = onCancel;
    }

    // Final safety: if neither change nor cancel fires (rare, but seen
    // with certain browser extensions), resolve with a clear error after
    // a generous timeout rather than leaking a pending promise forever.
    setTimeout(() => settle(() => reject(new Error("File picker timed out."))), 5 * 60_000);

    input.click();
  });
}