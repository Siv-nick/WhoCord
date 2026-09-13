// src/utils/export.ts
// ─────────────────────────────────────────────────────────────────────────────
// Canvas export (PNG) and map serialisation (.whocord-map JSON).

import type { GraphEdge, GraphNode, MapSaveFile, Viewport } from "../types/graph";

const MAP_VERSION = "1.0";

// ---------------------------------------------------------------------------
// PNG export via html2canvas
// ---------------------------------------------------------------------------

/**
 * Capture the canvas element as a high-resolution PNG and trigger a download.
 * Falls back to a warning if html2canvas is not available.
 */
export async function exportAsPNG(
  canvasElement: HTMLElement,
  filename: string = "whocord-map.png",
): Promise<void> {
  try {
    // Dynamic import so the app still works if html2canvas fails to load
    const html2canvas = (await import("html2canvas")).default;
    const canvas = await html2canvas(canvasElement, {
      backgroundColor: "#ffffff",
      scale: 2,                // 2× for retina quality
      useCORS: true,
      logging: false,
    });
    const link     = document.createElement("a");
    link.download  = filename;
    link.href      = canvas.toDataURL("image/png");
    link.click();
  } catch (err) {
    console.warn("html2canvas not available; falling back to SVG screenshot.", err);
    // Fallback: try to get an SVG element and convert
    const svg = canvasElement.querySelector("svg");
    if (svg) {
      const blob = new Blob([svg.outerHTML], { type: "image/svg+xml" });
      const url  = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.download = filename.replace(".png", ".svg");
      link.href     = url;
      link.click();
      URL.revokeObjectURL(url);
    }
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
    nodes:    nodes.map(n => ({
      ...n,
      // Ensure Sets are not included (InfoField values are plain strings)
    })),
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
  URL.revokeObjectURL(url);
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

    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) { reject(new Error("No file selected.")); return; }

      try {
        const text = await file.text();
        const data = JSON.parse(text);
        resolve(deserializeMap(data));
      } catch (err) {
        reject(new Error(`Could not parse map file: ${err}`));
      }
    };

    input.oncancel = () => reject(new Error("File picker cancelled."));
    input.click();
  });
}
