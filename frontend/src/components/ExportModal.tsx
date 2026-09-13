// src/components/ExportModal.tsx
// ─────────────────────────────────────────────────────────────────────────────
// Modal with two export options: Download PNG and Save Map (.whocord-map).

import React, { useState } from "react";
import type { GraphEdge, GraphNode, Viewport } from "../types/graph";
import { downloadMapFile, exportAsPNG } from "../utils/export";

interface Props {
  nodes:           GraphNode[];
  edges:           GraphEdge[];
  viewport:        Viewport;
  canvasElementId: string;
  onClose:         () => void;
}

export default function ExportModal({ nodes, edges, viewport, canvasElementId, onClose }: Props) {
  const [pngBusy, setPngBusy] = useState(false);
  const [pngDone, setPngDone] = useState(false);

  const handleExportPNG = async () => {
    setPngBusy(true);
    const el = document.getElementById(canvasElementId);
    if (el) {
      await exportAsPNG(el);
      setPngDone(true);
      setTimeout(() => setPngDone(false), 2000);
    }
    setPngBusy(false);
  };

  const handleSaveMap = () => {
    downloadMapFile(nodes, edges, viewport);
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/20 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Dialog */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div
          className="bg-white rounded-2xl shadow-2xl border border-gray-200
                     w-full max-w-sm p-6"
          onClick={e => e.stopPropagation()}
        >
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-base font-bold text-gray-900">Export / Save</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-700 text-lg leading-none"
            >
              ✕
            </button>
          </div>

          <div className="space-y-3">
            {/* PNG */}
            <button
              onClick={handleExportPNG}
              disabled={pngBusy}
              className="w-full flex items-center gap-4 rounded-xl border border-gray-200
                         px-4 py-3 hover:bg-gray-50 transition-colors text-left
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <span className="text-2xl">🖼</span>
              <div>
                <p className="text-sm font-semibold text-gray-900">
                  {pngDone ? "Downloaded ✓" : pngBusy ? "Capturing…" : "Download PNG"}
                </p>
                <p className="text-xs text-gray-500">
                  High-resolution image of the entire canvas
                </p>
              </div>
            </button>

            {/* Save map */}
            <button
              onClick={handleSaveMap}
              className="w-full flex items-center gap-4 rounded-xl border border-gray-200
                         px-4 py-3 hover:bg-gray-50 transition-colors text-left"
            >
              <span className="text-2xl">💾</span>
              <div>
                <p className="text-sm font-semibold text-gray-900">Save Map</p>
                <p className="text-xs text-gray-500">
                  Save as <code className="text-[10px]">.whocord-map</code> — restores
                  all nodes, edges and positions
                </p>
              </div>
            </button>
          </div>

          <p className="mt-4 text-[11px] text-gray-400 text-center">
            {nodes.length} nodes · {edges.length} edges
          </p>
        </div>
      </div>
    </>
  );
}
