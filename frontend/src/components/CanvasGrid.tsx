// src/components/CanvasGrid.tsx
import React from "react";
import type { Viewport } from "../types/graph";
import { useTheme } from "../hooks/useTheme";

interface Props {
  viewport: Viewport;
  width:    number;
  height:   number;
}

const BASE  = 40;
const DOT_R = 0.9;

export default function CanvasGrid({ viewport, width, height }: Props) {
  const { canvasBackground, gridColor } = useTheme();
  const { x: panX, y: panY, zoom } = viewport;
  const spacing = BASE * zoom;

  if (spacing < 6) {
    return (
      <div
        className="absolute inset-0"
        style={{ background: canvasBackground }}
      />
    );
  }

  const r    = DOT_R * Math.min(1.6, Math.max(0.5, zoom));
  const offX = ((panX % spacing) + spacing) % spacing;
  const offY = ((panY % spacing) + spacing) % spacing;

  return (
    <svg
      className="absolute inset-0 pointer-events-none"
      width={width} height={height}
      style={{ background: canvasBackground }}
    >
      <defs>
        <pattern
          id="wcdot"
          width={spacing} height={spacing}
          patternUnits="userSpaceOnUse"
          x={offX} y={offY}
        >
          <circle
            cx={spacing / 2}
            cy={spacing / 2}
            r={r}
            fill={gridColor}
          />
        </pattern>

        <radialGradient id="originGlow">
          <stop offset="0%"   stopColor="rgba(139,92,246,.28)" />
          <stop offset="100%" stopColor="rgba(139,92,246,0)" />
        </radialGradient>
      </defs>

      <rect width={width} height={height} fill="url(#wcdot)" />

      {/* Origin crosshair */}
      <circle cx={panX} cy={panY} r={160} fill="url(#originGlow)" />
      <line x1={panX - 14} y1={panY} x2={panX + 14} y2={panY}
            stroke="rgba(139,92,246,.35)" strokeWidth="1" />
      <line x1={panX} y1={panY - 14} x2={panX} y2={panY + 14}
            stroke="rgba(139,92,246,.35)" strokeWidth="1" />
    </svg>
  );
}