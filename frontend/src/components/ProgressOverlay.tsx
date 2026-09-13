// src/components/ProgressOverlay.tsx
// ─────────────────────────────────────────────────────────────────────────────
// Circular progress ring + percentage text, rendered on top of a node
// while an investigation is running.

import React from "react";

interface Props {
  progress: number;   // 0–100
  radius:   number;   // node radius in screen px
}

export default function ProgressOverlay({ progress, radius }: Props) {
  const stroke      = 3;
  const r           = radius - stroke;
  const circ        = 2 * Math.PI * r;
  const dashOffset  = circ - (circ * Math.min(progress, 100)) / 100;

  return (
    <g>
      {/* Background track */}
      <circle
        cx={0} cy={0} r={r}
        fill="none"
        stroke="rgba(0,0,0,0.12)"
        strokeWidth={stroke}
      />
      {/* Progress arc */}
      <circle
        cx={0} cy={0} r={r}
        fill="none"
        stroke="#4f46e5"
        strokeWidth={stroke}
        strokeDasharray={circ}
        strokeDashoffset={dashOffset}
        strokeLinecap="round"
        transform="rotate(-90)"
        style={{ transition: "stroke-dashoffset 0.4s ease" }}
      />
      {/* Percentage label */}
      <text
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="9"
        fontWeight="600"
        fill="#4f46e5"
        fontFamily="system-ui, sans-serif"
      >
        {Math.round(progress)}%
      </text>
      {/* Spinning dot indicator */}
      <circle
        cx={0}
        cy={-(r)}
        r={3}
        fill="#4f46e5"
        transform={`rotate(${progress * 3.6})`}
        style={{ transition: "transform 0.4s ease" }}
      />
    </g>
  );
}
