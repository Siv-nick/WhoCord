// src/components/Icons.tsx
// ─────────────────────────────────────────────────────────────────────────────
// One cohesive icon set. All glyphs are drawn on a 24×24 grid with 1.75px
// strokes and round caps so they feel tuned, not templated.
//
// Two render paths:
//   <Icon name="mail" size={16} />         → standalone <svg> for HTML
//   <Icon x={cx} y={cy} size={40} ... />   → positions itself inside an
//                                             existing <svg> (canvas nodes)
//
// Because nested <svg> is valid SVG, the same component works everywhere.
// ─────────────────────────────────────────────────────────────────────────────

import React from "react";

// ── Icon primitives ───────────────────────────────────────────────────
type El =
  | { t: "p"; d: string }
  | { t: "c"; cx: number; cy: number; r: number }
  | { t: "r"; x: number; y: number; w: number; h: number; rx?: number };

const p = (d: string): El => ({ t: "p", d });
const c = (cx: number, cy: number, r: number): El => ({ t: "c", cx, cy, r });
const r = (x: number, y: number, w: number, h: number, rx = 0): El =>
  ({ t: "r", x, y, w, h, rx });

// ── Registry ─────────────────────────────────────────────────────────
export const ICONS = {
  // ── Actions ──────────────────────────────────────────────────────────
  search:      [c(11, 11, 7), p("M20.5 20.5 L16 16")],
  command:     [p("M9 6v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3")],
  settings:    [p("M4 21v-6"), p("M4 10V3"), p("M12 21v-9"), p("M12 8V3"),
                p("M20 21v-5"), p("M20 12V3"), p("M2 15h4"), p("M10 8h4"), p("M18 16h4")],
  arrowLeft:   [p("M19 12H5"), p("M12 19l-7-7 7-7")],
  arrowRight:  [p("M5 12h14"), p("M12 5l7 7-7 7")],
  plus:        [p("M12 5v14"), p("M5 12h14")],
  minus:       [p("M5 12h14")],
  target:      [c(12, 12, 9), c(12, 12, 3), p("M12 1.5v3"), p("M12 19.5v3"),
                p("M1.5 12h3"), p("M19.5 12h3")],
  upload:      [p("M12 20V8"), p("M8 12l4-4 4 4"), p("M4 4h16")],
  download:    [p("M12 4v12"), p("M8 12l4 4 4-4"), p("M4 20h16")],
  trash:       [p("M3 6h18"), p("M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"),
                p("M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6")],
  palette:     [p("M12 22a10 10 0 1 1 10-10c0 2-2 3-4 3h-2a2 2 0 0 0-2 2c0 1 1 1.5 1 3a2 2 0 0 1-2 2z"),
                c(7.5, 11, 1), c(10, 7.5, 1), c(14, 7.5, 1), c(16.5, 11, 1)],
  refresh:     [p("M21 12a9 9 0 1 1-3-6.7"), p("M21 3v6h-6")],
  terminal:    [p("M4 17l6-6-6-6"), p("M12 19h8")],
  message:     [p("M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z")],
  layout:      [r(3, 3, 7, 7, 1), r(14, 3, 7, 7, 1), r(14, 14, 7, 7, 1), r(3, 14, 7, 7, 1)],
  list:        [p("M8 6h13"), p("M8 12h13"), p("M8 18h13"),
                p("M3.5 6h.01"), p("M3.5 12h.01"), p("M3.5 18h.01")],
  close:       [p("M18 6 6 18"), p("M6 6l12 12")],
  check:       [p("M20 6 9 17l-5-5")],
  copy:        [r(9, 9, 12, 12, 2),
                p("M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1")],
  edit:        [p("M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 3 22l1.5-4.5z")],
  external:    [p("M15 3h6v6"), p("M10 14 21 3"),
                p("M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6")],
  chevronDown: [p("m6 9 6 6 6-6")],
  chevronUp:   [p("m18 15-6-6-6 6")],
  chevronRight:[p("m9 18 6-6-6-6")],
  chevronLeft: [p("m15 18-6-6 6-6")],
  play:        [p("M6 4l14 8-14 8z")],
  stop:        [r(6, 6, 12, 12, 2)],
  eye:         [p("M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"), c(12, 12, 3)],
  shield:      [p("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z")],
  activity:    [p("M22 12h-4l-3 9L9 3l-3 9H2")],
  sparkle:     [p("M12 2l2.09 6.26L20 10l-5.91 1.74L12 18l-2.09-6.26L4 10l5.91-1.74z")],

  // ── Entity / data types ─────────────────────────────────────────────
  mail:        [r(2, 4, 20, 16, 2), p("M22 7l-9 6a2 2 0 0 1-2 0L2 7")],
  atSign:      [c(12, 12, 4), p("M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8")],
  user:        [p("M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"), c(12, 7, 4)],
  users:       [p("M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"), c(9, 7, 4),
                p("M22 21v-2a4 4 0 0 0-3-3.87"), p("M16 3.13a4 4 0 0 1 0 7.75")],
  phone:       [p("M22 17v2a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 3.2 2 2 0 0 1 4.1 1h2a2 2 0 0 1 2 1.7c.1.9.3 1.8.7 2.6a2 2 0 0 1-.5 2.1L7 8.7a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.8.3 1.7.5 2.6.6a2 2 0 0 1 1.7 2z")],
  globe:       [c(12, 12, 9), p("M3 12h18"), p("M12 3a13 13 0 0 0 0 18 13 13 0 0 0 0-18")],
  link:        [p("M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7L12 5"),
                p("M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7L12 19")],
  image:       [r(3, 3, 18, 18, 2), c(9, 9, 2), p("M21 15l-3-3a2 2 0 0 0-2.8 0L6 21")],
  alert:       [p("M10.3 3.8 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.8a2 2 0 0 0-3.4 0z"),
                p("M12 9v4"), p("M12 17h.01")],
  server:      [r(2, 2, 20, 8, 2), r(2, 14, 20, 8, 2), p("M6 6h.01"), p("M6 18h.01")],
  mapPin:      [p("M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"), c(12, 10, 3)],
  dot:         [c(12, 12, 4)],
  brain:       [p("M12 4a4 4 0 0 0-4 4v1a3 3 0 0 0 0 6v1a4 4 0 0 0 8 0v-1a3 3 0 0 0 0-6V8a4 4 0 0 0-4-4z"),
                p("M12 4v16")],
  hash:        [p("M4 9h16"), p("M4 15h16"), p("M10 3 8 21"), p("M16 3l-2 18")],
  key:         [c(8, 15, 4), p("M10.5 12.5 19 4"), p("M16 7l3 3"), p("M19 4l2 2")],
  cross:       [p("M4 4l16 16"), p("M20 4L4 20")],
  wifi:        [p("M5 12a10 10 0 0 1 14 0"), p("M8.5 15.5a5 5 0 0 1 7 0"), c(12, 19, 0.6)],
  code:        [p("M16 18l6-6-6-6"), p("M8 6l-6 6 6 6")],
} satisfies Record<string, El[]>;

export type IconName = keyof typeof ICONS;

// ── Renderer ──────────────────────────────────────────────────────────
function renderEls(els: El[]): React.ReactNode {
  return els.map((e, i) => {
    if (e.t === "p") return <path key={i} d={e.d} />;
    if (e.t === "c") return <circle key={i} cx={e.cx} cy={e.cy} r={e.r} />;
    return <rect key={i} x={e.x} y={e.y} width={e.w} height={e.h} rx={e.rx} />;
  });
}

// ── HTML icon ─────────────────────────────────────────────────────────
export function Icon({
  name, size = 16, strokeWidth = 1.75, className, style,
}: {
  name: IconName;
  size?: number;
  strokeWidth?: number;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24"
      fill="none" stroke="currentColor"
      strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"
      className={className} style={style} aria-hidden
    >
      {renderEls(ICONS[name])}
    </svg>
  );
}

// ── Canvas icon (positions itself inside an existing <svg>) ────────────
// Use inside SVG:  <Icon x={cx} y={cy} size={24} color="#fff" />
export function IconSvg({
  name, x = 0, y = 0, size = 24, color = "currentColor", strokeWidth = 1.75,
}: {
  name: IconName;
  x?: number; y?: number; size?: number;
  color?: string; strokeWidth?: number;
}) {
  const half = size / 2;
  return (
    <svg
      x={x - half} y={y - half}
      width={size} height={size} viewBox="0 0 24 24"
      fill="none" stroke={color}
      strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"
      overflow="visible"
      style={{ pointerEvents: "none" }}
    >
      {renderEls(ICONS[name])}
    </svg>
  );
}