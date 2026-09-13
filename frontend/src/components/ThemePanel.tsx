// src/components/ThemePanel.tsx
// ─────────────────────────────────────────────────────────────────────────────
// Theme customisation panel.  Every change is written straight to the
// persisted `whocord-theme` store so it survives reloads.

import React from "react";
import { useTheme, DEFAULT_ENTITY_COLORS } from "../hooks/useTheme";
import { Icon, type IconName } from "./Icons";
import type { NodeEntityType } from "../types/graph";

interface Props {
  isOpen:  boolean;
  onClose: () => void;
}

const ENTITY_ROWS: Array<{ type: NodeEntityType; label: string }> = [
  { type: "email",          label: "Email" },
  { type: "username",       label: "Username" },
  { type: "social_profile", label: "Social" },
  { type: "phone",          label: "Phone" },
  { type: "domain",         label: "Domain" },
  { type: "url",            label: "URL" },
  { type: "image",          label: "Image" },
  { type: "breach",         label: "Breach" },
  { type: "ip",             label: "IP" },
  { type: "name",           label: "Name" },
  { type: "location",       label: "Location" },
  { type: "unknown",        label: "Other" },
];

export default function ThemePanel({ isOpen, onClose }: Props) {
  const t = useTheme();

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm anim-in"
        onClick={onClose}
      />

      {/* Centering wrapper */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="surface anim-pop flex flex-col pointer-events-auto w-full"
          style={{ maxWidth: "min(660px, 96vw)", maxHeight: "86vh" }}
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4
                          border-b border-edge-0 shrink-0">
            <div className="flex items-center gap-2.5">
              <span className="text-violet-300">
                <Icon name="palette" size={16} />
              </span>
              <h2 className="text-base font-bold text-white">Theme</h2>
              <span className="chip chip-violet !py-0.5 !text-[9px]">auto-saved</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={t.reset}
                className="btn !text-[11px] !px-2.5 !py-1"
              >
                <Icon name="refresh" size={11} /> Reset
              </button>
              <button onClick={onClose} className="btn btn-ghost !p-1.5">
                <Icon name="close" size={14} />
              </button>
            </div>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto px-6 py-5 space-y-7">
            {/* Canvas */}
            <Section title="Canvas" icon="layout">
              <ColorRow
                label="Background"
                value={t.canvasBackground}
                onChange={v => t.set("canvasBackground", v)}
              />
              <ColorRow
                label="Grid dots"
                value={t.gridColor}
                onChange={v => t.set("gridColor", v)}
                alpha
              />
            </Section>

            {/* Edges */}
            <Section title="Edges" icon="activity">
              <ColorRow
                label="Default colour"
                value={t.edgeColor}
                onChange={v => t.set("edgeColor", v)}
                alpha
              />
              <ColorRow
                label="Node-hover glow"
                value={t.edgeHoverColor}
                onChange={v => t.set("edgeHoverColor", v)}
              />
              <SliderRow
                label="Thickness"
                min={1} max={5} step={0.5}
                value={t.edgeThickness}
                format={v => `${v.toFixed(1)} px`}
                onChange={v => t.set("edgeThickness", v)}
              />
              <SliderRow
                label="Opacity"
                min={0.1} max={1} step={0.05}
                value={t.edgeOpacity}
                format={v => `${Math.round(v * 100)}%`}
                onChange={v => t.set("edgeOpacity", v)}
              />
              <SliderRow
                label="Glow intensity"
                min={0} max={3} step={0.1}
                value={t.edgeHoverGlow}
                format={v => `${v.toFixed(1)}×`}
                onChange={v => t.set("edgeHoverGlow", v)}
              />
            </Section>

            {/* Node rings */}
            <Section title="Node rings" icon="target">
              <ColorRow
                label="Selection ring"
                value={t.nodeSelectedRingColor}
                onChange={v => t.set("nodeSelectedRingColor", v)}
              />
              <ColorRow
                label="Highlight ring"
                value={t.nodeHoverRingColor}
                onChange={v => t.set("nodeHoverRingColor", v)}
              />
              <ColorRow
                label="Default stroke"
                value={t.nodeStrokeColor}
                onChange={v => t.set("nodeStrokeColor", v)}
                alpha
              />
            </Section>

            {/* Per-entity node colours */}
            <Section title="Node colours" icon="palette">
              <p className="text-[11px] text-zinc-500 -mt-1 mb-2">
                Fill colour per entity type. The themed accent ring on top
                stays its identity colour regardless of the fill.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ENTITY_ROWS.map(row => {
                  const isCustom = t.entityColors[row.type] !== DEFAULT_ENTITY_COLORS[row.type];
                  return (
                    <div
                      key={row.type}
                      className="flex items-center gap-3 rounded-lg border border-edge-1
                                 bg-ink-800/50 px-3 py-2"
                    >
                      <input
                        type="color"
                        value={t.entityColors[row.type]}
                        onChange={e => t.setEntityColor(row.type, e.target.value)}
                        className="w-7 h-7 rounded cursor-pointer bg-transparent
                                   border border-edge-1 shrink-0"
                      />
                      <span className="flex-1 text-[12px] text-zinc-300">
                        {row.label}
                      </span>
                      {isCustom && (
                        <button
                          onClick={() =>
                            t.setEntityColor(row.type, DEFAULT_ENTITY_COLORS[row.type])
                          }
                          className="text-[10px] text-zinc-500 hover:text-zinc-200"
                          title="Reset to default"
                        >
                          ↺
                        </button>
                      )}
                      <span className="text-[10px] font-mono text-zinc-600">
                        {t.entityColors[row.type]}
                      </span>
                    </div>
                  );
                })}
              </div>
            </Section>
          </div>
        </div>
      </div>
    </>
  );
}

/* ── Layout helpers ─────────────────────────────────────────────── */

function Section({
  title, icon, children,
}: { title: string; icon: IconName; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
        <Icon name={icon} size={14} className="text-violet-300" />
        {title}
      </h3>
      <div className="space-y-2.5">{children}</div>
    </section>
  );
}

function ColorRow({
  label, value, onChange, alpha,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  alpha?: boolean;
}) {
  const isHex = value.startsWith("#");
  return (
    <div className="flex items-center gap-3">
      <span className="flex-1 text-[12px] text-zinc-300">{label}</span>

      {isHex ? (
        <input
          type="color"
          value={value}
          onChange={e => onChange(e.target.value)}
          className="w-9 h-8 rounded cursor-pointer bg-transparent
                     border border-edge-1 shrink-0"
        />
      ) : (
        <div
          className="w-9 h-8 rounded border border-edge-1 shrink-0"
          style={{ background: value }}
          title={value}
        />
      )}

      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        className="field !py-1 !text-[11px] !w-40 font-mono"
      />
    </div>
  );
}

function SliderRow({
  label, min, max, step, value, format, onChange,
}: {
  label: string;
  min: number; max: number; step: number;
  value: number;
  format: (v: number) => string;
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
        <span>{label}</span>
        <span className="font-bold text-white tabular-nums">
          {format(value)}
        </span>
      </label>
      <input
        type="range"
        min={min} max={max} step={step}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-full accent-violet-500"
      />
    </div>
  );
}