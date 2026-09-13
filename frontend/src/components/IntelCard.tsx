// src/components/IntelCard.tsx
import React, { useState } from "react";
import type { FindingPayload } from "../types/investigation";
import { Icon } from "./Icons";

interface Correlation {
  type: string;
  description: string;
  confidence: number;
}

interface Props {
  payload: FindingPayload;
}

function ConfidencePill({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const cls =
    value >= 0.75 ? "bg-orange-500/15 text-orange-300 border-orange-500/30"
    : value >= 0.50 ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
    : "bg-sky-500/15 text-sky-300 border-sky-500/30";
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${cls}`}>
      {pct}%
    </span>
  );
}

export default function IntelCard({ payload }: Props) {
  const [open, setOpen] = useState(true);

  const entityCount      = (payload.entity_count as number) ?? 0;
  const correlationCount = (payload.correlation_count as number) ?? 0;
  const hasNarrative     = Boolean(payload.has_narrative);
  const correlations     = payload.correlations as Correlation[] | undefined;

  return (
    <div className="rounded-xl border border-emerald-500/30 bg-ink-850/70
                    overflow-hidden anim-rise">
      {/* Header */}
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left
                   hover:bg-white/[.03] transition-colors"
      >
        <div className="h-8 w-8 rounded-lg bg-emerald-500/15 border border-emerald-500/25
                        flex items-center justify-center text-emerald-300 shrink-0">
          <Icon name="brain" size={15} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-emerald-200">
            Intelligence Report
          </p>
          <p className="text-[11px] text-zinc-500">
            {entityCount} entities · {correlationCount} correlations
            {hasNarrative ? " · AI narrative" : ""}
          </p>
        </div>
        <Icon name={open ? "chevronUp" : "chevronDown"} size={14}
              className="text-zinc-500 shrink-0" />
      </button>

      {/* Body */}
      {open && (
        <div className="px-4 pb-4 border-t border-edge-0">
          <div className="flex gap-6 mt-3 mb-3">
            <Stat label="Entities"     value={entityCount}      tone="emerald" />
            <Stat label="Correlations" value={correlationCount} tone="violet"  />
            <Stat label="Narrative"    value={hasNarrative ? "✓" : "—"} tone="amber" />
          </div>

          {correlationCount > 0 && correlations && correlations.length > 0 && (
            <div className="space-y-1.5">
              <p className="eyebrow mb-1">Top correlations</p>
              {correlations.slice(0, 5).map((c, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2 rounded-lg bg-ink-800
                             border border-edge-1 px-2.5 py-1.5"
                >
                  <ConfidencePill value={c.confidence} />
                  <span className="text-[11.5px] text-zinc-300 flex-1 leading-snug">
                    {c.description}
                  </span>
                </div>
              ))}
            </div>
          )}

          <p className="mt-3 text-[10px] text-zinc-600">
            Full intelligence section available in the HTML report.
          </p>
        </div>
      )}
    </div>
  );
}

function Stat({
  label, value, tone,
}: { label: string; value: number | string; tone: "emerald" | "violet" | "amber" }) {
  const color =
    tone === "emerald" ? "text-emerald-400"
    : tone === "violet" ? "text-violet-400"
    : "text-amber-400";
  return (
    <div className="text-center">
      <div className={`text-lg font-bold tabular-nums ${color}`}>{value}</div>
      <div className="text-[10px] text-zinc-500 uppercase tracking-wider">{label}</div>
    </div>
  );
}