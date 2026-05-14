// src/components/StageList.tsx
import React from "react";
import type { PivotInfo, StageState, StageStatus } from "../types/investigation";

const STAGE_ORDER = [
  "discord_mode", "discovery", "scraping", "media",
  "analysis", "intelligence", "email_intel", "reporting",
];

const STAGE_LABELS: Record<string, string> = {
  discord_mode:  "Discord Profile",
  discovery:     "Discovery",
  scraping:      "Profile Scraping",
  media:         "Media & EXIF",
  analysis:      "Analysis",
  intelligence:  "Intelligence Engine",
  email_intel:   "Email Intelligence",
  reporting:     "Report Generation",
};

const STATUS_STYLES: Record<StageStatus, { dot: string; row: string; label: string }> = {
  pending: { dot: "bg-neutral-600",                       row: "opacity-40",  label: "—"        },
  running: { dot: "bg-indigo-400 animate-pulse",          row: "opacity-100", label: "running…" },
  done:    { dot: "bg-emerald-500",                       row: "opacity-100", label: "done"     },
  error:   { dot: "bg-red-500",                           row: "opacity-100", label: "error"    },
  aborted: { dot: "bg-amber-500",                         row: "opacity-60",  label: "aborted"  },
};

const PIVOT_STATUS_STYLES: Record<string, { dot: string; label: string; textColor: string }> = {
  pending_confirm: { dot: "bg-amber-400 animate-pulse",  label: "confirm?", textColor: "text-amber-400" },
  running:         { dot: "bg-green-400 animate-pulse",  label: "running…", textColor: "text-green-400" },
  done:            { dot: "bg-emerald-500",              label: "merged",   textColor: "text-emerald-500"},
  error:           { dot: "bg-red-500",                  label: "error",    textColor: "text-red-400"   },
  skipped:         { dot: "bg-neutral-600",              label: "skipped",  textColor: "text-neutral-600"},
};

function elapsed(state: StageState): string {
  if (!state.startedAt) return "";
  const end = state.finishedAt ?? Date.now();
  const ms  = end - state.startedAt;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const SEED_ICON: Record<string, string> = {
  email:    "✉️",
  username: "👤",
};

interface Props {
  stages:    StageState[];
  pivots?:   PivotInfo[];
  className?: string;
}

export default function StageList({ stages, pivots = [], className = "" }: Props) {
  const byName: Record<string, StageState> = {};
  for (const s of stages) byName[s.name] = s;

  const ordered = STAGE_ORDER.map(name => byName[name] ?? {
    name,
    displayName: STAGE_LABELS[name] ?? name,
    status: "pending" as StageStatus,
    depth: 0,
  });

  const hasPivots = pivots.length > 0;

  return (
    <div className={`rounded-lg border border-neutral-800 bg-neutral-900 overflow-hidden ${className}`}>

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="px-4 py-2 border-b border-neutral-800 text-xs font-semibold
                      text-neutral-500 uppercase tracking-wider flex items-center gap-2">
        Pipeline Stages
        {hasPivots && (
          <span className="ml-auto text-[10px] font-bold px-1.5 py-0.5 rounded
                           bg-green-900 text-green-400">
            {pivots.length} pivot{pivots.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* ── Main stages ────────────────────────────────────────── */}
      <ul className="divide-y divide-neutral-800">
        {ordered.map(stage => {
          const st = STATUS_STYLES[stage.status];
          return (
            <li
              key={stage.name}
              className={`flex items-center gap-3 px-4 py-2.5 text-sm ${st.row} transition-opacity`}
            >
              <span className={`inline-block w-2.5 h-2.5 rounded-full shrink-0 ${st.dot}`} />
              <span className="flex-1 text-neutral-300">
                {STAGE_LABELS[stage.name] ?? stage.name}
              </span>
              {stage.startedAt && (
                <span className="text-xs text-neutral-600 tabular-nums">{elapsed(stage)}</span>
              )}
              <span className={`text-xs tabular-nums ${
                stage.status === "running" ? "text-indigo-400"
                : stage.status === "done"  ? "text-emerald-500"
                : stage.status === "error" ? "text-red-400"
                : "text-neutral-600"
              }`}>
                {st.label}
              </span>
            </li>
          );
        })}
      </ul>

      {/* ── Pivot sub-investigations ────────────────────────────── */}
      {hasPivots && (
        <>
          <div className="px-4 py-1.5 border-t border-neutral-800 bg-neutral-950
                          text-[10px] font-semibold text-green-700 uppercase tracking-wider">
            🔄 Pivot Branches
          </div>
          <ul className="divide-y divide-neutral-800/60">
            {pivots.map((pivot, i) => {
              const ps = PIVOT_STATUS_STYLES[pivot.status] ?? PIVOT_STATUS_STYLES.running;
              return (
                <li
                  key={`${pivot.seed}-${i}`}
                  className="flex items-center gap-2 pl-6 pr-4 py-2 text-xs"
                >
                  {/* Depth indicator line */}
                  <span className="text-neutral-700 shrink-0 font-mono">
                    {"└".repeat(pivot.depth)}
                  </span>

                  {/* Seed type icon */}
                  <span className="shrink-0">{SEED_ICON[pivot.seedType] ?? "•"}</span>

                  {/* Depth badge */}
                  <span className="shrink-0 text-[9px] font-bold px-1 py-0.5 rounded
                                   bg-green-950 text-green-600 border border-green-900">
                    d={pivot.depth}
                  </span>

                  {/* Seed value */}
                  <span className="flex-1 text-neutral-400 font-mono truncate" title={pivot.seed}>
                    {pivot.seed}
                  </span>

                  {/* Status dot */}
                  <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${ps.dot}`} />

                  {/* Status label */}
                  <span className={`tabular-nums shrink-0 ${ps.textColor}`}>
                    {ps.label}
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
