// src/components/StageList.tsx
import React from "react";
import type {
  PivotInfo,
  StageState,
  StageStatus,
} from "../types/investigation";
import { Icon, type IconName } from "./Icons";

const STAGE_ORDER = [
  "discord_mode",
  "discovery",
  "scraping",
  "media",
  "analysis",
  "intelligence",
  "email_intel",
  "reporting",
];

const STAGE_LABELS: Record<string, string> = {
  discord_mode: "Discord Profile",
  discovery:    "Discovery",
  scraping:     "Profile Scraping",
  media:        "Media & EXIF",
  analysis:     "Analysis",
  intelligence: "Intelligence Engine",
  email_intel:  "Email Intelligence",
  reporting:    "Report Generation",
};

const STATUS_STYLES: Record<
  StageStatus,
  { dot: string; row: string; label: string }
> = {
  pending: { dot: "bg-zinc-600",                       row: "opacity-40",  label: "—"        },
  running: { dot: "bg-violet-400 animate-pulse",       row: "opacity-100", label: "running…" },
  done:    { dot: "bg-emerald-500",                    row: "opacity-100", label: "done"     },
  error:   { dot: "bg-rose-500",                       row: "opacity-100", label: "error"    },
  aborted: { dot: "bg-amber-500",                      row: "opacity-60",  label: "aborted"  },
};

const PIVOT_STATUS_STYLES: Record<
  string,
  { dot: string; label: string; textColor: string }
> = {
  pending_confirm: {
    dot: "bg-amber-400 animate-pulse",
    label: "confirm?",
    textColor: "text-amber-400",
  },
  running: {
    dot: "bg-emerald-400 animate-pulse",
    label: "running…",
    textColor: "text-emerald-400",
  },
  done: {
    dot: "bg-emerald-500",
    label: "merged",
    textColor: "text-emerald-500",
  },
  error: {
    dot: "bg-rose-500",
    label: "error",
    textColor: "text-rose-400",
  },
  skipped: {
    dot: "bg-zinc-600",
    label: "skipped",
    textColor: "text-zinc-600",
  },
};

function elapsed(state: StageState): string {
  if (!state.startedAt) return "";
  const end = state.finishedAt ?? Date.now();
  const ms = end - state.startedAt;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const SEED_ICON: Record<string, IconName> = {
  email:    "mail",
  username: "user",
};

interface Props {
  stages: StageState[];
  pivots?: PivotInfo[];
  className?: string;
}

export default function StageList({
  stages,
  pivots = [],
  className = "",
}: Props) {
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
    <div className={`surface overflow-hidden ${className}`}>
      {/* Header */}
      <div className="px-4 py-2 border-b border-edge-0 eyebrow flex items-center gap-2">
        Pipeline Stages
        {hasPivots && (
          <span className="ml-auto chip chip-ok !py-0 !text-[9px]">
            {pivots.length} pivot{pivots.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Stages */}
      <ul className="divide-y divide-edge-0">
        {ordered.map(stage => {
          const st = STATUS_STYLES[stage.status];
          return (
            <li
              key={stage.name}
              className={`flex items-center gap-3 px-4 py-2.5 text-[13px] ${st.row} transition-opacity`}
            >
              <span
                className={`inline-block w-2 h-2 rounded-full shrink-0 ${st.dot}`}
              />
              <span className="flex-1 text-zinc-300">
                {STAGE_LABELS[stage.name] ?? stage.name}
              </span>
              {stage.startedAt && (
                <span className="text-[11px] text-zinc-600 tabular-nums">
                  {elapsed(stage)}
                </span>
              )}
              <span
                className={`text-[11px] tabular-nums ${
                  stage.status === "running"
                    ? "text-violet-400"
                    : stage.status === "done"
                    ? "text-emerald-500"
                    : stage.status === "error"
                    ? "text-rose-400"
                    : "text-zinc-600"
                }`}
              >
                {st.label}
              </span>
            </li>
          );
        })}
      </ul>

      {/* Pivots */}
      {hasPivots && (
        <>
          <div className="px-4 py-1.5 border-t border-edge-0 bg-ink-950
                          eyebrow !text-emerald-500 flex items-center gap-1.5">
            <Icon name="refresh" size={10} /> Pivot Branches
          </div>
          <ul className="divide-y divide-edge-0/60">
            {pivots.map((pivot, i) => {
              const ps = PIVOT_STATUS_STYLES[pivot.status] ?? PIVOT_STATUS_STYLES.running;
              return (
                <li
                  key={`${pivot.seed}-${i}`}
                  className="flex items-center gap-2 pl-6 pr-4 py-2 text-[11px]"
                >
                  <span className="text-zinc-700 shrink-0 font-mono">
                    {"└".repeat(pivot.depth)}
                  </span>
                  <span className="shrink-0 text-zinc-400">
                    <Icon name={SEED_ICON[pivot.seedType] ?? "dot"} size={11} />
                  </span>
                  <span className="shrink-0 text-[9px] font-bold px-1 py-0.5 rounded
                                   bg-emerald-500/10 text-emerald-400
                                   border border-emerald-500/25">
                    d={pivot.depth}
                  </span>
                  <span className="flex-1 text-zinc-400 font-mono truncate" title={pivot.seed}>
                    {pivot.seed}
                  </span>
                  <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${ps.dot}`} />
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