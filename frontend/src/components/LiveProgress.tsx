// src/components/LiveProgress.tsx
import React from "react";
import { Icon, type IconName } from "./Icons";

interface Props {
  currentStage: string | null;
  currentMessage: string;
  status: "idle" | "running" | "done" | "error";
  findingCount: number;
  pivotDepth: number;
}

const STAGE_ICON: Record<string, IconName> = {
  discord_mode: "message",
  discovery:    "search",
  scraping:     "code",
  media:        "image",
  analysis:     "activity",
  intelligence: "brain",
  email_intel:  "mail",
  reporting:    "layout",
};

export default function LiveProgress({
  currentStage,
  currentMessage,
  status,
  findingCount,
  pivotDepth,
}: Props) {
  const icon: IconName = currentStage
    ? (STAGE_ICON[currentStage] ?? "play")
    : "play";
  const isRunning = status === "running";

  return (
    <div className="surface p-4">
      {/* Status row */}
      <div className="flex items-center gap-3 mb-3">
        <div className="relative shrink-0">
          <span className="text-violet-300 flex items-center justify-center
                           h-8 w-8">
            <Icon name={icon} size={20} />
          </span>
          {isRunning && (
            <span className="absolute inset-0 rounded-full border-2 border-violet-500/60 animate-ping opacity-40" />
          )}
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-white truncate">
            {status === "idle" && "Waiting to start…"}
            {status === "running" &&
              (currentStage
                ? currentStage
                    .replace(/_/g, " ")
                    .replace(/\b\w/g, c => c.toUpperCase())
                : "Starting…")}
            {status === "done" && "Investigation complete"}
            {status === "error" && "Investigation encountered an error"}
          </p>
          {currentMessage && (
            <p className="text-[11px] text-zinc-500 truncate">{currentMessage}</p>
          )}
        </div>

        <div className="flex gap-2 shrink-0">
          <span className="chip !py-0.5">
            {findingCount} finding{findingCount !== 1 ? "s" : ""}
          </span>
          {pivotDepth > 0 && (
            <span className="chip chip-ok !py-0.5">
              pivot d={pivotDepth}
            </span>
          )}
        </div>
      </div>

      {/* Bar */}
      {isRunning && (
        <div className="h-1 rounded-full bg-ink-800 overflow-hidden">
          <div className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500
                          rounded-full animate-pulse w-3/4" />
        </div>
      )}
      {status === "done" && <div className="h-1 rounded-full bg-emerald-500" />}
      {status === "error" && <div className="h-1 rounded-full bg-rose-500" />}
    </div>
  );
}