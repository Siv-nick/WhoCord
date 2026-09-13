// src/components/LiveLogPanel.tsx
import React, { useEffect, useRef } from "react";
import { Icon, type IconName } from "./Icons";

interface Props {
  logs: string[];
  isOpen: boolean;
  onToggle: () => void;
  currentStage?: string | null;
}

const STAGE_ICON: Record<string, IconName> = {
  discord_mode:         "message",
  discovery:            "search",
  scraping:             "code",
  media:                "image",
  analysis:             "activity",
  intelligence:         "brain",
  email_intel:          "mail",
  reporting:            "layout",
  email_investigation:  "mail",
  domain_investigation: "globe",
  phone_investigation:  "phone",
  image_analysis:       "image",
  url_analysis:         "link",
  data_probe:           "search",
};

export default function LiveLogPanel({
  logs, isOpen, onToggle, currentStage,
}: Props) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs.length, isOpen]);

  const stageIcon: IconName | null = currentStage
    ? (STAGE_ICON[currentStage] ?? "play")
    : null;

  return (
    <div
      className="fixed right-0 top-0 h-full z-20 flex items-stretch"
      style={{ pointerEvents: "none" }}
    >
      {/* Toggle tab */}
      <button
        onClick={onToggle}
        className="self-center btn !rounded-r-none !rounded-l-lg !py-4 !px-2 !text-[11px]
                   hover:!border-violet-500/40"
        style={{ pointerEvents: "auto", writingMode: "vertical-rl" }}
        title={isOpen ? "Hide logs" : "Show logs"}
      >
        <span className="tracking-widest uppercase font-bold flex items-center gap-1.5">
          {stageIcon && <Icon name={stageIcon} size={11} />}
          Logs
          {logs.length > 0 && <span className="text-violet-300">{logs.length}</span>}
        </span>
      </button>

      {/* Panel */}
      <div
        className="bg-ink-900/95 backdrop-blur-xl border-l border-edge-0
                   flex flex-col transition-[width,opacity] duration-300 overflow-hidden"
        style={{
          width: isOpen ? 340 : 0,
          opacity: isOpen ? 1 : 0,
          pointerEvents: isOpen ? "auto" : "none",
        }}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-edge-0 shrink-0">
          <div className="flex items-center gap-2">
            {stageIcon && (
              <span className="text-violet-300">
                <Icon name={stageIcon} size={14} />
              </span>
            )}
            <span className="text-[12px] font-semibold text-zinc-200">
              Live Logs
            </span>
            <span className="chip !py-0.5 !text-[9px]">{logs.length}</span>
          </div>
          <button onClick={onToggle} className="btn btn-ghost !p-1.5">
            <Icon name="close" size={13} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-2.5 font-mono text-[10.5px]
                        leading-relaxed bg-ink-950/60 space-y-px">
          {logs.length === 0 ? (
            <div className="flex flex-col items-center gap-2 mt-10">
              <span className="text-zinc-700">
                <Icon name="terminal" size={20} />
              </span>
              <p className="text-zinc-600 text-[11px]">Waiting for events…</p>
            </div>
          ) : (
            logs.map((line, i) => {
              const color =
                line.includes("[!]")   ? "text-rose-400"
                : line.includes("[✓]") ? "text-emerald-400"
                : line.includes("[API]") ? "text-violet-300"
                : line.includes("==")  ? "text-violet-400 font-semibold"
                : "text-zinc-500";
              return (
                <div key={i} className={`whitespace-pre-wrap break-all ${color}`}>
                  {line}
                </div>
              );
            })
          )}
          <div ref={endRef} />
        </div>
      </div>
    </div>
  );
}