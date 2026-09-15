// src/components/PivotConfirmModal.tsx
import React, { useCallback, useEffect, useRef, useState } from "react";
import type { PivotConfirmRequestPayload, PivotSeed } from "../types/investigation";
import { confirmPivot } from "../utils/api";
import { Icon, type IconName } from "./Icons";

interface Props {
  payload: PivotConfirmRequestPayload;
  onClose: () => void;
}

const SEED_ICON: Record<string, IconName> = {
  email:    "mail",
  username: "user",
};

export default function PivotConfirmModal({ payload, onClose }: Props) {
  const { job_id, depth, seeds, timeout_seconds } = payload;

  const [checked, setChecked]     = useState<Set<string>>(() => new Set(seeds.map(s => s.value)));
  const [submitting, setSub]      = useState(false);
  const [countdown, setCD]        = useState(timeout_seconds);
  const timerRef                  = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const handleRun = useCallback(async (all = false) => {
    if (submitting) return;
    setSub(true);
    clearTimer();

    const approved: PivotSeed[] = all
      ? seeds
      : seeds.filter(s => checked.has(s.value));

    await confirmPivot(job_id, approved).catch(() => {});
    onClose();
  }, [submitting, seeds, checked, job_id, onClose, clearTimer]);

  const handleSkipAll = useCallback(async () => {
    if (submitting) return;
    setSub(true);
    clearTimer();
    await confirmPivot(job_id, []).catch(() => {});
    onClose();
  }, [submitting, job_id, onClose, clearTimer]);

  // Countdown to auto-skip. The server treats an unanswered prompt as
  // "run zero seeds" and the client must match — an auto-approve here
  // would let a slow user silently approve pivots they never saw.
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setCD(prev => {
        if (prev <= 1) {
          clearTimer();
          handleSkipAll();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearTimer();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggle = (value: string) => {
    setChecked(prev => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else                 next.add(value);
      return next;
    });
  };

  const pct = Math.round((countdown / timeout_seconds) * 100);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center
                    bg-black/70 backdrop-blur-sm anim-in">
      <div className="w-full max-w-md mx-4 surface anim-pop overflow-hidden">

        <div className="px-5 py-4 border-b border-edge-0
                        bg-gradient-to-r from-emerald-500/[.06] to-transparent">
          <div className="flex items-center gap-2 mb-1">
            <div className="h-7 w-7 rounded-lg bg-emerald-500/15 border border-emerald-500/25
                            flex items-center justify-center text-emerald-300 shrink-0">
              <Icon name="refresh" size={14} />
            </div>
            <h2 className="text-base font-bold text-white">Pivot investigation</h2>
            <span className="ml-auto chip chip-ok !py-0.5 !text-[10px]">
              Depth {depth}
            </span>
          </div>
          <p className="text-[11px] text-zinc-400 leading-relaxed mt-1">
            New seeds were discovered. Select which to investigate. If you
            do not respond within {timeout_seconds}s, the investigation
            continues without running any pivot seeds.
          </p>
        </div>

        <div className="px-5 pt-3">
          <div className="flex items-center justify-between text-[11px] text-zinc-500 mb-1">
            <span>Auto-skipping in {countdown}s</span>
            <span className="tabular-nums">
              {seeds.filter(s => checked.has(s.value)).length} / {seeds.length} selected
            </span>
          </div>
          <div className="h-1 rounded-full bg-ink-800 overflow-hidden">
            <div
              className="h-full bg-emerald-500 rounded-full transition-all duration-1000"
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>

        <div className="px-5 py-4 space-y-2 max-h-72 overflow-y-auto">
          {seeds.map(seed => {
            const isChecked = checked.has(seed.value);
            const iconName  = SEED_ICON[seed.type] ?? "dot";
            return (
              <label
                key={seed.value}
                className={[
                  "flex items-center gap-3 rounded-lg border px-3 py-2.5 cursor-pointer",
                  "transition-all duration-150",
                  isChecked
                    ? "border-emerald-500/40 bg-emerald-500/[.06]"
                    : "border-edge-1 bg-ink-850/40 opacity-60",
                ].join(" ")}
              >
                <div
                  onClick={() => toggle(seed.value)}
                  className={[
                    "w-4 h-4 rounded border-2 flex items-center justify-center shrink-0",
                    "transition-colors",
                    isChecked ? "border-emerald-500 bg-emerald-500" : "border-edge-2",
                  ].join(" ")}
                >
                  {isChecked && (
                    <Icon name="check" size={9} strokeWidth={3} />
                  )}
                </div>

                <span className="text-zinc-400 flex items-center" style={{ width: 14 }}>
                  <Icon name={iconName} size={13} />
                </span>

                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-mono text-zinc-200 truncate">
                    {seed.value}
                  </p>
                  <p className="text-[10px] text-zinc-500 capitalize">{seed.type}</p>
                </div>
              </label>
            );
          })}
        </div>

        <div className="px-5 pb-5 flex gap-3 border-t border-edge-0 pt-4">
          <button
            onClick={() => handleRun(false)}
            disabled={submitting || checked.size === 0}
            className="flex-1 btn btn-primary justify-center !py-2.5"
          >
            <Icon name="play" size={12} />
            {submitting
              ? "Starting…"
              : `Run ${checked.size} seed${checked.size !== 1 ? "s" : ""}`}
          </button>
          <button
            onClick={handleSkipAll}
            disabled={submitting}
            className="flex-1 btn justify-center !py-2.5 hover:!border-rose-500/40
                       hover:!text-rose-300"
          >
            <Icon name="close" size={12} /> Skip all
          </button>
        </div>
      </div>
    </div>
  );
}