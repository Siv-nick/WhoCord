// src/components/BatchModal.tsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { startBatch, fetchBatch, type BatchDetail } from "../utils/api";
import { Icon, type IconName } from "./Icons";

// Server-side cap in web_app.py's /api/batch handler. Keep these in sync.
const SERVER_TARGET_CAP = 500;

const BATCH_MODES: Array<{ id: string; label: string; icon: IconName }> = [
  { id: "manual", label: "Usernames", icon: "atSign" },
  { id: "email",  label: "Emails",    icon: "mail"   },
  { id: "domain", label: "Domains",   icon: "globe"  },
  { id: "phone",  label: "Phones",    icon: "phone"  },
  { id: "url",    label: "URLs",      icon: "link"   },
];

interface Props {
  onClose: () => void;
}

export default function BatchModal({ onClose }: Props) {
  const navigate = useNavigate();
  const [mode,     setMode]     = useState<string>("manual");
  const [rawInput, setRawInput] = useState("");
  const [caseId,   setCaseId]   = useState("");
  const [busy,     setBusy]     = useState(false);
  const [error,    setError]    = useState("");
  const [batch,    setBatch]    = useState<BatchDetail | null>(null);

  // One target per non-blank line, deduplicated.
  const targets = Array.from(
    new Set(
      rawInput
        .split(/\r?\n/)
        .map(s => s.trim())
        .filter(Boolean),
    ),
  );

  const overCap = targets.length > SERVER_TARGET_CAP;

  // Poll the batch summary while any job is still running.
  useEffect(() => {
    if (!batch) return;
    const iv = window.setInterval(async () => {
      try {
        const fresh = await fetchBatch(batch.batch_id);
        setBatch(fresh);
        if (fresh.jobs.every(j => j.status !== "running")) {
          window.clearInterval(iv);
        }
      } catch {
        /* keep polling */
      }
    }, 3_000);
    return () => window.clearInterval(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch?.batch_id]);

  const handleStart = async () => {
    if (targets.length === 0) {
      setError("Enter at least one target.");
      return;
    }
    if (overCap) {
      setError(
        `Too many targets: ${targets.length}. The server caps a batch ` +
        `run at ${SERVER_TARGET_CAP}. Trim the list and try again.`,
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      const summary = await startBatch(targets, mode, caseId || undefined);
      if (summary.error) throw new Error(summary.error);
      const detail = await fetchBatch(summary.batch_id);
      setBatch(detail);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleTrimToCap = () => {
    setRawInput(targets.slice(0, SERVER_TARGET_CAP).join("\n"));
    setError("");
  };

  const doneCount = batch?.jobs.filter(j => j.status === "done").length ?? 0;

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm anim-in"
        onClick={onClose}
      />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4
                      pointer-events-none">
        <div
          className="surface anim-pop flex flex-col pointer-events-auto w-full"
          style={{ maxWidth: "min(680px, 96vw)", maxHeight: "86vh" }}
          onClick={e => e.stopPropagation()}
        >
          <div className="flex items-center justify-between px-5 py-4
                          border-b border-edge-0 shrink-0">
            <div className="flex items-center gap-2.5">
              <span className="text-violet-300">
                <Icon name="list" size={16} />
              </span>
              <h2 className="text-base font-bold text-white">Batch investigation</h2>
            </div>
            <button onClick={onClose} className="btn btn-ghost !p-1.5">
              <Icon name="close" size={14} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-5 py-5">
            {!batch && (
              <>
                <p className="text-[12px] text-zinc-500 mb-4 leading-snug">
                  Run the same module against many targets. Each target becomes
                  its own job, sharing a case id — view them in History once
                  the batch finishes.
                </p>

                <label className="eyebrow block mb-1.5">Module</label>
                <div className="grid grid-cols-5 gap-2 mb-5">
                  {BATCH_MODES.map(m => {
                    const active = mode === m.id;
                    return (
                      <button
                        key={m.id}
                        onClick={() => setMode(m.id)}
                        className={[
                          "flex flex-col items-center gap-1.5 rounded-xl border py-2.5 px-1",
                          "text-[10px] font-semibold transition-all",
                          active
                            ? "border-violet-500/60 bg-violet-500/15 text-violet-100"
                            : "border-edge-1 text-zinc-400 hover:border-edge-2 hover:text-zinc-100",
                        ].join(" ")}
                      >
                        <Icon name={m.icon} size={15} />
                        <span>{m.label}</span>
                      </button>
                    );
                  })}
                </div>

                <label className="eyebrow block mb-1.5">
                  Targets
                  <span className="text-zinc-600 normal-case tracking-normal ml-1">
                    — one per line ({targets.length} parsed)
                  </span>
                </label>
                <textarea
                  value={rawInput}
                  onChange={e => setRawInput(e.target.value)}
                  rows={8}
                  placeholder={"alice\nalice_dev\nbob_42"}
                  className={[
                    "field !text-[12px] font-mono resize-y leading-relaxed !py-2",
                    overCap ? "!border-amber-500/40 !ring-1 !ring-amber-500/20" : "",
                  ].join(" ")}
                />

                {/* Over-cap warning. The server will reject the request
                    if this reaches it; the client catches it earlier so
                    the operator does not lose their paste. */}
                {overCap && (
                  <div className="mt-2 rounded-lg border border-amber-500/30
                                  bg-amber-500/[.06] px-3 py-2.5
                                  flex items-start gap-2.5 anim-pop">
                    <span className="shrink-0 mt-0.5 text-amber-300">
                      <Icon name="alert" size={13} />
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-[12px] font-semibold text-amber-200">
                        {targets.length} targets — over the {SERVER_TARGET_CAP} cap
                      </p>
                      <p className="text-[11px] text-amber-200/80 mt-0.5 leading-snug">
                        The server rejects batches larger than{" "}
                        {SERVER_TARGET_CAP}. Trim the list, or run it in
                        multiple batches.
                      </p>
                      <button
                        onClick={handleTrimToCap}
                        className="mt-2 text-[11px] text-amber-200
                                   hover:text-amber-100 underline-offset-2
                                   hover:underline font-semibold"
                      >
                        Keep first {SERVER_TARGET_CAP}
                      </button>
                    </div>
                  </div>
                )}

                <label className="eyebrow block mb-1.5 mt-4">
                  Case id
                  <span className="text-zinc-600 normal-case tracking-normal ml-1">
                    — optional, auto-generated when blank
                  </span>
                </label>
                <input
                  value={caseId}
                  onChange={e => setCaseId(e.target.value)}
                  placeholder="e.g. case-2026-04-alice"
                  className="field !py-1.5 !text-sm mb-4"
                />

                {error && (
                  <p className="text-[12px] text-rose-400 mb-3 flex items-center gap-1.5">
                    <Icon name="alert" size={11} /> {error}
                  </p>
                )}

                <div className="flex gap-2">
                  <button
                    onClick={handleStart}
                    disabled={busy || targets.length === 0 || overCap}
                    className="flex-1 btn btn-primary justify-center !py-2.5
                               disabled:!opacity-40 disabled:!cursor-not-allowed"
                    title={overCap ? `Reduce to ${SERVER_TARGET_CAP} targets` : undefined}
                  >
                    <Icon name="play" size={12} />
                    {busy
                      ? "Starting…"
                      : overCap
                      ? `Too many targets`
                      : `Start ${targets.length || ""} job${targets.length === 1 ? "" : "s"}`}
                  </button>
                  <button onClick={onClose} className="btn !px-4">
                    Cancel
                  </button>
                </div>
              </>
            )}

            {batch && (
              <>
                <div className="flex items-center gap-3 mb-4 flex-wrap">
                  <span className="chip chip-violet">
                    batch {batch.batch_id.slice(0, 8)}
                  </span>
                  {batch.case_id && (
                    <span className="chip">case {batch.case_id}</span>
                  )}
                  <span className="ml-auto text-[11px] text-zinc-500 tabular-nums">
                    {doneCount} / {batch.jobs.length} done
                  </span>
                </div>

                <div className="rounded-lg border border-edge-1 overflow-hidden">
                  {batch.jobs.map((j, i) => (
                    <div
                      key={j.job_id}
                      className={[
                        "flex items-center gap-3 px-3 py-2 text-[12px]",
                        i % 2 === 0 ? "bg-ink-850/60" : "bg-ink-900/60",
                        i < batch.jobs.length - 1 ? "border-b border-edge-0" : "",
                      ].join(" ")}
                    >
                      <span
                        className="font-mono text-zinc-300 truncate flex-1"
                        title={j.target}
                      >
                        {j.target}
                      </span>
                      <span
                        className={[
                          "text-[10px] font-bold uppercase tracking-wider shrink-0",
                          j.status === "done"      ? "text-emerald-400"
                          : j.status === "running" ? "text-violet-400 animate-pulse"
                          : j.status === "error"   ? "text-rose-400"
                          : j.status === "cancelled" ? "text-amber-400"
                          : "text-zinc-500",
                        ].join(" ")}
                      >
                        {j.status}
                      </span>
                      {j.has_report && (
                        <a
                          href={`/api/investigations/${j.job_id}/report`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[10px] text-violet-300 hover:underline shrink-0"
                        >
                          report
                        </a>
                      )}
                    </div>
                  ))}
                </div>

                <div className="flex gap-2 mt-4">
                  <button
                    onClick={() => navigate("/dashboard/history")}
                    className="flex-1 btn justify-center"
                  >
                    <Icon name="refresh" size={12} /> Open history
                  </button>
                  <button onClick={onClose} className="btn !px-4">
                    Close
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </>
  );
}