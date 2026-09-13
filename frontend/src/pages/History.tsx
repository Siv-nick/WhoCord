// src/pages/History.tsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchInvestigations, investigationReportUrl } from "../utils/api";
import { Icon } from "../components/Icons";
import type { Job } from "../types/investigation";

function StatusBadge({ status }: { status: Job["status"] }) {
  const map: Record<Job["status"], string> = {
    done:    "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    running: "bg-violet-500/15 text-violet-300 border-violet-500/30 animate-pulse",
    error:   "bg-rose-500/15 text-rose-300 border-rose-500/30",
  };
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border
                      uppercase tracking-wider ${map[status]}`}>
      {status}
    </span>
  );
}

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleString(); }
  catch { return iso; }
}

export default function History() {
  const navigate              = useNavigate();
  const [jobs, setJobs]       = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");

  const load = async () => {
    setLoading(true);
    try { setJobs(await fetchInvestigations()); }
    catch { setError("Failed to load investigation history."); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Investigation History</h1>
          <p className="text-[13px] text-zinc-500 mt-0.5">
            All past and active investigation runs.
          </p>
        </div>
        <button onClick={load} className="btn">
          <Icon name="refresh" size={12} /> Refresh
        </button>
      </div>

      {loading && <div className="text-zinc-500 text-sm">Loading…</div>}
      {error   && <div className="text-rose-400 text-sm">{error}</div>}

      {!loading && !error && jobs.length === 0 && (
        <div className="text-center py-16">
          <div className="mx-auto mb-4 h-14 w-14 rounded-full border border-edge-1
                          bg-ink-850 flex items-center justify-center text-zinc-600">
            <Icon name="search" size={22} />
          </div>
          <p className="text-sm text-zinc-500">No investigations yet.</p>
          <button onClick={() => navigate("/")} className="btn btn-primary mt-4">
            <Icon name="sparkle" size={12} /> Start one
          </button>
        </div>
      )}

      {!loading && jobs.length > 0 && (
        <div className="surface overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_80px_160px_90px_120px] px-4 py-2.5
                          border-b border-edge-0 eyebrow">
            <span>Target</span>
            <span>Mode</span>
            <span>Started</span>
            <span>Status</span>
            <span>Actions</span>
          </div>

          {jobs.map((job, i) => (
            <div
              key={job.id}
              className={`grid grid-cols-[1fr_80px_160px_90px_120px] px-4 py-3
                          items-center text-sm
                          ${i % 2 === 0 ? "bg-ink-900/60" : "bg-ink-850/60"}
                          ${i < jobs.length - 1 ? "border-b border-edge-0" : ""}`}
            >
              <span className="text-zinc-300 font-mono truncate pr-4">
                {job.target || "—"}
              </span>
              <span className="text-zinc-500 text-xs">{job.mode || "—"}</span>
              <span className="text-zinc-500 text-xs">{formatDate(job.started_at)}</span>
              <span><StatusBadge status={job.status} /></span>
              <div className="flex gap-2">
                {job.has_report && (
                  <a
                    href={investigationReportUrl(job.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] font-semibold px-2 py-1 rounded border
                               border-violet-500/40 bg-violet-500/10 text-violet-200
                               hover:bg-violet-500/20 transition-colors
                               inline-flex items-center gap-1"
                  >
                    <Icon name="external" size={10} /> Report
                  </a>
                )}
                {job.has_intel && (
                  <a
                    href={`/api/investigations/${job.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] font-semibold px-2 py-1 rounded border
                               border-edge-1 bg-white/[.03] text-zinc-400
                               hover:bg-white/[.06] transition-colors"
                  >
                    JSON
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}