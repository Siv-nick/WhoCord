// src/pages/History.tsx
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  deleteInvestigation,
  fetchInvestigations,
  investigationReportUrl,
} from "../utils/api";
import { Icon } from "../components/Icons";
import type { Job } from "../types/investigation";

function StatusBadge({ status }: { status: Job["status"] }) {
  const map: Record<Job["status"], string> = {
    done:      "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    running:   "bg-violet-500/15 text-violet-300 border-violet-500/30 animate-pulse",
    error:     "bg-rose-500/15 text-rose-300 border-rose-500/30",
    cancelled: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  };
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border
                      uppercase tracking-wider ${map[status] ?? map.done}`}>
      {status}
    </span>
  );
}

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleString(); }
  catch { return iso; }
}

/** Rows per page. The backend caps `limit` at 1000; 50 keeps the table
 *  readable and the payload small. */
const PAGE_SIZE = 50;

export default function History() {
  const navigate                = useNavigate();
  const [jobs, setJobs]         = useState<Job[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [confirmId, setConfirm] = useState<string | null>(null);
  const [flashMsg, setFlash]    = useState("");
  const [offset, setOffset]     = useState(0);
  const [total, setTotal]       = useState(0);

  // `fetchInvestigations` resolves to a JobPage ({ jobs, total, ... }),
  // not a bare array. Assigning the page object straight into a
  // Job[] state was a compile error (TS2345) that broke `npm run
  // build`, and in dev it threw "jobs.map is not a function" on first
  // render. Destructure the page and track `total` so the pager can
  // tell whether more rows exist server-side.
  const load = useCallback(async (nextOffset: number) => {
    setLoading(true);
    setError("");
    try {
      const page = await fetchInvestigations({
        limit:  PAGE_SIZE,
        offset: nextOffset,
      });
      setJobs(page.jobs ?? []);
      setTotal(page.total ?? 0);
      setOffset(page.offset ?? nextOffset);
    } catch {
      setError("Failed to load investigation history.");
      setJobs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const reload = useCallback(() => { void load(offset); }, [load, offset]);

  useEffect(() => { void load(0); }, [load]);

  const handleDelete = async (id: string) => {
    setDeleting(id);
    setConfirm(null);
    const res = await deleteInvestigation(id);
    setDeleting(null);
    if (!res.success) {
      setFlash(`Delete failed: ${res.error ?? "unknown error"}`);
      setTimeout(() => setFlash(""), 4000);
      return;
    }
    setFlash(`Deleted ${id.slice(0, 8)}… (${res.files_removed?.length ?? 0} file(s))`);
    setTimeout(() => setFlash(""), 4000);
    // Deleting the only row on the last page would otherwise strand the
    // operator on an empty page with no way back.
    const lastRowOnPage = jobs.length === 1 && offset > 0;
    await load(lastRowOnPage ? Math.max(0, offset - PAGE_SIZE) : offset);
  };

  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd   = offset + jobs.length;
  const hasPrev   = offset > 0;
  const hasNext   = offset + jobs.length < total;

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Investigation History</h1>
          <p className="text-[13px] text-zinc-500 mt-0.5">
            {total > 0
              ? `Showing ${pageStart}–${pageEnd} of ${total} run${total === 1 ? "" : "s"}.`
              : "All past and active investigation runs."}
          </p>
        </div>
        <button onClick={reload} className="btn">
          <Icon name="refresh" size={12} /> Refresh
        </button>
      </div>

      {flashMsg && (
        <div className="mb-4 rounded-lg border border-violet-500/30 bg-violet-500/10
                        px-4 py-2 text-sm text-violet-200 anim-pop">
          {flashMsg}
        </div>
      )}

      {loading && <div className="text-zinc-500 text-sm">Loading…</div>}
      {error   && <div className="text-rose-400 text-sm">{error}</div>}

      {!loading && !error && jobs.length === 0 && offset === 0 && (
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
          <div className="grid grid-cols-[1fr_90px_120px_150px_100px_130px]
                          px-4 py-2.5 border-b border-edge-0 eyebrow">
            <span>Target</span>
            <span>Mode</span>
            <span>Case</span>
            <span>Started</span>
            <span>Status</span>
            <span className="text-right">Actions</span>
          </div>

          {jobs.map((job, i) => (
            <div
              key={job.id}
              className={`grid grid-cols-[1fr_90px_120px_150px_100px_130px]
                          px-4 py-3 items-center text-sm
                          ${i % 2 === 0 ? "bg-ink-900/60" : "bg-ink-850/60"}
                          ${i < jobs.length - 1 ? "border-b border-edge-0" : ""}`}
            >
              <span className="text-zinc-300 font-mono truncate pr-4"
                    title={job.target}>
                {job.target || "—"}
              </span>
              <span className="text-zinc-500 text-xs">{job.mode || "—"}</span>
              <span className="text-zinc-500 text-xs truncate pr-2"
                    title={job.case_id}>
                {job.case_id || "—"}
              </span>
              <span className="text-zinc-500 text-xs">{formatDate(job.started_at)}</span>
              <span><StatusBadge status={job.status} /></span>

              <div className="flex gap-2 justify-end items-center">
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

                {confirmId === job.id ? (
                  <>
                    <button
                      onClick={() => handleDelete(job.id)}
                      disabled={deleting === job.id}
                      className="text-[10px] font-bold px-2 py-1 rounded
                                 border border-rose-500/50 bg-rose-500/20
                                 text-rose-200 hover:bg-rose-500/30
                                 disabled:opacity-40"
                    >
                      {deleting === job.id ? "…" : "Confirm"}
                    </button>
                    <button
                      onClick={() => setConfirm(null)}
                      className="text-[10px] px-2 py-1 rounded border
                                 border-edge-1 text-zinc-400 hover:text-zinc-200"
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => setConfirm(job.id)}
                    disabled={job.status === "running"}
                    title={
                      job.status === "running"
                        ? "Stop the investigation before deleting"
                        : "Delete this investigation and its files"
                    }
                    className="text-[10px] font-semibold px-2 py-1 rounded border
                               border-edge-1 text-zinc-500
                               hover:border-rose-500/40 hover:text-rose-300
                               disabled:opacity-30 disabled:hover:border-edge-1
                               disabled:hover:text-zinc-500
                               inline-flex items-center gap-1"
                  >
                    <Icon name="trash" size={10} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {!loading && !error && (hasPrev || hasNext) && (
        <div className="flex items-center justify-between mt-4">
          <button
            onClick={() => load(Math.max(0, offset - PAGE_SIZE))}
            disabled={!hasPrev}
            className="btn disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Icon name="chevronLeft" size={12} /> Previous
          </button>

          <span className="text-[11px] text-zinc-500 tabular-nums">
            Page {Math.floor(offset / PAGE_SIZE) + 1} of{" "}
            {Math.max(1, Math.ceil(total / PAGE_SIZE))}
          </span>

          <button
            onClick={() => load(offset + PAGE_SIZE)}
            disabled={!hasNext}
            className="btn disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Next <Icon name="chevronRight" size={12} />
          </button>
        </div>
      )}
    </div>
  );
}