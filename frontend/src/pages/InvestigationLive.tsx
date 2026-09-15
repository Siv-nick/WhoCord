// src/pages/InvestigationLive.tsx
//
// Legacy live view. Reads its params from nav state (passed by
// Dashboard) and streams /run with POST + fetch + ReadableStream.
//
// Change log
// ----------
// - /run is POST-only as of Tier 2, item 1.2. Replaced the previous
//   `useSSE(sseUrl, ...)` with an inline fetch loop that mirrors the
//   pattern in hooks/useInvestigation.ts. The reducer, dispatch flow,
//   and rendering are unchanged.
// - Fixed a stale closure: the finding handler used to read
//   `state.currentStage` captured at first render, so every finding
//   was recorded with an empty stage. Now reads a ref that mirrors
//   the current value.

import React, { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { apiFetch, runUrl, stopInvestigation } from "../utils/api";
import LiveProgress from "../components/LiveProgress";
import StageList from "../components/StageList";
import ResultCard from "../components/ResultCard";
import IntelCard from "../components/IntelCard";
import PivotConfirmModal from "../components/PivotConfirmModal";
import { Icon } from "../components/Icons";
import type {
  Finding,
  FindingCategory,
  FindingPayload,
  InvestigationState,
  PivotConfirmRequestPayload,
  PivotInfo,
  RunParams,
  SSEEvent,
  StageState,
  StageStatus,
} from "../types/investigation";

// ---------------------------------------------------------------------------
// Finding category map
// ---------------------------------------------------------------------------

const FINDING_CATEGORIES: Record<string, FindingCategory> = {
  email:               "email",
  name_clue:           "identity",
  discord_handle:      "identity",
  avatar_url:          "media",
  avatar_downloaded:   "media",
  connected_account:   "social",
  holehe:              "breach",
  hibp:                "breach",
  hibp_skipped:        "breach",
  h8mail:              "breach",
  scylla:              "breach",
  gravatar:            "social",
  ghunt:               "identity",
  emailrep:            "email",
  exif_gps:            "media",
  reverse_image:       "media",
  correlations:        "intelligence",
  intelligence_report: "intelligence",
  persona_summary:     "intelligence",
  wayback:             "social",
  whois:               "social",
  pivot_start:         "pivot",
  pivot_done:          "pivot",
  pivot_error:         "pivot",
  pivot_skipped:       "pivot",
};

function categorise(type: string): FindingCategory {
  return FINDING_CATEGORIES[type] ?? "other";
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

type RunStatus = "idle" | "running" | "stopping" | "done" | "cancelled" | "error";

type Action =
  | { type: "JOB_START";    jobId: string; target: string; mode: InvestigationState["mode"] }
  | { type: "STAGE_START";  stage: string; depth: number }
  | { type: "STAGE_DONE";   stage: string; depth: number }
  | { type: "STAGE_ERROR";  stage: string; error: string }
  | { type: "PROGRESS";     message: string }
  | { type: "FINDING";      finding: Finding }
  | { type: "LOG";          line: string }
  | { type: "PIVOT_ADD";    seed: string; seedType: string; depth: number; status: PivotInfo["status"] }
  | { type: "PIVOT_UPDATE"; seed: string; status: PivotInfo["status"] }
  | { type: "PIVOT_CONFIRM_REQUEST"; payload: PivotConfirmRequestPayload }
  | { type: "PIVOT_CONFIRM_RESOLVED" }
  | { type: "STOPPING" }
  | { type: "STOP_FAILED" }
  | { type: "STREAM_END";   reportUrl: string | null; status: "done" | "cancelled" | "error" }
  | { type: "SSE_INTERRUPTED" }
  | { type: "SSE_RECONNECTED" }
  | { type: "SSE_GIVE_UP" };

interface ExtendedState extends InvestigationState {
  runStatus: RunStatus;
}

const INITIAL: ExtendedState = {
  jobId:               null,
  target:              "",
  mode:                "",
  status:              "idle",
  stages:              [],
  findings:            [],
  logs:                [],
  currentStage:        null,
  reportUrl:           null,
  pivotDepth:          0,
  pivots:              [],
  pivotConfirmPending: null,
  runStatus:           "idle",
};

let _fid = 0;
const nextId = () => `f${++_fid}`;

function updateStage(
  stages: StageState[],
  name: string,
  updates: Partial<StageState>,
): StageState[] {
  const idx = stages.findIndex(s => s.name === name);
  if (idx === -1) {
    return [...stages, { name, displayName: name, status: "pending", depth: 0, ...updates }];
  }
  const next = [...stages];
  next[idx] = { ...next[idx], ...updates };
  return next;
}

function updatePivot(
  pivots: PivotInfo[],
  seed: string,
  status: PivotInfo["status"],
): PivotInfo[] {
  return pivots.map(p => (p.seed === seed ? { ...p, status } : p));
}

function reducer(state: ExtendedState, action: Action): ExtendedState {
  switch (action.type) {
    case "JOB_START":
      return {
        ...state,
        jobId:     action.jobId,
        target:    action.target,
        mode:      action.mode,
        status:    "running",
        runStatus: "running",
      };

    case "STAGE_START":
      return {
        ...state,
        currentStage: action.stage,
        stages: updateStage(state.stages, action.stage, {
          status: "running",
          depth: action.depth,
          startedAt: Date.now(),
        }),
      };

    case "STAGE_DONE":
      return {
        ...state,
        stages: updateStage(state.stages, action.stage, {
          status: "done",
          finishedAt: Date.now(),
        }),
      };

    case "STAGE_ERROR":
      return {
        ...state,
        stages: updateStage(state.stages, action.stage, {
          status: "error",
          errorMessage: action.error,
          finishedAt: Date.now(),
        }),
      };

    case "FINDING":
      return { ...state, findings: [action.finding, ...state.findings] };

    case "LOG":
      return { ...state, logs: [...state.logs, action.line].slice(-500) };

    case "PIVOT_ADD": {
      const exists = state.pivots.some(p => p.seed === action.seed);
      if (exists) return state;
      const info: PivotInfo = {
        seed:     action.seed,
        seedType: action.seedType as "email" | "username",
        depth:    action.depth,
        status:   action.status,
      };
      return {
        ...state,
        pivots:     [...state.pivots, info],
        pivotDepth: Math.max(state.pivotDepth, action.depth),
      };
    }

    case "PIVOT_UPDATE":
      return { ...state, pivots: updatePivot(state.pivots, action.seed, action.status) };

    case "PIVOT_CONFIRM_REQUEST":
      return { ...state, pivotConfirmPending: action.payload };

    case "PIVOT_CONFIRM_RESOLVED":
      return { ...state, pivotConfirmPending: null };

    case "STOPPING":
      return {
        ...state,
        runStatus: "stopping",
        logs: [...state.logs, "[stop] stop signal sent — waiting for worker to exit…"].slice(-500),
      };

    case "STOP_FAILED":
      return {
        ...state,
        runStatus: "running",
        logs: [...state.logs, "[stop] server could not honour stop request"].slice(-500),
      };

    case "STREAM_END":
      return {
        ...state,
        runStatus: action.status,
        reportUrl: action.reportUrl ?? state.reportUrl,
      };

    case "SSE_INTERRUPTED":
      return {
        ...state,
        logs: [...state.logs, "[sse] connection interrupted"].slice(-500),
      };

    case "SSE_RECONNECTED":
      return {
        ...state,
        logs: [...state.logs, "[sse] reconnected"].slice(-500),
      };

    case "SSE_GIVE_UP":
      return {
        ...state,
        runStatus: "error",
        logs: [...state.logs, "[sse] connection permanently lost"].slice(-500),
      };

    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function InvestigationLive() {
  const location  = useLocation();
  const navigate  = useNavigate();
  const nav_state = location.state as
    | { params?: RunParams; mode?: string; target?: string }
    | null;

  const [state, dispatch]       = useReducer(reducer, INITIAL);
  const [showLogs, setShowLogs] = useState(false);
  const [curMsg, setCurMsg]     = useState("");
  const [stopBusy, setStopBusy] = useState(false);
  const logsEndRef              = useRef<HTMLDivElement>(null);
  const abortRef                = useRef<AbortController | null>(null);

  // Live mirror of currentStage so the finding handler doesn't read a
  // stale closure value.
  const currentStageRef = useRef<string | null>(null);
  currentStageRef.current = state.currentStage;

  const params = nav_state?.params ?? null;

  const handleEvent = useCallback((event: SSEEvent) => {
    const p = event.payload as Record<string, unknown>;

    switch (event.type) {
      case "job_start":
        dispatch({
          type: "JOB_START",
          jobId:  String(p.job_id ?? ""),
          target: String(p.target ?? nav_state?.target ?? ""),
          mode:   String(p.mode || nav_state?.mode || "") as InvestigationState["mode"],
        });
        break;

      case "stage_start":
        dispatch({ type: "STAGE_START", stage: String(p.stage ?? ""), depth: Number(p.depth ?? 0) });
        setCurMsg("");
        break;

      case "stage_done":
        dispatch({ type: "STAGE_DONE", stage: String(p.stage ?? ""), depth: Number(p.depth ?? 0) });
        break;

      case "stage_error":
        dispatch({ type: "STAGE_ERROR", stage: String(p.stage ?? ""), error: String(p.error ?? "") });
        break;

      case "progress":
        setCurMsg(String(p.message ?? ""));
        break;

      case "finding": {
        const ftype = String(p.type ?? "");
        dispatch({
          type: "FINDING",
          finding: {
            id:        nextId(),
            stage:     String(currentStageRef.current ?? ""),
            type:      ftype,
            category:  categorise(ftype),
            label:     ftype,
            timestamp: Date.now(),
            payload:   p as FindingPayload,
          },
        });
        break;
      }

      case "log":
        dispatch({ type: "LOG", line: String(p.line ?? "") });
        requestAnimationFrame(() =>
          logsEndRef.current?.scrollIntoView({ behavior: "smooth" }),
        );
        break;

      case "pivot_start":
        dispatch({
          type: "PIVOT_ADD",
          seed:     String(p.seed ?? ""),
          seedType: String(p.seed_type ?? "username"),
          depth:    Number(p.depth ?? 1),
          status:   "running",
        });
        break;

      case "pivot_done":
        dispatch({ type: "PIVOT_UPDATE", seed: String(p.seed ?? ""), status: "done" });
        break;

      case "pivot_error":
        dispatch({ type: "PIVOT_UPDATE", seed: String(p.seed ?? ""), status: "error" });
        break;

      case "pivot_skipped":
        dispatch({ type: "PIVOT_UPDATE", seed: String(p.seed ?? ""), status: "skipped" });
        break;

      case "pivot_confirm_request": {
        const seeds = (p.seeds as Array<{ value: string; type: string }>) ?? [];
        for (const s of seeds) {
          dispatch({
            type: "PIVOT_ADD",
            seed:     s.value,
            seedType: s.type as "email" | "username",
            depth:    Number(p.depth ?? 1),
            status:   "pending_confirm",
          });
        }
        dispatch({
          type: "PIVOT_CONFIRM_REQUEST",
          payload: p as unknown as PivotConfirmRequestPayload,
        });
        break;
      }

      case "pivot_confirm_timeout":
        dispatch({ type: "PIVOT_CONFIRM_RESOLVED" });
        dispatch({
          type: "LOG",
          line: `[pivot] confirmation window elapsed at depth ${p.depth ?? "?"} — skipping seeds`,
        });
        break;

      case "abort":
        dispatch({
          type: "LOG",
          line: `[abort] ${String(p.reason ?? "aborted")} at stage ${String(p.stage ?? "?")}`,
        });
        break;

      case "stream_end": {
        const raw = String(p.status ?? "done");
        const terminal: "done" | "cancelled" | "error" =
          raw === "cancelled" ? "cancelled" :
          raw === "error"     ? "error"     :
          "done";
        dispatch({
          type: "STREAM_END",
          reportUrl: p.report_url ? String(p.report_url) : null,
          status: terminal,
        });
        break;
      }
    }
  }, [nav_state]);

  // ------------------------------------------------------------------ //
  // Stream lifecycle
  // ------------------------------------------------------------------ //
  useEffect(() => {
    if (!params) return;

    const controller = new AbortController();
    abortRef.current = controller;

    (async () => {
      try {
        const res = await apiFetch(runUrl(), {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify(params),
          signal:  controller.signal,
        });

        if (!res.ok) {
          const text = await res.text().catch(() => "");
          dispatch({ type: "LOG", line: `[error] /run returned HTTP ${res.status}: ${text.slice(0, 200)}` });
          dispatch({ type: "STREAM_END", reportUrl: null, status: "error" });
          return;
        }

        if (!res.body) {
          dispatch({ type: "LOG", line: "[error] /run returned no response body" });
          dispatch({ type: "STREAM_END", reportUrl: null, status: "error" });
          return;
        }

        const reader  = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer    = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const raw = line.slice(6).trim();
            if (!raw) continue;

            let parsed: SSEEvent;
            try {
              parsed = JSON.parse(raw) as SSEEvent;
            } catch {
              dispatch({ type: "LOG", line: raw });
              continue;
            }

            handleEvent(parsed);

            if (parsed.type === "stream_end" || parsed.type === "error") {
              return;
            }
          }
        }

        // Stream ended without a stream_end event. Settle to error so
        // the UI doesn't stay on "running".
        dispatch({ type: "STREAM_END", reportUrl: null, status: "error" });
      } catch (err) {
        if ((err as Error)?.name === "AbortError") {
          return;
        }
        dispatch({ type: "LOG", line: `[sse] error: ${err}` });
        dispatch({ type: "STREAM_END", reportUrl: null, status: "error" });
      } finally {
        if (abortRef.current === controller) {
          abortRef.current = null;
        }
      }
    })();

    return () => {
      controller.abort();
    };
  }, [params, handleEvent]);

  if (!params) {
    return (
      <div className="p-8">
        <p className="text-zinc-400 text-sm mb-4">No investigation in progress.</p>
        <button onClick={() => navigate("/dashboard")} className="btn btn-primary">
          <Icon name="arrowLeft" size={12} /> Back to Dashboard
        </button>
      </div>
    );
  }

  // ------------------------------------------------------------------ //
  // Stop button handler
  // ------------------------------------------------------------------ //
  const handleStop = useCallback(async () => {
    if (stopBusy) return;
    setStopBusy(true);
    dispatch({ type: "STOPPING" });

    const result = await stopInvestigation(state.jobId ?? undefined);
    if (!result.success) {
      dispatch({
        type: "LOG",
        line: `[stop] server refused: ${result.error ?? "unknown"}`,
      });
      if (result.error && !result.error.includes("not running")) {
        dispatch({ type: "STOP_FAILED" });
      }
    }

    // Safety: if the stream never delivers stream_end, give up after
    // 20s and force the local UI to settle.
    setTimeout(() => {
      setStopBusy(false);
      if (state.runStatus === "stopping") {
        abortRef.current?.abort();
        abortRef.current = null;
        dispatch({
          type: "LOG",
          line: "[stop] worker did not confirm exit within 20s — closing local stream",
        });
        dispatch({
          type: "STREAM_END",
          reportUrl: null,
          status: "cancelled",
        });
      }
    }, 20_000);
  }, [stopBusy, state.jobId, state.runStatus]);

  const intelFinding    = state.findings.find(f => f.type === "intelligence_report");
  const regularFindings = state.findings.filter(f => f.type !== "intelligence_report");
  const isDone          = state.runStatus === "done";
  const isCancelled     = state.runStatus === "cancelled";
  const isRunning       = state.runStatus === "running";
  const isStopping      = state.runStatus === "stopping";

  const statusLabel =
    isRunning  ? "Running"     :
    isStopping ? "Stopping…"   :
    isDone     ? "Complete"    :
    isCancelled? "Cancelled"   :
    state.runStatus === "error" ? "Error" : "";

  return (
    <div className="p-6 max-w-5xl mx-auto">

      {state.pivotConfirmPending && (
        <PivotConfirmModal
          payload={state.pivotConfirmPending}
          onClose={() => dispatch({ type: "PIVOT_CONFIRM_RESOLVED" })}
        />
      )}

      <div className="flex items-center gap-4 mb-6">
        <button
          onClick={() => navigate("/dashboard")}
          className="btn btn-ghost !p-2"
          aria-label="Back"
        >
          <Icon name="arrowLeft" size={14} />
        </button>
        <div className="flex-1 min-w-0">
          <h1 className="text-lg font-bold text-white truncate">
            Investigation{state.target ? `: ${state.target}` : ""}
          </h1>
          {state.jobId && (
            <p className="text-[11px] text-zinc-600 font-mono">
              job: {state.jobId.slice(0, 8)}…  ·  {statusLabel}
            </p>
          )}
        </div>

        {(isRunning || isStopping) && (
          <button
            onClick={handleStop}
            disabled={isStopping || stopBusy}
            className="btn btn-danger"
          >
            <Icon name="stop" size={12} />
            {isStopping ? "Stopping…" : "Stop"}
          </button>
        )}

        {(isDone || isCancelled) && state.reportUrl && (
          <a
            href={state.reportUrl}
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary"
          >
            <Icon name="external" size={12} /> View report
          </a>
        )}
      </div>

      {isCancelled && (
        <div className="mb-4 rounded-xl border border-amber-500/30 bg-amber-500/10
                        px-4 py-3 text-amber-200 text-sm flex items-center gap-2">
          <Icon name="alert" size={14} />
          Investigation was cancelled. Partial results below.
        </div>
      )}

      <LiveProgress
        currentStage={state.currentStage}
        currentMessage={curMsg}
        status={
          state.runStatus === "idle" ? "idle" :
          state.runStatus === "error" ? "error" :
          state.runStatus === "done" || state.runStatus === "cancelled" ? "done" :
          "running"
        }
        findingCount={state.findings.length}
        pivotDepth={state.pivotDepth}
      />

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-6 items-start">

        <div className="space-y-3">
          {intelFinding && <IntelCard payload={intelFinding.payload} />}
          {regularFindings.length === 0 && !intelFinding && (
            <div className="text-center py-12 text-zinc-600 text-sm">
              {isRunning || isStopping ? "Waiting for findings…" : "No findings."}
            </div>
          )}
          {regularFindings.map(f => <ResultCard key={f.id} finding={f} />)}
        </div>

        <div className="space-y-4">
          <StageList stages={state.stages} pivots={state.pivots} />

          <div className="surface overflow-hidden">
            <button
              onClick={() => setShowLogs(v => !v)}
              className="w-full px-3 py-2 text-[11px] text-zinc-500 hover:text-zinc-300
                         flex items-center justify-between transition-colors"
            >
              <span className="flex items-center gap-2">
                <Icon name="terminal" size={11} />
                Console ({state.logs.length})
              </span>
              <Icon name={showLogs ? "chevronUp" : "chevronDown"} size={11} />
            </button>
            {showLogs && (
              <div className="max-h-64 overflow-y-auto px-3 pb-3 font-mono text-[10px]
                              text-zinc-500 leading-relaxed space-y-px bg-ink-950/60">
                {state.logs.map((line, i) => <div key={i}>{line}</div>)}
                <div ref={logsEndRef} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}