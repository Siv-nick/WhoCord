// src/hooks/useChat.ts
//
// Change log
// ----------
// - Stream errors are now classified. The LLM endpoint and the
//   pipeline emit bracketed markers ([LLM 500: …], [LLM 429: …],
//   [Stream error: …]) as ordinary token text. A non-technical user
//   seeing raw HTTP status codes has no idea what to do. Messages now
//   carry an errorKind and a friendly message; the raw detail is kept
//   in a separate field for developers.

import { useCallback, useRef, useState } from "react";
import type { ChatMessage, GraphEdge, GraphNode } from "../types/graph";
import type {
  Finding,
  InvestigationStatus,
  PivotInfo,
} from "../types/investigation";
import { apiFetch } from "../utils/api";

let _msgSeq = 0;
const newMsgId = () => `msg_${++_msgSeq}_${Date.now()}`;

const MAX_NODES     = 400;
const MAX_EDGES     = 800;
const MAX_LOGS      = 150;
const MAX_FINDINGS  = 60;

export interface ChatExtraContext {
  status?:       InvestigationStatus;
  currentStage?: string | null;
  target?:       string;
  mode?:         string;
  jobId?:        string | null;
  pivotDepth?:   number;
  pivots?:       PivotInfo[];
  logs?:         string[];
  findings?:     Finding[];
}

interface UseChatResult {
  messages:  ChatMessage[];
  streaming: boolean;
  sendMessage: (
    text:  string,
    nodes: GraphNode[],
    edges: GraphEdge[],
    ctx?:  ChatExtraContext,
  ) => Promise<void>;
  clearChat: () => void;
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

type ErrorKind = "not_configured" | "rate_limited" | "provider_error" | "network";

interface ClassifiedError {
  kind:     ErrorKind;
  friendly: string;
  detail:   string;
}

const _LLM_ERR_RE = /^\[LLM (\d{3}): ([\s\S]*)\]$/;
const _STREAM_ERR_RE = /^\[Stream error: ([\s\S]*)\]$/;

function classifyErrorMarker(raw: string): ClassifiedError | null {
  const llm = raw.match(_LLM_ERR_RE);
  if (llm) {
    const status = Number(llm[1]);
    const detail = llm[2].trim();
    if (status === 401 || status === 403) {
      return {
        kind: "not_configured",
        friendly:
          "The AI provider rejected the request. Check that the API key " +
          "stored in Configuration is still valid.",
        detail,
      };
    }
    if (status === 429) {
      return {
        kind: "rate_limited",
        friendly:
          "The AI provider is rate-limiting requests. Wait a moment and " +
          "try again — or switch to a smaller model in Configuration.",
        detail,
      };
    }
    if (status === 503) {
      return {
        kind: "not_configured",
        friendly:
          "No AI provider is configured. Add an API key in Configuration " +
          "to enable the chat.",
        detail,
      };
    }
    if (status >= 500) {
      return {
        kind: "provider_error",
        friendly:
          "The AI provider returned an error. This is usually transient — " +
          "try again in a few seconds.",
        detail,
      };
    }
    return {
      kind: "provider_error",
      friendly: `The AI provider returned HTTP ${status}.`,
      detail,
    };
  }

  const stream = raw.match(_STREAM_ERR_RE);
  if (stream) {
    return {
      kind: "network",
      friendly:
        "The connection to the AI provider was interrupted. Check your " +
        "network and try again.",
      detail: stream[1].trim(),
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Payload trimming
// ---------------------------------------------------------------------------

function trimRawData(raw: unknown, maxKeys = 12, maxChars = 120): Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, unknown> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (count >= maxKeys) break;
    if (v === null || v === undefined) continue;
    if (typeof v === "object") continue;
    out[k] = typeof v === "string" ? v.slice(0, maxChars) : v;
    count += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useChat(): UseChatResult {
  const [messages,  setMessages]  = useState<ChatMessage[]>([]);
  const [streaming, setStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const clearChat = useCallback(() => setMessages([]), []);

  const sendMessage = useCallback(async (
    text: string,
    nodes: GraphNode[],
    edges: GraphEdge[],
    ctx: ChatExtraContext = {},
  ) => {
    if (!text.trim() || streaming) return;

    const userMsg: ChatMessage = {
      id:      newMsgId(),
      role:    "user",
      content: text.trim(),
      ts:      Date.now(),
    };
    setMessages(prev => [...prev, userMsg]);
    setStreaming(true);

    const assistantId = newMsgId();
    const assistantMsg: ChatMessage = {
      id:      assistantId,
      role:    "assistant",
      content: "",
      ts:      Date.now(),
    };
    setMessages(prev => [...prev, assistantMsg]);

    abortRef.current = new AbortController();

    const trimmedNodes = nodes.slice(0, MAX_NODES).map(n => ({
      id:         n.id,
      label:      n.label,
      entityType: n.entityType,
      module:     n.module,
      infoFields: n.infoFields.map(f => ({
        label: f.label,
        value: f.value.slice(0, 500),
      })),
      rawData:    trimRawData(n.rawData),
    }));

    const trimmedEdges = edges.slice(0, MAX_EDGES).map(e => ({
      sourceId: e.sourceId,
      targetId: e.targetId,
    }));

    const trimmedLogs = (ctx.logs ?? []).slice(-MAX_LOGS);

    const trimmedFindings = (ctx.findings ?? []).slice(0, MAX_FINDINGS).map(f => {
      const p = f.payload as Record<string, unknown>;
      const summary = String(
        p.value ?? p.url ?? p.email ?? p.domain ?? f.label
      ).slice(0, 120);
      return { type: f.type, stage: f.stage, summary };
    });

    const body = {
      message: text.trim(),
      job_id:  ctx.jobId ?? undefined,
      map: {
        node_count:   nodes.length,
        edge_count:   edges.length,
        nodes:        trimmedNodes,
        edges:        trimmedEdges,
        status:       ctx.status      ?? "idle",
        currentStage: ctx.currentStage ?? null,
        target:       ctx.target      ?? "",
        mode:         ctx.mode        ?? "",
        jobId:        ctx.jobId       ?? null,
        pivotDepth:   ctx.pivotDepth  ?? 0,
        pivots:       ctx.pivots      ?? [],
        logs:         trimmedLogs,
        findings:     trimmedFindings,
      },
    };

    // Accumulate the raw stream separately from what we display, so we
    // can classify the first chunk if it turns out to be an error
    // marker rather than real content.
    let accumulated = "";
    let classified: ClassifiedError | null = null;

    // Tokens arrive one SSE line at a time. Committing each one to
    // state re-copied the whole messages array and re-rendered the
    // chat tree per token — several hundred renders for a normal
    // response, all while the canvas is mounted alongside. Coalesce
    // into one commit per animation frame instead; the text still
    // appears to stream, but at the display's refresh rate rather
    // than the model's token rate.
    let flushPending: number | null = null;

    const commit = () => {
      flushPending = null;
      setMessages(prev =>
        prev.map(m => {
          if (m.id !== assistantId) return m;
          if (classified) {
            return {
              ...m,
              content:   classified.friendly,
              errorKind: classified.kind,
              errorRaw:  classified.detail,
            };
          }
          return { ...m, content: accumulated };
        }),
      );
    };

    const flushAccumulated = () => {
      if (flushPending !== null) return;
      flushPending = requestAnimationFrame(commit);
    };

    /** Force an immediate commit and drop any queued frame. */
    const flushNow = () => {
      if (flushPending !== null) {
        cancelAnimationFrame(flushPending);
        flushPending = null;
      }
      commit();
    };

    try {
      const res = await apiFetch("/api/ai/chat", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
        signal:  abortRef.current.signal,
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      if (!res.body) throw new Error("No response body");

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   buffer  = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const raw = line.slice(6).trim();
          if (raw === "[DONE]") break;

          try {
            const token = JSON.parse(raw) as { token?: string; text?: string };
            const chunk = token.token ?? token.text ?? "";
            if (!chunk) continue;

            accumulated += chunk;

            // Classify as soon as we have a candidate marker.
            if (!classified) {
              const c = classifyErrorMarker(accumulated.trim());
              if (c) {
                classified = c;
              }
            }

            flushAccumulated();
          } catch {
            if (raw) {
              accumulated += raw;
              flushAccumulated();
            }
          }
        }
      }

      // Final pass — the accumulated string might have only become a
      // complete marker on the last chunk.
      if (!classified) {
        const c = classifyErrorMarker(accumulated.trim());
        if (c) {
          classified = c;
        }
      }
      // The stream is finished; commit synchronously so the last tokens
      // cannot be stranded in a frame that never runs (e.g. the tab is
      // backgrounded, where rAF is throttled or paused entirely).
      flushNow();
    } catch (err: unknown) {
      // Drop any queued frame first: it would otherwise land after the
      // error message below and overwrite it with partial content.
      if (flushPending !== null) {
        cancelAnimationFrame(flushPending);
        flushPending = null;
      }
      if ((err as Error)?.name === "AbortError") {
        // User cancelled — keep whatever had already streamed in.
        commit();
      } else {
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId
              ? {
                  ...m,
                  content:
                    "Could not reach the AI endpoint. The server may be " +
                    "unavailable — try again in a moment.",
                  errorKind: "network" as ErrorKind,
                  errorRaw:  String(err),
                }
              : m,
          ),
        );
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }, [streaming]);

  return { messages, streaming, sendMessage, clearChat };
}