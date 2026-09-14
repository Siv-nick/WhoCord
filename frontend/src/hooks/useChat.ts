// src/hooks/useChat.ts
import { useCallback, useRef, useState } from "react";
import type { ChatMessage, GraphEdge, GraphNode } from "../types/graph";
import type {
  Finding,
  InvestigationStatus,
  PivotInfo,
} from "../types/investigation";

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

    try {
      const res = await fetch("/api/ai/chat", {
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
            if (chunk) {
              setMessages(prev =>
                prev.map(m =>
                  m.id === assistantId
                    ? { ...m, content: m.content + chunk }
                    : m,
                ),
              );
            }
          } catch {
            if (raw) {
              setMessages(prev =>
                prev.map(m =>
                  m.id === assistantId
                    ? { ...m, content: m.content + raw }
                    : m,
                ),
              );
            }
          }
        }
      }
    } catch (err: unknown) {
      if ((err as Error)?.name !== "AbortError") {
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId
              ? { ...m, content: "⚠️ Error: could not reach the AI endpoint." }
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