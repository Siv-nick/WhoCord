// src/hooks/useChat.ts
// ─────────────────────────────────────────────────────────────────────────────
// Manages the AI Chat panel: sends map state + user question to
// POST /api/ai/chat and streams the Groq response back token by token.

import { useCallback, useRef, useState } from "react";
import type { ChatMessage } from "../types/graph";
import type { GraphEdge, GraphNode } from "../types/graph";

let _msgSeq = 0;
const newMsgId = () => `msg_${++_msgSeq}_${Date.now()}`;

interface UseChatResult {
  messages:  ChatMessage[];
  streaming: boolean;
  sendMessage: (
    text: string,
    nodes: GraphNode[],
    edges: GraphEdge[],
  ) => Promise<void>;
  clearChat: () => void;
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
  ) => {
    if (!text.trim() || streaming) return;

    // Append user message
    const userMsg: ChatMessage = {
      id:      newMsgId(),
      role:    "user",
      content: text.trim(),
      ts:      Date.now(),
    };
    setMessages(prev => [...prev, userMsg]);
    setStreaming(true);

    // Placeholder for the assistant reply (streamed in)
    const assistantId = newMsgId();
    const assistantMsg: ChatMessage = {
      id:      assistantId,
      role:    "assistant",
      content: "",
      ts:      Date.now(),
    };
    setMessages(prev => [...prev, assistantMsg]);

    abortRef.current = new AbortController();

    try {
      const res = await fetch("/api/ai/chat", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text.trim(),
          map: {
            node_count:  nodes.length,
            edge_count:  edges.length,
            nodes: nodes.map(n => ({
              label:      n.label,
              entityType: n.entityType,
              infoFields: n.infoFields.map(f => ({ label: f.label, value: f.value })),
            })),
          },
        }),
        signal: abortRef.current.signal,
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

        // Parse SSE lines
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
            // Raw text fallback
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
