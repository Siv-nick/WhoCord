// src/components/ChatPanel.tsx
import React, { useEffect, useRef, useState } from "react";
import type { ChatMessage, GraphEdge, GraphNode } from "../types/graph";
import type {
  Finding,
  InvestigationStatus,
  PivotInfo,
} from "../types/investigation";
import { useChat } from "../hooks/useChat";
import { Icon } from "./Icons";

interface Props {
  isOpen:  boolean;
  onClose: () => void;
  nodes:   GraphNode[];
  edges:   GraphEdge[];
  invStatus?:     InvestigationStatus;
  invStage?:      string | null;
  invJobId?:      string | null;
  invTarget?:     string;
  invMode?:       string;
  invPivotDepth?: number;
  invPivots?:     PivotInfo[];
  invLogs?:       string[];
  invFindings?:   Finding[];
}

function Bubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"} mb-3 anim-rise`}>
      <div
        className={[
          "max-w-[85%] rounded-2xl px-3.5 py-2.5 text-[13px] leading-relaxed",
          isUser
            ? "bg-gradient-to-br from-violet-500 to-violet-700 text-white rounded-br-md shadow-[0_8px_24px_-12px_rgba(139,92,246,.9)]"
            : "bg-ink-800 border border-edge-1 text-zinc-200 rounded-bl-md",
        ].join(" ")}
        style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}
      >
        {msg.content || (
          <span className="flex gap-1 items-center text-zinc-500 text-xs py-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-bounce"
                  style={{ animationDelay: "0ms" }} />
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-bounce"
                  style={{ animationDelay: "150ms" }} />
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-bounce"
                  style={{ animationDelay: "300ms" }} />
          </span>
        )}
      </div>
    </div>
  );
}

export default function ChatPanel({
  isOpen, onClose, nodes, edges,
  invStatus, invStage, invJobId, invTarget, invMode,
  invPivotDepth, invPivots, invLogs, invFindings,
}: Props) {
  const { messages, streaming, sendMessage, clearChat } = useChat();
  const [input, setInput] = useState("");
  const endRef   = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (isOpen) setTimeout(() => inputRef.current?.focus(), 320);
  }, [isOpen]);

  const send = async () => {
    const t = input.trim();
    if (!t || streaming) return;
    setInput("");
    await sendMessage(t, nodes, edges, {
      status:       invStatus,
      currentStage: invStage,
      jobId:        invJobId,
      target:       invTarget,
      mode:         invMode,
      pivotDepth:   invPivotDepth,
      pivots:       invPivots,
      logs:         invLogs,
      findings:     invFindings,
    });
  };

  const SUGGESTIONS = [
    "Summarise the map",
    "What's the strongest link?",
    "Suggest next investigation steps",
  ];

  return (
    <div
      className="fixed right-0 top-0 h-full z-30 flex flex-col
                 bg-ink-900/95 backdrop-blur-xl border-l border-edge-0
                 transition-[width,opacity] duration-300 overflow-hidden"
      style={{
        width: isOpen ? 380 : 0,
        opacity: isOpen ? 1 : 0,
        pointerEvents: isOpen ? "auto" : "none",
      }}
    >
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3.5 border-b border-edge-0 shrink-0">
        <div className="relative">
          <div className="h-8 w-8 rounded-lg flex items-center justify-center
                          bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white">
            <Icon name="sparkle" size={16} />
          </div>
          {streaming && (
            <span className="absolute -inset-0.5 rounded-lg border-2 border-violet-400/60 animate-ping" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[13px] font-bold text-white">AI Analyst</p>
          <p className="text-[10px] text-zinc-500">Full intel + canvas context</p>
        </div>
        {messages.length > 0 && (
          <button
            onClick={clearChat}
            className="btn btn-ghost !text-[11px] !px-2 !py-1"
          >
            Clear
          </button>
        )}
        <button onClick={onClose} className="btn btn-ghost !p-1.5">
          <Icon name="close" size={14} />
        </button>
      </div>

      {/* Context pill */}
      <div className="px-4 pt-3 pb-1 shrink-0">
        <div className="flex items-center gap-2 rounded-lg border border-violet-500/20
                        bg-violet-500/[.06] px-3 py-1.5">
          <span className="text-violet-300">
            <Icon name="layout" size={11} />
          </span>
          <span className="text-[11px] text-violet-200 font-medium">
            {nodes.length} nodes · {edges.length} edges
            {invJobId ? " · intel dump loaded" : ""}
          </span>
          <span className="ml-auto text-[10px] text-violet-400/70">in context</span>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 text-center anim-in">
            <div className="text-violet-300 opacity-70">
              <Icon name="sparkle" size={44} />
            </div>
            <div>
              <p className="text-sm font-semibold text-zinc-200">
                Ask about your investigation
              </p>
              <p className="text-[11px] text-zinc-500 mt-1 max-w-[220px]
                            leading-relaxed mx-auto">
                The model sees your canvas, live logs, findings, pivots,
                and the full persisted intel dump.
              </p>
            </div>
            <div className="w-full space-y-1.5 mt-1">
              {SUGGESTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => { setInput(s); inputRef.current?.focus(); }}
                  className="w-full text-left text-[11.5px] rounded-lg border border-edge-1
                             bg-ink-800/60 px-3 py-2 text-zinc-400
                             hover:text-zinc-100 hover:border-violet-500/40
                             hover:bg-violet-500/[.06] transition-all"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {messages.map(m => <Bubble key={m.id} msg={m} />)}
            <div ref={endRef} />
          </>
        )}
      </div>

      {/* Composer */}
      <div className="px-3 pb-4 pt-2 border-t border-edge-0 shrink-0">
        <div className="flex items-end gap-2 rounded-xl border border-edge-1
                        bg-ink-850 px-3 py-2 transition-all
                        focus-within:border-violet-500/50 focus-within:ring-4
                        focus-within:ring-violet-500/10">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
            placeholder="Ask anything…"
            rows={1}
            disabled={streaming}
            className="flex-1 resize-none bg-transparent text-[13px] text-zinc-100
                       placeholder-zinc-500 outline-none border-0
                       max-h-32 overflow-y-auto leading-relaxed disabled:opacity-50"
            style={{ minHeight: 22 }}
          />
          <button
            onClick={send}
            disabled={!input.trim() || streaming}
            className="btn btn-primary !px-3 !py-1.5 !text-[11px]
                       disabled:!opacity-30 shrink-0"
          >
            {streaming ? "…" : "Send"}
          </button>
        </div>
        <p className="mt-1.5 text-[10px] text-zinc-600 text-center">
          Shift+Enter for newline
        </p>
      </div>
    </div>
  );
}