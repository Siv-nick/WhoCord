// src/components/CardListPanel.tsx
import React, { useState } from "react";
import type { GraphNode } from "../types/graph";
import { entityIconName, MODULE_LABELS } from "../utils/classify";
import { Icon } from "./Icons";

interface Props {
  nodes: GraphNode[];
  onSelectNode: (id: string) => void;
  onClose: () => void;
  isOpen: boolean;
}

type Layout = "list" | "grid";

export default function CardListPanel({ nodes, onSelectNode, onClose, isOpen }: Props) {
  const [layout, setLayout]   = useState<Layout>("list");
  const [details, setDetails] = useState(false);
  const [q, setQ]             = useState("");

  const filtered = q.trim()
    ? nodes.filter(n => {
        const k = q.toLowerCase();
        return (
          n.label.toLowerCase().includes(k) ||
          n.entityType.toLowerCase().includes(k) ||
          n.infoFields.some(f => f.value.toLowerCase().includes(k))
        );
      })
    : nodes;

  return (
    <div
      className="fixed right-0 top-0 h-full z-30 flex flex-col
                 bg-ink-900/95 backdrop-blur-xl border-l border-edge-0
                 transition-[width,opacity] duration-300 overflow-hidden"
      style={{
        width: isOpen ? 400 : 0,
        opacity: isOpen ? 1 : 0,
        pointerEvents: isOpen ? "auto" : "none",
      }}
    >
      {/* Header */}
      <div className="px-4 py-3.5 border-b border-edge-0 shrink-0">
        <div className="flex items-center gap-2">
          <p className="text-[13px] font-bold text-white">Cards</p>
          <span className="chip !py-0.5 !text-[9px]">
            {filtered.length} / {nodes.length}
          </span>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              onClick={() => setDetails(v => !v)}
              className={`btn !text-[10px] !px-2 !py-1 ${
                details ? "!border-violet-500/40 !text-violet-200 !bg-violet-500/10" : ""
              }`}
            >
              {details ? "Collapse" : "Expand"}
            </button>
            <button
              onClick={() => setLayout(l => l === "list" ? "grid" : "list")}
              className="btn !px-2 !py-1"
              aria-label="Toggle layout"
            >
              <Icon name={layout === "list" ? "layout" : "list"} size={12} />
            </button>
            <button onClick={onClose} className="btn btn-ghost !p-1.5">
              <Icon name="close" size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="px-4 py-2.5 border-b border-edge-0 shrink-0">
        <div className="relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500">
            <Icon name="search" size={13} />
          </span>
          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Search…"
            className="field !pl-8 !py-1.5 !text-xs"
          />
        </div>
      </div>

      {/* Content */}
      <div
        className="flex-1 overflow-y-auto bg-ink-950/50 p-3"
        style={{
          display: layout === "grid" ? "grid" : "flex",
          gridTemplateColumns: layout === "grid" ? "1fr 1fr" : undefined,
          flexDirection: layout === "list" ? "column" : undefined,
          gap: 8,
          alignContent: "start",
        }}
      >
        {filtered.length === 0 && (
          <p className="text-zinc-500 text-xs text-center py-10"
             style={{ gridColumn: "1 / -1" }}>
            {q ? "No matches." : "No nodes yet."}
          </p>
        )}

        {filtered.map(node => (
          <Card
            key={node.id}
            node={node}
            expanded={details}
            onSelect={() => onSelectNode(node.id)}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Card ────────────────────────────────────────────────────────────
function Card({
  node, expanded, onSelect,
}: {
  node: GraphNode;
  expanded: boolean;
  onSelect: () => void;
}) {
  const preview = node.infoFields.find(
    f => f.value && f.key !== "type" && f.key !== "source" && !f.isImage,
  );

  const ring: Record<string, string> = {
    email:    "border-sky-500/30",
    username: "border-violet-500/30",
    breach:   "border-rose-500/30",
    domain:   "border-amber-500/30",
    ip:       "border-emerald-500/30",
    phone:    "border-rose-500/30",
  };
  const accent = ring[node.entityType] ?? "border-edge-1";

  return (
    <div
      className={`group bg-ink-850 border ${accent} rounded-xl overflow-hidden
                  hover:border-violet-500/40
                  hover:shadow-[0_8px_28px_-14px_rgba(139,92,246,.5)]
                  transition-all cursor-pointer`}
      style={{ minWidth: 0, flexShrink: 0 }}
      onClick={onSelect}
    >
      <div className="p-3">
        <div className="flex items-start gap-2.5">
          <span className="shrink-0 mt-0.5 text-violet-300">
            <Icon name={entityIconName(node.entityType)} size={16} />
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-semibold text-white leading-tight break-words">
              {node.label.length > 30 ? node.label.slice(0, 28) + "…" : node.label}
            </p>
            <div className="mt-1.5 flex items-center gap-1.5 flex-wrap">
              <span className="chip !text-[9px] !py-0.5">
                {MODULE_LABELS[node.module]}
              </span>
              <span className="text-[9px] text-zinc-600 font-mono truncate">
                {node.entityType}
              </span>
            </div>
            {!expanded && preview && (
              <p className="mt-2 text-[11px] text-zinc-500 leading-snug break-words">
                <span className="text-zinc-600">{preview.label}:</span>{" "}
                {preview.value.length > 56
                  ? preview.value.slice(0, 54) + "…"
                  : preview.value}
              </p>
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-edge-0 px-3 py-2.5 space-y-2">
          {node.infoFields.length === 0 ? (
            <p className="italic text-[11px] text-zinc-600">No details.</p>
          ) : (
            node.infoFields.slice(0, 8).map(f => (
              <div key={f.key}>
                <div className="eyebrow !text-[9px]">{f.label}</div>
                {f.isImage ? (
                  <img
                    src={f.value}
                    alt=""
                    className="mt-1 rounded border border-edge-1 max-h-20"
                    onError={e => (e.currentTarget.style.display = "none")}
                  />
                ) : (
                  <div className="mt-0.5 text-[11px] text-zinc-300 break-words leading-snug">
                    {/^https?:\/\//.test(f.value) ? (
                      <a
                        href={f.value}
                        target="_blank"
                        rel="noreferrer"
                        className="text-violet-300 hover:underline break-all"
                      >
                        {f.value}
                      </a>
                    ) : (
                      f.value || "—"
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}