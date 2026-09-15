// src/components/InfoCard.tsx
import React, { useState } from "react";
import type { GraphNode, InfoField } from "../types/graph";
import { entityIconName, MODULE_LABELS } from "../utils/classify";
import { Icon } from "./Icons";

interface Props {
  node: GraphNode;
  initialPos: { x: number; y: number };
  onFieldChange: (nodeId: string, key: string, value: string) => void;
  onClose: () => void;
}

const CONFIDENCE_LABEL = (c: number): string => {
  if (c >= 0.8) return "high";
  if (c >= 0.6) return "medium";
  if (c >= 0.4) return "low";
  return "very low";
};

const CONFIDENCE_COLOR = (c: number): string => {
  if (c >= 0.8) return "text-emerald-300";
  if (c >= 0.6) return "text-lime-300";
  if (c >= 0.4) return "text-amber-300";
  return "text-rose-300";
};

function InfoCard({
  node, initialPos, onFieldChange, onClose,
}: Props) {
  const [pos, setPos]        = useState(initialPos);
  const [dragging, setDrag]  = useState(false);
  const [start, setStart]    = useState({ x: 0, y: 0 });
  const [editingKey, setEK]  = useState<string | null>(null);
  const [editVal, setEV]     = useState("");

  const onDown = (e: React.PointerEvent<HTMLDivElement>) => {
    setDrag(true);
    setStart({ x: e.clientX - pos.x, y: e.clientY - pos.y });
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };
  const onMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!dragging) return;
    setPos({ x: e.clientX - start.x, y: e.clientY - start.y });
  };
  const onUp = () => setDrag(false);

  const startEdit  = (f: InfoField) => { setEK(f.key); setEV(f.value); };
  const commitEdit = (key: string)  => { onFieldChange(node.id, key, editVal); setEK(null); };

  const avatarField = node.infoFields.find(f => f.isImage);
  const others      = node.infoFields.filter(f => !f.isImage);

  return (
    <div
      className="fixed z-50 surface anim-pop overflow-hidden flex flex-col"
      style={{
        left: pos.x,
        top: pos.y,
        width: 380,
        maxHeight: "80vh",
        userSelect: dragging ? "none" : "auto",
      }}
      onPointerMove={onMove}
      onPointerUp={onUp}
    >
      {/* Header */}
      <div
        className="flex items-center gap-3 px-3.5 py-3 cursor-move select-none
                   bg-gradient-to-b from-white/[.02] to-transparent
                   border-b border-edge-0 shrink-0"
        onPointerDown={onDown}
      >
        <div className="flex h-8 w-8 items-center justify-center rounded-lg
                        bg-violet-500/15 border border-violet-500/25 text-violet-200 shrink-0">
          <Icon name={entityIconName(node.entityType)} size={16} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold text-white truncate leading-tight">
            {node.label}
          </p>
          <p className="eyebrow mt-0.5">
            {MODULE_LABELS[node.module]} · {node.entityType}
          </p>
        </div>
        <button
          onClick={onClose}
          className="btn btn-ghost !p-1.5"
          aria-label="Close"
        >
          <Icon name="close" size={14} />
        </button>
      </div>

      {/* Confidence row — shown when we have a value for this node.
          Placed above the avatar so it reads as a headline attribute,
          not a per-field detail. */}
      {typeof node.confidence === "number" && (
        <div className="px-3.5 py-2.5 border-b border-edge-0 shrink-0">
          <div className="flex items-center justify-between mb-1.5">
            <span className="eyebrow">Confidence</span>
            <span className={`text-[11px] font-bold tabular-nums ${
              CONFIDENCE_COLOR(node.confidence)
            }`}>
              {Math.round(node.confidence * 100)}%
              <span className="ml-1.5 text-[10px] font-medium opacity-80">
                {CONFIDENCE_LABEL(node.confidence)}
              </span>
            </span>
          </div>
          <div className="h-1 rounded-full bg-ink-800 overflow-hidden">
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${Math.round(node.confidence * 100)}%`,
                background: node.confidence >= 0.8
                  ? "linear-gradient(90deg, #10b981, #22c55e)"
                  : node.confidence >= 0.6
                  ? "linear-gradient(90deg, #84cc16, #bef264)"
                  : node.confidence >= 0.4
                  ? "linear-gradient(90deg, #f59e0b, #fbbf24)"
                  : "linear-gradient(90deg, #f43f5e, #fb7185)",
              }}
            />
          </div>
        </div>
      )}

      {/* Avatar */}
      {avatarField && (
        <div className="px-3.5 pt-3.5 pb-3 shrink-0 border-b border-edge-0">
          <div className="relative rounded-lg overflow-hidden bg-ink-900 border border-edge-1">
            <img
              src={avatarField.value}
              alt="avatar"
              className="w-full max-h-48 object-cover"
              onError={e => (e.currentTarget.style.display = "none")}
            />
            <a
              href={avatarField.value}
              target="_blank"
              rel="noreferrer"
              className="absolute top-2 right-2 rounded-md bg-black/60 backdrop-blur
                         border border-white/10 px-2 py-1 text-[10px] text-zinc-200
                         hover:bg-black/80 transition-colors flex items-center gap-1"
            >
              Open <Icon name="external" size={10} />
            </a>
          </div>
        </div>
      )}

      {/* Fields */}
      <div className="flex-1 overflow-y-auto">
        {others.length === 0 && !avatarField && (
          <div className="px-4 py-10 text-center">
            <div className="text-zinc-700 mb-2 inline-flex">
              <Icon name="dot" size={20} />
            </div>
            <p className="text-xs text-zinc-500 italic">Awaiting data…</p>
          </div>
        )}
        {others.map((f, i) => (
          <FieldRow
            key={f.key}
            field={f}
            isLast={i === others.length - 1}
            isEditing={editingKey === f.key}
            editVal={editVal}
            onEdit={() => startEdit(f)}
            onChange={setEV}
            onCommit={() => commitEdit(f.key)}
            onCancel={() => setEK(null)}
          />
        ))}
      </div>

      {/* Footer */}
      <div className="px-3.5 py-2 border-t border-edge-0 flex items-center
                      justify-between shrink-0">
        <span className="text-[10px] text-zinc-600">
          {new Date(node.createdAt).toLocaleTimeString()}
        </span>
        <span className="text-[10px] text-zinc-600">
          {node.infoFields.length} field{node.infoFields.length !== 1 ? "s" : ""}
        </span>
      </div>
    </div>
  );
}

// ─── Field row ───────────────────────────────────────────────────────
function FieldRow({
  field, isLast, isEditing, editVal, onEdit, onChange, onCommit, onCancel,
}: {
  field: InfoField;
  isLast: boolean;
  isEditing: boolean;
  editVal: string;
  onEdit: () => void;
  onChange: (v: string) => void;
  onCommit: () => void;
  onCancel: () => void;
}) {
  const isUrl = /^https?:\/\//.test(field.value);

  return (
    <div className={[
      "group px-3.5 py-2.5 flex items-start gap-3",
      !isLast ? "border-b border-edge-0" : "",
      "hover:bg-white/[.02] transition-colors",
    ].join(" ")}>
      <span className="eyebrow shrink-0 pt-0.5 w-20 leading-snug">
        {field.label}
      </span>
      <div className="flex-1 min-w-0">
        {isEditing ? (
          <div className="flex gap-1.5 anim-pop">
            <input
              autoFocus
              value={editVal}
              onChange={e => onChange(e.target.value)}
              onKeyDown={e => {
                if (e.key === "Enter")  onCommit();
                if (e.key === "Escape") onCancel();
              }}
              className="field !py-1 !text-xs"
            />
            <button
              onClick={onCommit}
              className="btn btn-primary !px-2 !py-1 !text-[10px]"
            >
              <Icon name="check" size={10} />
            </button>
          </div>
        ) : isUrl ? (
          <div className="flex items-center gap-1.5">
            <a
              href={field.value}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-violet-300 hover:text-violet-200
                         hover:underline break-all leading-relaxed"
            >
              {field.value}
            </a>
            <CopyBtn value={field.value} />
          </div>
        ) : (
          <div className="flex items-start gap-1.5">
            <span className="text-[12.5px] text-zinc-200 break-words leading-relaxed flex-1">
              {field.value || <span className="text-zinc-600 italic">—</span>}
            </span>
            {field.value && <CopyBtn value={field.value} />}
            {field.editable && (
              <button
                onClick={onEdit}
                className="opacity-0 group-hover:opacity-100 transition-opacity
                           text-zinc-500 hover:text-violet-300 shrink-0"
                aria-label="Edit"
              >
                <Icon name="edit" size={11} />
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Copy button ─────────────────────────────────────────────────────
function CopyBtn({ value }: { value: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      onClick={e => {
        e.stopPropagation();
        navigator.clipboard.writeText(value).catch(() => {});
        setOk(true);
        setTimeout(() => setOk(false), 1200);
      }}
      className="opacity-0 group-hover:opacity-100 transition-opacity
                 text-zinc-500 hover:text-zinc-200 shrink-0"
      title="Copy"
    >
      <Icon name={ok ? "check" : "copy"} size={11} />
    </button>
  );
}

// Memoised: Re-rendered by unrelated canvas interactions.
export default React.memo(InfoCard);
