// src/components/NodePopup.tsx
import React, { useEffect, useState } from "react";
import type { GraphNode } from "../types/graph";
import { entityIconName, MODULE_LABELS } from "../utils/classify";
import { Icon, type IconName } from "./Icons";

interface Props {
  node: GraphNode;
  hasChildren: boolean;
  screenPos: { x: number; y: number };
  onConnect: (id: string) => void;
  onViewDetails: (id: string) => void;
  onInvestigate: (id: string) => void;
  onColourChange: (id: string, colour: string) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}

const COLORS = [
  "#f4f4f5", "#0a0a0d", "#8b5cf6", "#38bdf8", "#10b981",
  "#f59e0b", "#f43f5e", "#f472b6", "#22d3ee", "#a3e635",
];

function NodePopup({
  node, hasChildren, screenPos,
  onConnect, onViewDetails, onInvestigate,
  onColourChange, onDelete, onClose,
}: Props) {
  const [confirm, setConfirm] = useState(false);
  const [colors,  setColors]  = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="fixed inset-0 z-30" onClick={onClose} />
      <div
        className="fixed z-40 surface anim-pop w-60 p-1"
        style={{
          left: Math.min(screenPos.x + 10, window.innerWidth  - 260),
          top:  Math.max(10, Math.min(screenPos.y - 40, window.innerHeight - 380)),
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-3 py-2.5 flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-md
                          bg-violet-500/15 border border-violet-500/25 text-violet-200 shrink-0">
            <Icon name={entityIconName(node.entityType)} size={14} />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[13px] font-bold text-white truncate leading-tight">
              {node.label}
            </p>
            <p className="eyebrow mt-0.5 truncate">
              {MODULE_LABELS[node.module]} · {node.entityType}
            </p>
          </div>
        </div>

        <div className="hairline mx-1" />

        {/* Actions */}
        <div className="p-1 space-y-0.5">
          <MenuBtn
            icon="link"
            label="Connect"
            hint="Investigate from here"
            primary
            onClick={() => { onConnect(node.id); onClose(); }}
          />
          <MenuBtn
            icon="eye"
            label="View details"
            hint="Open info card"
            onClick={() => { onViewDetails(node.id); onClose(); }}
          />
          <MenuBtn
            icon="search"
            label="Re-investigate"
            onClick={() => { onInvestigate(node.id); onClose(); }}
          />
        </div>

        <div className="hairline mx-1" />

        {/* Colour */}
        <div className="p-1">
          <MenuBtn
            icon="palette"
            label="Change colour"
            onClick={() => setColors(v => !v)}
          />
          {colors && (
            <div className="px-2 pt-1.5 pb-2 anim-pop">
              <div className="grid grid-cols-5 gap-1.5 mb-2">
                {COLORS.map(c => (
                  <button
                    key={c}
                    onClick={() => onColourChange(node.id, c)}
                    className="h-6 w-6 rounded-full border border-white/10
                               hover:scale-110 transition-transform"
                    style={{ background: c }}
                    aria-label={`Set colour ${c}`}
                  />
                ))}
              </div>
              <input
                type="color"
                value={node.colour}
                onChange={e => onColourChange(node.id, e.target.value)}
                className="w-full h-7 rounded cursor-pointer bg-transparent
                           border border-edge-1"
              />
            </div>
          )}
        </div>

        <div className="hairline mx-1" />

        {/* Delete */}
        <div className="p-1">
          {!confirm ? (
            <MenuBtn
              icon="trash"
              label="Delete node"
              danger
              onClick={() => hasChildren ? setConfirm(true) : (onDelete(node.id), onClose())}
            />
          ) : (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/25 anim-pop">
              <p className="text-[11px] text-rose-200 font-semibold mb-2.5 leading-snug">
                {hasChildren
                  ? "This node has children. Delete the whole branch?"
                  : "Delete this node?"}
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => { onDelete(node.id); onClose(); }}
                  className="flex-1 btn btn-danger justify-center"
                >
                  Delete
                </button>
                <button
                  onClick={() => setConfirm(false)}
                  className="flex-1 btn justify-center"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Menu row ────────────────────────────────────────────────────────
function MenuBtn({
  icon, label, hint, onClick, primary, danger,
}: {
  icon: IconName;
  label: string;
  hint?: string;
  onClick: () => void;
  primary?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={[
        "w-full text-left px-3 py-2 rounded-lg flex items-center gap-2.5",
        "transition-colors text-[13px]",
        danger
          ? "text-rose-400 hover:bg-rose-500/10"
          : primary
          ? "text-violet-200 hover:bg-violet-500/15"
          : "text-zinc-300 hover:bg-white/[.05]",
      ].join(" ")}
    >
      <span className="w-4 flex items-center justify-center opacity-90">
        <Icon name={icon} size={14} />
      </span>
      <span className="flex-1 min-w-0">
        <span className="block font-medium">{label}</span>
        {hint && <span className="block text-[10px] text-zinc-500 mt-0.5">{hint}</span>}
      </span>
    </button>
  );
}

// Memoised: Re-rendered by unrelated canvas interactions.
export default React.memo(NodePopup);
